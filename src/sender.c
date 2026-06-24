// RFC 8762 STAMP Sender実装
// 指定されたサーバーに対してSTAMPパケットを送信し、RTTを測定する

#include "stamp.h"
#include <math.h>
#ifdef _WIN32
#include <mswsock.h>
#endif

#define SERVER_IP	  "127.0.0.1" // デフォルトのサーバーIPアドレス（ローカルホスト）
#define SEND_INTERVAL_SEC 1	      // 送信間隔（秒）

// ソケットタイムアウト（stamp_protocol.h から移設、sender 専用の運用定数）
#define SOCKET_TIMEOUT_SEC  5
#define SOCKET_TIMEOUT_USEC 0

// 統計・表示用定数（stamp_protocol.h から移設、sender 専用の運用定数）
#define STAMP_STATS_INITIAL_MIN		  1e9
#define STAMP_ASYMMETRY_WARN_THRESHOLD_MS 10.0

#ifdef __linux__
#define SENDER_IFNAME(opts) ((opts).ifname)
#else
#define SENDER_IFNAME(opts) (NULL)
#endif

static bool g_negative_delay_seen = false;
static bool g_oneway_mode = false;
// タイムスタンプ形式フラグ（true: PTP/Z=1, false: NTP）。main() が CLI から設定
static bool g_ptp_mode = false;
static uint16_t
	g_error_estimate_nbo; // htons済み Error Estimate（main()で設定）

#ifdef __linux__
static bool g_tx_hw_timestamp_enabled = false;
static bool g_phc_enabled = false;
// PHC fd は main() の AUTO_CLOSE_FD ローカルで管理（プロセス終了時に自動 close）
static clockid_t g_phc_clockid = CLOCK_REALTIME;
#endif

// 統計情報構造体
struct sender_stats {
	uint32_t sent;
	uint32_t received;
	uint32_t timeouts;
	double min_rtt;
	double max_rtt;
	double sum_rtt;
	// One-way delay 統計
	double min_fwd, max_fwd, sum_fwd;
	double min_bwd, max_bwd, sum_bwd;
	double sum_fwd_sq, sum_bwd_sq; // jitter 計算用 (分散)
};

static struct sender_stats g_stats = {
	.sent = 0,
	.received = 0,
	.timeouts = 0,
	.min_rtt = STAMP_STATS_INITIAL_MIN,
	.max_rtt = 0,
	.sum_rtt = 0,
	.min_fwd = STAMP_STATS_INITIAL_MIN,
	.max_fwd = 0,
	.sum_fwd = 0,
	.min_bwd = STAMP_STATS_INITIAL_MIN,
	.max_bwd = 0,
	.sum_bwd = 0,
	.sum_fwd_sq = 0,
	.sum_bwd_sq = 0,
};

/**
 * 統計情報の表示
 */
__attribute__((cold)) static void print_statistics(void)
{
	printf("\n--- STAMP Statistics ---\n");
	printf("Packets sent: %u\n", g_stats.sent);
	printf("Packets received: %u\n", g_stats.received);
	printf("Packet loss: %.2f%%\n",
	       stamp_packet_loss(g_stats.sent, g_stats.received));
	printf("Timeouts: %u\n", g_stats.timeouts);
	if (g_stats.received > 0) {
		printf("RTT min/avg/max = %.3f/%.3f/%.3f ms\n",
		       g_stats.min_rtt,
		       g_stats.sum_rtt / g_stats.received,
		       g_stats.max_rtt);
		if (g_oneway_mode) {
			double avg_fwd = g_stats.sum_fwd / g_stats.received;
			double avg_bwd = g_stats.sum_bwd / g_stats.received;
			double jitter_fwd = stamp_jitter(g_stats.sum_fwd,
							 g_stats.sum_fwd_sq,
							 g_stats.received);
			double jitter_bwd = stamp_jitter(g_stats.sum_bwd,
							 g_stats.sum_bwd_sq,
							 g_stats.received);
			printf("Forward  min/avg/max/jitter = "
			       "%.3f/%.3f/%.3f/%.3f ms\n",
			       g_stats.min_fwd,
			       avg_fwd,
			       g_stats.max_fwd,
			       jitter_fwd);
			printf("Backward min/avg/max/jitter = "
			       "%.3f/%.3f/%.3f/%.3f ms\n",
			       g_stats.min_bwd,
			       avg_bwd,
			       g_stats.max_bwd,
			       jitter_bwd);
		}
	}
	if (g_negative_delay_seen) {
		fprintf(stderr, "\nWarning: A negative delay was detected.\n");
		fprintf(stderr,
			"This typically indicates system clock skew.\n");
		fprintf(stderr,
			"Please ensure time synchronization is active on your "
			"system.\n");
		fprintf(stderr,
			"Tools: Windows (w32tm), Linux (chronyc/timedatectl), "
			"macOS (sntp).\n");
	}
}

/**
 * 使用方法の表示
 * @param prog プログラム名
 */
__attribute__((cold)) static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-4|-6] [-P] [-c] [-O] [-i iface] "
		"[server_ip|hostname] [port]\n",
		prog ? prog : "sender");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -4    Force IPv4\n");
	fprintf(stderr, "  -6    Force IPv6\n");
	fprintf(stderr, "  -P    Use PTP timestamp format (Z=1)\n");
#ifdef __linux__
	fprintf(stderr,
		"  -i    Network interface for hardware timestamping (e.g., "
		"eth0)\n");
	fprintf(stderr,
		"  -c    Use PHC (PTP Hardware Clock) "
		"(requires -i)\n");
#endif
	fprintf(stderr, "  -O    One-way delay measurement mode\n");
	fprintf(stderr, "  (default: auto-detect from address format)\n");
}

/**
 * ソケットの初期化
 * @return ソケットディスクリプタ、エラー時INVALID_SOCKET
 */

#ifdef _WIN32
/**
 * Windows: sender ソケットのタイムアウト・カーネルTS設定
 * @return 成功時0、エラー時-1
 */
__attribute__((cold)) static int configure_sender_socket_windows(SOCKET sockfd)
{
	DWORD timeout_ms = (SOCKET_TIMEOUT_SEC * 1000) +
			   (SOCKET_TIMEOUT_USEC / 1000);
	if (setsockopt(sockfd,
		       SOL_SOCKET,
		       SO_RCVTIMEO,
		       (const char *)&timeout_ms,
		       sizeof(timeout_ms)) < 0) {
		PRINT_SOCKET_ERROR("setsockopt failed");
		return -1;
	}

	if (!stamp_init_wsa_recvmsg(sockfd, &g_wsa_recvmsg)) {
		fprintf(stderr,
			"Warning: WSARecvMsg not available; "
			"kernel timestamps disabled\n");
	}
	stamp_enable_kernel_timestamping_windows(sockfd);
	return 0;
}
#else
/**
 * Unix: sender ソケットのタイムアウト・タイムスタンプ・ビジーポーリング設定
 * @return 成功時0、エラー時-1
 */
__attribute__((cold)) static int configure_sender_socket_unix(
	SOCKET sockfd,
	__attribute__((unused)) const char *ifname)
{
	if (stamp_set_socket_timeouts(sockfd,
				      SOCKET_TIMEOUT_SEC,
				      SOCKET_TIMEOUT_USEC,
				      false) < 0) {
		PRINT_SOCKET_ERROR("setsockopt failed");
		return -1;
	}

	stamp_enable_so_timestamp(sockfd);

#ifdef __linux__
	// SO_BUSY_POLL: ビジーポーリングでレイテンシ削減（成否は無視）
	(void)stamp_enable_busy_poll(sockfd);

	// SO_TIMESTAMPING: カーネルレベルの送受信タイムスタンプ + HW 検出。
	// sender は TX HW (T1) も試行し、g_tx_hw_timestamp_enabled を更新する。
	struct stamp_so_timestamping_opts ts_opts = {
		.ifname = ifname,
		.want_tx_hw = true,
		.require_rx_hw = false,
		.hw_kind = "HW",
		.rx_label = "RX (T4)",
		.tx_label = "TX (T1)",
	};
	(void)stamp_setup_so_timestamping(sockfd,
					  &ts_opts,
					  &g_tx_hw_timestamp_enabled,
					  NULL);
#endif // __linux__

	return 0;
}
#endif

/**
 * 送信TTL/Hop Limitの設定 (RFC 4656 Section 4.1.2 SHOULD)
 */
__attribute__((cold)) static void setup_sender_ttl(SOCKET sockfd, int family)
{
	if (family == AF_INET) {
		int ttl = IP_TTL_MAX;
		if (setsockopt(sockfd,
			       IPPROTO_IP,
			       IP_TTL,
			       (const char *)&ttl,
			       sizeof(ttl)) < 0) {
			fprintf(stderr,
				"Warning: IP_TTL=255 failed (error "
				"%d); using OS default TTL\n",
				SOCKET_ERRNO);
		}
	} else {
		int hops = IP_TTL_MAX;
		if (setsockopt(sockfd,
			       IPPROTO_IPV6,
			       IPV6_UNICAST_HOPS,
			       (const char *)&hops,
			       sizeof(hops)) < 0) {
			fprintf(stderr,
				"Warning: IPV6_UNICAST_HOPS=255 failed "
				"(error %d); using OS default Hop Limit\n",
				SOCKET_ERRNO);
		}
	}
}

__attribute__((cold)) static SOCKET init_socket(
	const char *host,
	uint16_t port,
	struct sockaddr_storage *servaddr,
	socklen_t *servaddr_len,
	int af_hint,
	__attribute__((unused)) const char *ifname)
{
	SOCKET sockfd = INVALID_SOCKET;
	struct addrinfo *result = NULL;
	struct addrinfo *rp;
	int last_err = 0;
	struct sockaddr_storage last_addr;
	bool have_last_addr = false;

	if (stamp_resolve_address_list(host, port, af_hint, &result) != 0) {
		fprintf(stderr, "Failed to resolve address: %s\n", host);
		return INVALID_SOCKET;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family != AF_INET && rp->ai_family != AF_INET6) {
			continue;
		}

		sockfd = socket(rp->ai_family, SOCK_DGRAM, 0);
		if (SOCKET_ERROR_CHECK(sockfd)) {
			last_err = SOCKET_ERRNO;
			continue;
		}

#ifdef _WIN32
		if (configure_sender_socket_windows(sockfd) != 0) {
			CLOSE_SOCKET(sockfd);
			freeaddrinfo(result);
			return INVALID_SOCKET;
		}
#else
		if (configure_sender_socket_unix(sockfd, ifname) != 0) {
			CLOSE_SOCKET(sockfd);
			freeaddrinfo(result);
			return INVALID_SOCKET;
		}
#endif

		setup_sender_ttl(sockfd, rp->ai_family);

		if (connect(sockfd, rp->ai_addr, ADDRLEN_CAST(rp->ai_addrlen)) <
		    0) {
			last_err = SOCKET_ERRNO;
			if (rp->ai_addrlen <= sizeof(last_addr)) {
				memset(&last_addr, 0, sizeof(last_addr));
				memcpy(&last_addr, rp->ai_addr, rp->ai_addrlen);
				have_last_addr = true;
			}
			CLOSE_SOCKET(sockfd);
			// NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
			sockfd = INVALID_SOCKET;
			continue;
		}

		memset(servaddr, 0, sizeof(*servaddr));
		memcpy(servaddr, rp->ai_addr, rp->ai_addrlen);
		*servaddr_len = (socklen_t)rp->ai_addrlen;
		freeaddrinfo(result);
		return sockfd;
	}

	freeaddrinfo(result);

	fprintf(stderr,
		"Failed to connect to any resolved address for %s:%u\n",
		host,
		(unsigned int)port);
	if (last_err != 0) {
		fprintf(stderr,
			"connect to remote STAMP server failed: error %d\n",
			last_err);
	}

	if (have_last_addr) {
		char addrstr[INET6_ADDRSTRLEN] = {0};
		uint16_t port_tmp = stamp_sockaddr_get_port(&last_addr);
		if (stamp_sockaddr_to_string(&last_addr,
					     addrstr,
					     sizeof(addrstr)) != NULL) {
			fprintf(stderr,
				"Last attempted address: %s:%u (remote host or "
				"network may be unreachable).\n",
				addrstr,
				(unsigned int)port_tmp);
		}
	}

	return INVALID_SOCKET;
}

/**
 * STAMPパケットの送信 (RFC 8762 Section 4.2.1)
 * @param sockfd ソケットディスクリプタ
 * @param seq シーケンス番号
 * @param tx_packet 送信パケットのポインタ
 * @return 成功時0、エラー時-1
 */
static int send_stamp_packet(SOCKET sockfd,
			     uint32_t seq,
			     struct stamp_sender_packet *tx_packet,
			     uint32_t *real_t1_sec,
			     uint32_t *real_t1_frac)
{
	uint32_t t1_sec;
	uint32_t t1_frac;

	memset(tx_packet, 0, sizeof(*tx_packet));
	tx_packet->seq_num = htonl(seq);
	tx_packet->error_estimate = g_error_estimate_nbo;

	// T1: 送信時刻
#ifdef __linux__
	if (g_phc_enabled) {
		if (unlikely(stamp_get_phc_timestamp(g_phc_clockid,
						     &t1_sec,
						     &t1_frac,
						     g_ptp_mode) != 0)) {
			fprintf(stderr, "Failed to get PHC T1 timestamp\n");
			return -1;
		}
	} else
#endif
		if (unlikely(stamp_get_timestamp(&t1_sec,
						 &t1_frac,
						 g_ptp_mode) != 0)) {
		fprintf(stderr, "Failed to get T1 timestamp\n");
		return -1;
	}
	tx_packet->timestamp_sec = t1_sec;
	tx_packet->timestamp_frac = t1_frac;

	*real_t1_sec = t1_sec;
	*real_t1_frac = t1_frac;

	if (unlikely(send(sockfd,
			  (const char *)tx_packet,
			  (int)sizeof(*tx_packet),
			  0) < 0)) {
		PRINT_SOCKET_ERROR("send failed");
		return -1;
	}

#ifdef __linux__
	// TX HW タイムスタンプ: MSG_ERRQUEUE から取得
	if (g_tx_hw_timestamp_enabled) {
		uint32_t hw_sec;
		uint32_t hw_frac;
		if (stamp_retrieve_tx_hw_timestamp(sockfd,
						   &hw_sec,
						   &hw_frac,
						   g_ptp_mode)) {
			*real_t1_sec = hw_sec;
			*real_t1_frac = hw_frac;
		}
	}
#endif

	g_stats.sent++;
	return 0;
}

/**
 * RTT 統計の更新
 */
static inline void update_rtt_stats(double rtt)
{
	g_stats.received++;
	g_stats.sum_rtt += rtt;
	if (rtt < g_stats.min_rtt) {
		g_stats.min_rtt = rtt;
	}
	if (rtt > g_stats.max_rtt) {
		g_stats.max_rtt = rtt;
	}
}

/**
 * One-way delay 統計の更新と異常値警告
 */
static inline void update_oneway_stats(double forward_delay,
				       double backward_delay)
{
	g_stats.sum_fwd += forward_delay;
	g_stats.sum_bwd += backward_delay;
	g_stats.sum_fwd_sq += forward_delay * forward_delay;
	g_stats.sum_bwd_sq += backward_delay * backward_delay;
	if (forward_delay < g_stats.min_fwd) {
		g_stats.min_fwd = forward_delay;
	}
	if (forward_delay > g_stats.max_fwd) {
		g_stats.max_fwd = forward_delay;
	}
	if (backward_delay < g_stats.min_bwd) {
		g_stats.min_bwd = backward_delay;
	}
	if (backward_delay > g_stats.max_bwd) {
		g_stats.max_bwd = backward_delay;
	}

	if (forward_delay < 0 || backward_delay < 0) {
		fprintf(stderr,
			"Warning: Negative one-way delay detected. "
			"Clock synchronization may be required.\n");
	} else if (fabs(forward_delay - backward_delay) >
		   STAMP_ASYMMETRY_WARN_THRESHOLD_MS) {
		fprintf(stderr,
			"Warning: Forward/backward delay difference "
			"> 10ms (%.3f ms). Path asymmetry or clock "
			"skew suspected.\n",
			fabs(forward_delay - backward_delay));
	}
}

/**
 * 測定結果行の出力
 */
static inline void print_measurement_result(uint32_t seq_nbo,
					    double forward_delay,
					    double backward_delay,
					    double rtt,
					    double offset)
{
	if (g_oneway_mode) {
		printf("%" PRIu32 "\t%.3f\t\t%.3f\t\t%.3f\n",
		       (uint32_t)ntohl(seq_nbo),
		       forward_delay,
		       backward_delay,
		       offset);
	} else {
		printf("%" PRIu32 "\t%.3f\t\t%.3f\t\t%.3f\t%.3f\n",
		       (uint32_t)ntohl(seq_nbo),
		       forward_delay,
		       backward_delay,
		       rtt,
		       offset);
	}
}

/**
 * 受信パケットの遅延計算・統計更新・結果表示
 */
static void compute_and_report_delays(
	const struct stamp_reflector_packet *rx_packet,
	uint32_t real_t1_sec,
	uint32_t real_t1_frac,
	uint32_t t4_sec,
	uint32_t t4_frac)
{
	uint16_t sender_ee = ntohs(g_error_estimate_nbo);
	uint16_t reflector_ee = ntohs(rx_packet->error_estimate);

	if (unlikely((reflector_ee & ERROR_ESTIMATE_MULT_MASK) == 0)) {
		fprintf(stderr,
			"Warning: Reflector error_estimate has zero multiplier "
			"(0x%04x)\n",
			reflector_ee);
	}

	double t1 =
		stamp_timestamp_to_double(real_t1_sec, real_t1_frac, sender_ee);
	double t2 = stamp_timestamp_to_double(rx_packet->rx_sec,
					      rx_packet->rx_frac,
					      reflector_ee);
	double t3 = stamp_timestamp_to_double(rx_packet->timestamp_sec,
					      rx_packet->timestamp_frac,
					      reflector_ee);
	double t4 = stamp_timestamp_to_double(t4_sec, t4_frac, sender_ee);

	if (t1 > t4) {
		fprintf(stderr,
			"Warning: T1 > T4 detected. Severe clock skew or "
			"timestamp error.\n");
		fprintf(stderr,
			"  T1=%.9f, T2=%.9f, T3=%.9f, T4=%.9f\n",
			t1,
			t2,
			t3,
			t4);
		fprintf(stderr,
			"  Difference: %.6f ms\n",
			(t1 - t4) * MSEC_PER_SEC);
		g_negative_delay_seen = true;
	}

	double forward_delay = stamp_forward_delay(t1, t2);
	double backward_delay = stamp_backward_delay(t3, t4);
	double rtt = stamp_rtt(forward_delay, backward_delay);
	double offset = stamp_clock_offset(t1, t2, t3, t4);

	if (forward_delay < 0 || backward_delay < 0) {
		g_negative_delay_seen = true;
	}

	update_rtt_stats(rtt);
	if (g_oneway_mode) {
		update_oneway_stats(forward_delay, backward_delay);
	}

	print_measurement_result(rx_packet->sender_seq_num,
				 forward_delay,
				 backward_delay,
				 rtt,
				 offset);
}

/**
 * STAMPパケットの受信と処理
 * @return 成功時0、エラー時-1
 */
static int receive_and_process_packet(
	SOCKET sockfd,
	const struct stamp_sender_packet *tx_packet,
	uint32_t real_t1_sec,
	uint32_t real_t1_frac,
	uint8_t *buffer,
	size_t buffer_len)
{
	struct stamp_reflector_packet rx_packet;
	struct sockaddr_storage recvaddr;
	socklen_t len = sizeof(recvaddr);
	uint32_t t4_sec = 0;
	uint32_t t4_frac = 0;

	int n = stamp_recv_with_timestamp(sockfd,
					  buffer,
					  buffer_len,
					  &recvaddr,
					  &len,
					  NULL,
					  &t4_sec,
					  &t4_frac,
					  g_ptp_mode);
	if (unlikely(n < 0)) {
		if (stamp_recv_timed_out()) {
			fprintf(stderr, "Timeout waiting for response\n");
			g_stats.timeouts++;
		} else {
			PRINT_SOCKET_ERROR("recvfrom failed");
		}
		return -1;
	}

	if (unlikely(!stamp_validate_packet(buffer, n))) {
		fprintf(stderr, "Invalid packet received\n");
		return -1;
	}

	memcpy(&rx_packet, buffer, sizeof(rx_packet));

	if (unlikely(rx_packet.sender_seq_num != tx_packet->seq_num)) {
		fprintf(stderr,
			"Sequence number mismatch: expected %" PRIu32
			", got %" PRIu32 "\n",
			(uint32_t)ntohl(tx_packet->seq_num),
			(uint32_t)ntohl(rx_packet.sender_seq_num));
		return -1;
	}

	compute_and_report_delays(&rx_packet,
				  real_t1_sec,
				  real_t1_frac,
				  t4_sec,
				  t4_frac);
	return 0;
}

/**
 * sender のコマンドラインオプション
 */
struct sender_options {
	int af_hint;
	uint16_t port;
	const char *host;
	bool ptp_mode;
	bool oneway_mode;
#ifdef __linux__
	const char *ifname;
	bool phc_requested;
#endif
};

/**
 * コマンドラインオプションの解析
 * @return 成功時0、エラー時1
 */
__attribute__((cold)) static int
parse_sender_options(int argc, char *argv[], struct sender_options *opts)
{
	opts->af_hint = AF_UNSPEC;
	opts->port = STAMP_PORT;
	opts->host = SERVER_IP;
	opts->ptp_mode = false;
	opts->oneway_mode = false;
#ifdef __linux__
	opts->ifname = NULL;
	opts->phc_requested = false;
#endif

	int opt;
	while ((opt = getopt(argc, argv, "46i:PcO")) != -1) {
		switch (opt) {
		case '4':
			opts->af_hint = AF_INET;
			break;
		case '6':
			opts->af_hint = AF_INET6;
			break;
		case 'i':
#ifdef __linux__
			opts->ifname = optarg;
#else
			fprintf(stderr,
				"Warning: -i option is only supported on "
				"Linux\n");
#endif
			break;
		case 'P':
			opts->ptp_mode = true;
			break;
		case 'c':
#ifdef __linux__
			opts->phc_requested = true;
#else
			fprintf(stderr,
				"Warning: -c option is only supported on "
				"Linux\n");
#endif
			break;
		case 'O':
			opts->oneway_mode = true;
			break;
		default:
			print_usage(argc > 0 ? argv[0] : "sender");
			return 1;
		}
	}

	int remaining_args = argc - optind;
	if (remaining_args > 2) {
		print_usage(argc > 0 ? argv[0] : "sender");
		return 1;
	}

	if (remaining_args > 0) {
		opts->host = argv[optind];
	}
	if (remaining_args > 1 &&
	    stamp_parse_port(argv[optind + 1], &opts->port) != 0) {
		fprintf(stderr, "Invalid port: %s\n", argv[optind + 1]);
		print_usage(argc > 0 ? argv[0] : "sender");
		return 1;
	}

	return 0;
}

/**
 * 測定開始メッセージの表示
 */
__attribute__((cold)) static void print_sender_start_message(
	const struct sockaddr_storage *servaddr)
{
	char addr_port_str[STAMP_ADDR_PORT_BUFSIZE];
	const char *family_str = (servaddr->ss_family == AF_INET6) ? "IPv6"
								   : "IPv4";
	stamp_format_sockaddr_with_port(servaddr,
					addr_port_str,
					sizeof(addr_port_str));
	printf("STAMP Sender targeting %s (%s)", addr_port_str, family_str);
	if (g_ptp_mode) {
		printf(" [PTP]");
	}
#ifdef __linux__
	if (g_phc_enabled) {
		printf(" [PHC]");
	}
#endif
	if (g_oneway_mode) {
		printf(" [One-way]");
	}
	printf("\n");
	printf("Press Ctrl+C to stop and show statistics\n");
	if (g_oneway_mode) {
		printf("Seq\tFwd(ms)\t\tBwd(ms)\t\tOffset(ms)\n");
		printf("-------------------------------------------"
		       "--------\n");
	} else {
		printf("Seq\tFwd(ms)\t\tBwd(ms)\t\tRTT(ms)\tOffset(ms)\n");
		printf("-------------------------------------------"
		       "--------\n");
	}
}

/**
 * g_running チェック付きインターバルスリープ
 */
static inline void sleep_with_interrupt_check(void)
{
#ifdef _WIN32
	int total_ms = SEND_INTERVAL_SEC * 1000;
	int sleep_interval_ms = SLEEP_CHECK_INTERVAL_MS;
	for (int elapsed = 0; elapsed < total_ms &&
			      __atomic_load_n(&g_running, __ATOMIC_SEQ_CST);
	     elapsed += sleep_interval_ms) {
		int remaining = total_ms - elapsed;
		int sleep_time = remaining < sleep_interval_ms
					 ? remaining
					 : sleep_interval_ms;
		Sleep((DWORD)sleep_time);
	}
#else
	long total_ns = SEND_INTERVAL_SEC * (long)NSEC_PER_SEC;
	long interval_ns = SLEEP_CHECK_INTERVAL_MS * 1000000L;
	struct timespec req;
	for (long elapsed = 0; elapsed < total_ns &&
			       __atomic_load_n(&g_running, __ATOMIC_SEQ_CST);
	     elapsed += interval_ns) {
		long remaining = total_ns - elapsed;
		long sleep_ns = remaining < interval_ns ? remaining
							: interval_ns;
		req.tv_sec = sleep_ns / (long)NSEC_PER_SEC;
		req.tv_nsec = sleep_ns % (long)NSEC_PER_SEC;
		nanosleep(&req, NULL);
	}
#endif
}

/**
 * プラットフォーム初期化（WSAStartup / シグナルハンドラ）
 * @return 成功時0、エラー時-1
 */
__attribute__((cold)) static int platform_init_sender(void)
{
#ifdef _WIN32
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return -1;
	}
	SetConsoleCtrlHandler(stamp_signal_handler, TRUE);
#else
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stamp_signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) != 0) {
		fprintf(stderr,
			"Warning: sigaction(SIGINT) failed: %s\n",
			strerror(errno));
	}
	if (sigaction(SIGTERM, &sa, NULL) != 0) {
		fprintf(stderr,
			"Warning: sigaction(SIGTERM) failed: %s\n",
			strerror(errno));
	}
#endif
	return 0;
}

int main(int argc, char *argv[])
{
	AUTO_CLOSE_SOCKET SOCKET sockfd = INVALID_SOCKET;
#ifdef __linux__
	AUTO_CLOSE_FD int phc_fd = -1;
#endif
	struct sockaddr_storage servaddr;
	socklen_t servaddr_len;
	struct stamp_sender_packet tx_packet;
	uint32_t seq = 0;
	int exit_code = 0;

	if (platform_init_sender() != 0) {
		return 1;
	}

	struct sender_options opts;
	if (parse_sender_options(argc, argv, &opts) != 0) {
		exit_code = 1;
		goto cleanup;
	}

	g_ptp_mode = opts.ptp_mode;
	g_oneway_mode = opts.oneway_mode;
	g_error_estimate_nbo = stamp_default_error_estimate_nbo(g_ptp_mode);

	sockfd = init_socket(opts.host,
			     opts.port,
			     &servaddr,
			     &servaddr_len,
			     opts.af_hint,
			     SENDER_IFNAME(opts));
	if (SOCKET_ERROR_CHECK(sockfd)) {
		exit_code = 1;
		goto cleanup;
	}
#ifdef __linux__
	if (!stamp_setup_phc_from_options(sockfd,
					  opts.phc_requested,
					  opts.ifname,
					  &phc_fd,
					  &g_phc_clockid,
					  &g_phc_enabled)) {
		exit_code = 1;
		goto cleanup;
	}
#endif
	print_sender_start_message(&servaddr);

	uint8_t recv_buffer[STAMP_MAX_PACKET_SIZE];
	while (__atomic_load_n(&g_running, __ATOMIC_SEQ_CST)) {
		uint32_t real_t1_sec = 0;
		uint32_t real_t1_frac = 0;
		if (send_stamp_packet(sockfd,
				      seq,
				      &tx_packet,
				      &real_t1_sec,
				      &real_t1_frac) == 0) {
			receive_and_process_packet(sockfd,
						   &tx_packet,
						   real_t1_sec,
						   real_t1_frac,
						   recv_buffer,
						   sizeof(recv_buffer));
		}
		seq++; // uint32_t ラップは意図的（RFC 8762 準拠）
		sleep_with_interrupt_check();
	}

	print_statistics();

cleanup:
	// PHC fd は AUTO_CLOSE_FD により main() スコープ離脱時に自動 close される
#ifdef _WIN32
	// WSACleanup 前にソケットを閉じ AUTO_CLOSE_SOCKET の二重解放を防止
	if (!SOCKET_ERROR_CHECK(sockfd)) {
		CLOSE_SOCKET(sockfd);
		// NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
		sockfd = INVALID_SOCKET; // cppcheck-suppress unreadVariable
	}
	WSACleanup();
#endif
	return exit_code;
}
