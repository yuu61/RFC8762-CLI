// RFC 8762 STAMP Reflector実装
// Senderからのパケットを受信し、タイムスタンプを付けて返送する

#include "stamp.h"
#include <stdarg.h>
#ifdef _WIN32
#include <mswsock.h>
#else
#include <sys/wait.h>
#endif

// セッション統計情報
struct reflector_stats {
	uint32_t packets_reflected;
	uint32_t packets_dropped;
};

static struct reflector_stats g_stats = {0, 0};

#ifdef __linux__
#define REFLECTOR_IFNAME (g_ifname)
#else
#define REFLECTOR_IFNAME (NULL)
#endif

static bool g_ptp_mode = false;
static uint16_t
	g_error_estimate_nbo; // htons済み Error Estimate（main()で設定）
static bool g_warned_ttl_unavailable = false;

#ifndef _WIN32
// ファイアウォール管理用のグローバル変数
static uint16_t g_firewall_port = 0;
static int g_firewall_family = AF_UNSPEC;
static volatile sig_atomic_t g_firewall_rule_added = 0;

// ランタイムデバッグフラグ
static bool g_debug_mode = false;

#ifdef __linux__
// ハードウェアタイムスタンプ用インターフェース名
static const char *g_ifname = NULL;
static bool g_phc_enabled = false;
static int g_phc_fd = -1;
static clockid_t g_phc_clockid = CLOCK_REALTIME;
#endif

#define DEBUG_LOG(fmt, ...)                                                 \
	do {                                                                \
		if (g_debug_mode) {                                         \
			debug_log_impl("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
		}                                                           \
	} while (0)

__attribute__((format(printf, 1, 2), cold)) static inline void debug_log_impl(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/**
 * nftコマンドをfork+execvpで安全に実行（シェルインジェクション防止）
 * @param argv execvp用の引数配列（NULL終端）
 * @param suppress_stderr
 * trueの場合、子プロセスでstderrを/dev/nullにリダイレクト
 * @return 子プロセスの終了コード、エラー時-1
 */
__attribute__((cold)) static int run_nft_command(const char *const argv[],
						 bool suppress_stderr)
{
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		if (suppress_stderr) {
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) {
				dup2(devnull, STDERR_FILENO);
				close(devnull);
			}
		}
		// execvp は char *const argv[] を要求するが、
		// const char *const argv[] から安全にキャスト可能
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
		execvp(argv[0], (char *const *)argv);
#pragma GCC diagnostic pop
		_exit(127);
	}
	int status;
	if (waitpid(pid, &status, 0) < 0) {
		return -1;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/**
 * ファイアウォールルールを追加（nftables使用）
 * @param port UDPポート番号
 * @param family アドレスファミリ（未使用：nftables inet
 * familyがIPv4/IPv6両対応のため）
 * @return 成功時0、エラー時-1
 */
__attribute__((cold)) static int add_firewall_rule(
	uint16_t port,
	__attribute__((unused)) int family)
{
	char port_str[16];

	if (geteuid() != 0) {
		return -1;
	}

	if (port == 0) {
		fprintf(stderr,
			"Error: Invalid port number for firewall rule: %u\n",
			port);
		return -1;
	}

	snprintf(port_str, sizeof(port_str), "%u", port);

	{
		const char *const argv[] = {"nft",
					    "add",
					    "table",
					    "inet",
					    "stamp_reflector",
					    NULL};
		if (run_nft_command(argv, true) != 0) {
			fprintf(stderr,
				"Warning: Failed to create nftables table\n");
			return -1;
		}
	}

	{
		const char *const argv[] = {
			"nft",
			"add",
			"chain",
			"inet",
			"stamp_reflector",
			"input",
			"{ type filter hook input priority 0 ; }",
			NULL};
		if (run_nft_command(argv, true) != 0) {
			fprintf(stderr,
				"Warning: Failed to create nftables chain\n");
			const char *const del_argv[] = {"nft",
							"delete",
							"table",
							"inet",
							"stamp_reflector",
							NULL};
			(void)run_nft_command(del_argv, true);
			return -1;
		}
	}

	{
		const char *const argv[] = {"nft",
					    "add",
					    "rule",
					    "inet",
					    "stamp_reflector",
					    "input",
					    "udp",
					    "dport",
					    port_str,
					    "accept",
					    NULL};
		if (run_nft_command(argv, false) != 0) {
			fprintf(stderr,
				"Warning: Failed to add nftables rule for "
				"port %u\n",
				port);
			const char *const del_argv[] = {"nft",
							"delete",
							"table",
							"inet",
							"stamp_reflector",
							NULL};
			(void)run_nft_command(del_argv, true);
			return -1;
		}
	}

	printf("Firewall rule added for UDP port %u (IPv4+IPv6 via nftables)\n",
	       port);
	g_firewall_port = port;
	g_firewall_family = family;
	g_firewall_rule_added = 1;
	return 0;
}

/**
 * ファイアウォールルールを削除
 */
__attribute__((cold)) static void remove_firewall_rule(void)
{
	uint16_t port;

	// 二重実行防止
	{
		sig_atomic_t expected = 1;
		if (!__atomic_compare_exchange_n(&g_firewall_rule_added,
						 &expected,
						 0,
						 false,
						 __ATOMIC_SEQ_CST,
						 __ATOMIC_SEQ_CST)) {
			return;
		}
	}

	port = g_firewall_port;

	if (port == 0) {
		return;
	}

	const char *const argv[] =
		{"nft", "delete", "table", "inet", "stamp_reflector", NULL};
	if (run_nft_command(argv, true) == 0) {
		printf("Firewall rules removed for UDP port %u (nftables table "
		       "deleted)\n",
		       port);
	} else {
		fprintf(stderr, "Warning: Failed to remove nftables table\n");
	}

	g_firewall_port = 0;
	g_firewall_family = AF_UNSPEC;
}
#endif

/**
 * 統計情報の表示
 */
__attribute__((cold)) static void print_statistics(void)
{
	printf("\n--- STAMP Reflector Statistics ---\n");
	printf("Packets reflected: %u\n", g_stats.packets_reflected);
	printf("Packets dropped: %u\n", g_stats.packets_dropped);
}

/**
 * 使用方法の表示
 * @param prog プログラム名
 */
__attribute__((cold)) static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-4|-6] [-d] [-P] [-c] [-i iface] [port]\n",
		prog ? prog : "reflector");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -4    IPv4 only\n");
	fprintf(stderr, "  -6    IPv6 only\n");
	fprintf(stderr, "  -d    Enable debug output\n");
	fprintf(stderr, "  -P    Use PTP timestamp format (Z=1)\n");
#ifdef __linux__
	fprintf(stderr,
		"  -i    Network interface for hardware timestamping (e.g., "
		"eth0)\n");
	fprintf(stderr,
		"  -c    Use PHC (PTP Hardware Clock) "
		"(requires -i)\n");
#endif
	fprintf(stderr,
		"  (default: dual-stack, accepting both IPv4 and IPv6)\n");
}

#ifdef _WIN32
static LPFN_WSARECVMSG g_wsa_recvmsg = NULL;
#endif

#ifndef _WIN32
/**
 * cmsgからTTL/Hop Limitを抽出（Linux用）
 */
__attribute__((hot)) static inline void extract_ttl_from_cmsg(struct msghdr *msg, uint8_t *ttl)
{
	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_TTL &&
		    (size_t)cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
			int recv_ttl;
			memcpy(&recv_ttl, CMSG_DATA(cmsg), sizeof(recv_ttl));
			if (recv_ttl >= 0 && recv_ttl <= IP_TTL_MAX) {
				*ttl = (uint8_t)recv_ttl;
			}
		}
#ifdef IPV6_HOPLIMIT
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_HOPLIMIT &&
		    (size_t)cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
			int recv_hop;
			memcpy(&recv_hop, CMSG_DATA(cmsg), sizeof(recv_hop));
			if (recv_hop >= 0 && recv_hop <= IP_TTL_MAX) {
				*ttl = (uint8_t)recv_hop;
			}
		}
#endif
	}
}
#endif

/**
 * 受信TTL/Hop Limitオプションの設定
 * dual-stack ソケットの場合、IPv4-mapped IPv6 受信のため IP_RECVTTL も設定する
 */
__attribute__((cold)) static void setup_recv_ttl_options(SOCKET sockfd,
							 int family,
							 bool is_dualstack)
{
	if (family == AF_INET || is_dualstack) {
#ifdef IP_RECVTTL
		int recv_ttl = 1;
		if (setsockopt(sockfd,
			       IPPROTO_IP,
			       IP_RECVTTL,
			       (const char *)&recv_ttl,
			       sizeof(recv_ttl)) < 0) {
			fprintf(stderr,
				"Warning: IP_RECVTTL failed (error "
				"%d); TTL info may be unavailable\n",
				SOCKET_ERRNO);
		}
#else
		fprintf(stderr,
			"Warning: IP_RECVTTL not available on this "
			"platform; TTL info will be unavailable\n");
#endif
	}
	if (family != AF_INET) {
#ifdef IPV6_RECVHOPLIMIT
		int recv_hop = 1;
		if (setsockopt(sockfd,
			       IPPROTO_IPV6,
			       IPV6_RECVHOPLIMIT,
			       (const char *)&recv_hop,
			       sizeof(recv_hop)) < 0) {
			fprintf(stderr,
				"Warning: IPV6_RECVHOPLIMIT failed "
				"(error %d); Hop Limit info may be "
				"unavailable\n",
				SOCKET_ERRNO);
		}
#elif defined(IPV6_HOPLIMIT)
		int recv_hop = 1;
		if (setsockopt(sockfd,
			       IPPROTO_IPV6,
			       IPV6_HOPLIMIT,
			       (const char *)&recv_hop,
			       sizeof(recv_hop)) < 0) {
			fprintf(stderr,
				"Warning: IPV6_HOPLIMIT failed (error "
				"%d); Hop Limit info may be "
				"unavailable\n",
				SOCKET_ERRNO);
		}
#else
		fprintf(stderr,
			"Warning: IPV6_RECVHOPLIMIT/IPV6_HOPLIMIT not "
			"available on this platform; Hop Limit info "
			"will be unavailable\n");
#endif
	}
}

#ifdef _WIN32
/**
 * Windows: reflector ソケットのタイムアウト・カーネルTS設定
 */
__attribute__((cold)) static void configure_reflector_socket_windows(SOCKET sockfd)
{
	DWORD timeout_ms = STAMP_REFLECTOR_TIMEOUT_MS;
	if (setsockopt(sockfd,
		       SOL_SOCKET,
		       SO_RCVTIMEO,
		       (const char *)&timeout_ms,
		       sizeof(timeout_ms)) < 0) {
		fprintf(stderr,
			"Warning: setsockopt SO_RCVTIMEO "
			"failed (error %d)\n",
			SOCKET_ERRNO);
	}
	if (setsockopt(sockfd,
		       SOL_SOCKET,
		       SO_SNDTIMEO,
		       (const char *)&timeout_ms,
		       sizeof(timeout_ms)) < 0) {
		fprintf(stderr,
			"Warning: setsockopt SO_SNDTIMEO "
			"failed (error %d)\n",
			SOCKET_ERRNO);
	}
	stamp_enable_kernel_timestamping_windows(sockfd);
}
#else
#ifdef __linux__
/**
 * Linux: SO_TIMESTAMPING + HW TS 検出設定
 */
__attribute__((cold)) static void configure_reflector_so_timestamping(
	SOCKET sockfd,
	const char *ifname)
{
#ifdef SO_TIMESTAMPING
	int ts_flags = SOF_TIMESTAMPING_RX_SOFTWARE |
		       SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;

	if (ifname != NULL) {
		struct stamp_hwts_caps caps;
		if (stamp_detect_hwts_caps(sockfd, ifname, &caps) == 0 &&
		    caps.rx_hw) {
			if (stamp_configure_hwtstamp_filter(sockfd,
							    ifname,
							    false) == 0) {
				ts_flags |= SOF_TIMESTAMPING_RX_HARDWARE |
					    SOF_TIMESTAMPING_RAW_HARDWARE;
				fprintf(stderr,
					"Hardware timestamping "
					"enabled for RX (T2) "
					"on %s\n",
					ifname);
			} else {
				fprintf(stderr,
					"Warning: Failed to "
					"configure HW "
					"timestamping on %s; "
					"using software "
					"timestamps\n",
					ifname);
			}
		} else {
			fprintf(stderr,
				"Warning: NIC %s does not "
				"support RX HW timestamping; "
				"using software timestamps\n",
				ifname);
		}
	}

	if (setsockopt(sockfd,
		       SOL_SOCKET,
		       SO_TIMESTAMPING,
		       &ts_flags,
		       sizeof(ts_flags)) < 0) {
		DEBUG_LOG("SO_TIMESTAMPING not available (error %d)", errno);
	} else {
		DEBUG_LOG("SO_TIMESTAMPING enabled (flags=0x%x)",
			  (unsigned)ts_flags);
	}
#endif
}
#endif // __linux__

/**
 * Unix: reflector ソケットのタイムアウト・タイムスタンプ・ビジーポーリング設定
 */
__attribute__((cold)) static void configure_reflector_socket_unix(
	SOCKET sockfd,
	__attribute__((unused)) const char *ifname)
{
	struct timeval tv;
	tv.tv_sec = STAMP_REFLECTOR_TIMEOUT_MS / 1000;
	tv.tv_usec = (STAMP_REFLECTOR_TIMEOUT_MS % 1000) * 1000L;
	(void)setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	stamp_enable_so_timestamp(sockfd);

#ifdef __linux__
#ifdef SO_BUSY_POLL
	{
		int busy_poll = STAMP_BUSY_POLL_USEC;
		if (setsockopt(sockfd,
			       SOL_SOCKET,
			       SO_BUSY_POLL,
			       &busy_poll,
			       sizeof(busy_poll)) < 0) {
			DEBUG_LOG("SO_BUSY_POLL not available (error %d)",
				  errno);
		} else {
			DEBUG_LOG("SO_BUSY_POLL enabled (%d usec)", busy_poll);
		}
	}
#endif
	configure_reflector_so_timestamping(sockfd, ifname);
#endif // __linux__
}
#endif

/**
 * reflector ソケットのバインド
 * @return 成功時0、エラー時-1
 */
__attribute__((cold)) static int bind_reflector_socket(SOCKET sockfd,
						       int family,
						       uint16_t port)
{
	struct sockaddr_storage servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&servaddr;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = INADDR_ANY;
		sin->sin_port = htons(port);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&servaddr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = htons(port);
	}

	return bind(sockfd,
		    (const struct sockaddr *)&servaddr,
		    stamp_get_sockaddr_len(family));
}

/**
 * リスニングソケットの初期化
 * @return ソケットディスクリプタ、エラー時INVALID_SOCKET
 */
__attribute__((cold)) static SOCKET init_reflector_socket(
	uint16_t port,
	int af_hint,
	int *out_family,
	__attribute__((unused)) const char *ifname)
{
	SOCKET sockfd;
	int opt = 1;
	int family;
	int try_ipv4_fallback = (af_hint == AF_UNSPEC);

	family = (af_hint == AF_UNSPEC) ? AF_INET6 : af_hint;

	for (int retry = 0; retry < 2; retry++) {
		if (retry == 1) {
			family = AF_INET;
		}

		sockfd = socket(family, SOCK_DGRAM, 0);
		if (SOCKET_ERROR_CHECK(sockfd)) {
			if (try_ipv4_fallback && family == AF_INET6) {
				continue;
			}
			PRINT_SOCKET_ERROR("socket creation failed");
			return INVALID_SOCKET;
		}

		if (setsockopt(sockfd,
			       SOL_SOCKET,
			       SO_REUSEADDR,
			       (const char *)&opt,
			       sizeof(opt)) < 0) {
			PRINT_SOCKET_ERROR("setsockopt SO_REUSEADDR failed");
			fprintf(stderr,
				"Continuing without address reuse (port may "
				"not be immediately reusable after restart)\n");
		}

		if (family == AF_INET6 && af_hint == AF_UNSPEC) {
#ifdef IPV6_V6ONLY
			int v6only = 0;
			(void)setsockopt(sockfd,
					 IPPROTO_IPV6,
					 IPV6_V6ONLY,
					 (const char *)&v6only,
					 sizeof(v6only));
#endif
		}

#ifdef _WIN32
		configure_reflector_socket_windows(sockfd);
#endif
		setup_recv_ttl_options(sockfd, family, family == AF_INET6 && af_hint == AF_UNSPEC);
#ifndef _WIN32
		configure_reflector_socket_unix(sockfd, ifname);
#endif

		if (bind_reflector_socket(sockfd, family, port) < 0) {
			if (try_ipv4_fallback && family == AF_INET6) {
				CLOSE_SOCKET(sockfd);
				continue;
			}
			PRINT_SOCKET_ERROR("bind failed");
			CLOSE_SOCKET(sockfd);
			return INVALID_SOCKET;
		}

		if (out_family) {
			*out_family = family;
		}
		return sockfd;
	}

	PRINT_SOCKET_ERROR("Failed to create socket for both IPv6 and IPv4");
	return INVALID_SOCKET;
}

/**
 * STAMPパケットの反射処理
 * @return 成功時0、エラー時-1
 */
__attribute__((hot)) static inline int reflect_packet(
	SOCKET sockfd,
	uint8_t *buffer,
	int send_len,
	const struct sockaddr_storage *cliaddr,
	socklen_t len,
	uint8_t ttl,
	uint32_t t2_sec,
	uint32_t t2_frac)
{
	struct stamp_reflector_packet *packet;
	uint32_t t3_sec;
	uint32_t t3_frac;

	if (unlikely(send_len <= 0 || send_len > STAMP_MAX_PACKET_SIZE)) {
		fprintf(stderr,
			"Invalid packet size: %d (valid range: 1-%d)\n",
			send_len,
			STAMP_MAX_PACKET_SIZE);
		return -1;
	}
	if (send_len < STAMP_BASE_PACKET_SIZE) {
		fprintf(stderr,
			"Warning: packet size %d < minimum %d\n",
			send_len,
			STAMP_BASE_PACKET_SIZE);
	}

	stamp_build_reflector_packet(buffer,
				     send_len,
				     ttl,
				     t2_sec,
				     t2_frac,
				     g_error_estimate_nbo);

	packet = (struct stamp_reflector_packet *)buffer;

	// T3: 送信時刻（sendto() 直前に取得）
	// T3 はパケットに格納してから送信するため、T1 のように sendto() 後に
	// MSG_ERRQUEUE から HW TX タイムスタンプを取得する方式は使えない。
	// PHC 有効時は NIC と同一の HW クロックを読み取ることで近似する。
#ifdef __linux__
	if (g_phc_enabled) {
		if (unlikely(stamp_get_phc_timestamp(g_phc_clockid,
						     &t3_sec,
						     &t3_frac,
						     g_ptp_mode) != 0)) {
			fprintf(stderr, "Failed to get PHC T3 timestamp\n");
			return -1;
		}
	} else
#endif
		if (unlikely(stamp_get_timestamp(&t3_sec,
						 &t3_frac,
						 g_ptp_mode) != 0)) {
		fprintf(stderr, "Failed to get T3 timestamp\n");
		return -1;
	}
	packet->timestamp_sec = t3_sec;
	packet->timestamp_frac = t3_frac;

	ssize_t send_result = sendto(sockfd,
				     (const char *)buffer,
				     (size_t)send_len,
				     0,
				     (const struct sockaddr *)cliaddr,
				     len);
	if (unlikely(send_result < 0)) {
		int err = SOCKET_ERRNO;
		char addr_str[INET6_ADDRSTRLEN];
		stamp_sockaddr_to_string_safe(cliaddr,
					      addr_str,
					      sizeof(addr_str));
		fprintf(stderr,
			"sendto failed: error=%d, dest=%s, addrlen=%d, "
			"family=%d, send_len=%d\n",
			err,
			addr_str,
			(int)len,
			cliaddr->ss_family,
			send_len);
		g_stats.packets_dropped++;
		return -1;
	}

	g_stats.packets_reflected++;
	return 0;
}

#ifdef _WIN32
/**
 * Windows: WSAMSG から TTL/Hop Limit を抽出
 */
static inline void extract_ttl_from_wsamsg(WSAMSG *msg, uint8_t *ttl)
{
	WSACMSGHDR *cmsg;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
	for (cmsg = WSA_CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = WSA_CMSG_NXTHDR(msg, cmsg)) {
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_TTL &&
		    cmsg->cmsg_len >= WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR)) +
					      sizeof(int)) {
			int recv_ttl;
			memcpy(&recv_ttl,
			       WSA_CMSG_DATA(cmsg),
			       sizeof(recv_ttl));
			if (recv_ttl >= 0 && recv_ttl <= IP_TTL_MAX) {
				*ttl = (uint8_t)recv_ttl;
			}
		}
#ifdef IPV6_HOPLIMIT
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_HOPLIMIT &&
		    cmsg->cmsg_len >= WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR)) +
					      sizeof(int)) {
			int recv_hop;
			memcpy(&recv_hop,
			       WSA_CMSG_DATA(cmsg),
			       sizeof(recv_hop));
			if (recv_hop >= 0 && recv_hop <= IP_TTL_MAX) {
				*ttl = (uint8_t)recv_hop;
			}
		}
#endif
	}
}

/**
 * Windows: WSARecvMsg によるタイムスタンプ付き受信
 */
__attribute__((hot)) static inline int recv_stamp_packet_wsa(
	SOCKET sockfd,
	uint8_t *buffer,
	int buffer_len,
	struct sockaddr_storage *cliaddr,
	socklen_t *len,
	uint8_t *ttl,
	uint32_t *t2_sec,
	uint32_t *t2_frac)
{
	WSABUF data_buf;
	WSAMSG msg;
	char control[STAMP_CMSG_BUFSIZE];
	DWORD bytes = 0;

	data_buf.buf = (CHAR *)buffer;
	data_buf.len = (ULONG)buffer_len;
	memset(&msg, 0, sizeof(msg));
	msg.name = (LPSOCKADDR)cliaddr;
	msg.namelen = *len;
	msg.lpBuffers = &data_buf;
	msg.dwBufferCount = 1;
	msg.Control.buf = control;
	msg.Control.len = sizeof(control);

	if (g_wsa_recvmsg(sockfd, &msg, &bytes, NULL, NULL) == SOCKET_ERROR) {
		return -1;
	}

	*len = msg.namelen;

	if (t2_sec && t2_frac) {
		if (!stamp_extract_kernel_timestamp_windows(&msg,
							    t2_sec,
							    t2_frac,
							    g_ptp_mode)) {
			if (unlikely(stamp_get_timestamp(t2_sec,
							 t2_frac,
							 g_ptp_mode) != 0)) {
				fprintf(stderr,
					"Warning: Failed to get fallback T2 "
					"timestamp\n");
				return -1;
			}
		}
	}

	if (ttl) {
		extract_ttl_from_wsamsg(&msg, ttl);
	}

	return (int)bytes;
}

/**
 * Windows: recvfrom フォールバック受信
 */
__attribute__((hot)) static inline int recv_stamp_packet_fallback(
	SOCKET sockfd,
	uint8_t *buffer,
	int buffer_len,
	struct sockaddr_storage *cliaddr,
	socklen_t *len,
	uint32_t *t2_sec,
	uint32_t *t2_frac)
{
	int n = recvfrom(sockfd,
			 (char *)buffer,
			 buffer_len,
			 0,
			 (struct sockaddr *)cliaddr,
			 len);
	if (n > 0 && t2_sec && t2_frac) {
		if (unlikely(stamp_get_timestamp(t2_sec, t2_frac, g_ptp_mode) !=
			     0)) {
			fprintf(stderr,
				"Warning: Failed to get fallback T2 "
				"timestamp\n");
			return -1;
		}
	}
	return n;
}
#else
/**
 * Unix: recvmsg によるタイムスタンプ付き受信
 */
__attribute__((hot)) static inline int recv_stamp_packet_unix(
	SOCKET sockfd,
	uint8_t *buffer,
	int buffer_len,
	struct sockaddr_storage *cliaddr,
	socklen_t *len,
	uint8_t *ttl,
	uint32_t *t2_sec,
	uint32_t *t2_frac)
{
	struct msghdr msg;
	struct iovec iov;
	char control[STAMP_CMSG_BUFSIZE];

	if (ttl) {
		*ttl = 0;
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buffer;
	iov.iov_len = (size_t)buffer_len;
	msg.msg_name = cliaddr;
	msg.msg_namelen = *len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ssize_t n = recvmsg(sockfd, &msg, 0);
	if (unlikely(n < 0)) {
		return -1;
	}

	*len = msg.msg_namelen;

	if (t2_sec && t2_frac) {
		if (!stamp_extract_kernel_timestamp_linux(&msg,
							  t2_sec,
							  t2_frac,
							  g_ptp_mode)) {
			if (unlikely(stamp_get_timestamp(t2_sec,
							 t2_frac,
							 g_ptp_mode) != 0)) {
				fprintf(stderr,
					"Warning: Failed to get fallback T2 "
					"timestamp\n");
				return -1;
			}
		}
	}

	if (ttl) {
		extract_ttl_from_cmsg(&msg, ttl);
	}

	return (int)n;
}
#endif

/**
 * STAMPパケットの受信（タイムスタンプ付き）
 * @return 受信バイト数、エラー時-1
 */
__attribute__((hot)) static inline int recv_stamp_packet(
	SOCKET sockfd,
	uint8_t *buffer,
	int buffer_len,
	struct sockaddr_storage *cliaddr,
	socklen_t *len,
	uint8_t *ttl,
	uint32_t *t2_sec,
	uint32_t *t2_frac)
{
#ifdef _WIN32
	if (ttl) {
		*ttl = 0;
	}
	if (g_wsa_recvmsg == NULL) {
		return recv_stamp_packet_fallback(sockfd,
						  buffer,
						  buffer_len,
						  cliaddr,
						  len,
						  t2_sec,
						  t2_frac);
	}
	return recv_stamp_packet_wsa(sockfd,
				     buffer,
				     buffer_len,
				     cliaddr,
				     len,
				     ttl,
				     t2_sec,
				     t2_frac);
#else
	return recv_stamp_packet_unix(sockfd,
				      buffer,
				      buffer_len,
				      cliaddr,
				      len,
				      ttl,
				      t2_sec,
				      t2_frac);
#endif
}

/**
 * reflector のコマンドラインオプション
 */
struct reflector_options {
	int af_hint;
	uint16_t port;
	bool ptp_mode;
#ifndef _WIN32
	bool debug_mode;
#endif
#ifdef __linux__
	bool phc_requested;
#endif
};

/**
 * コマンドラインオプションの解析
 * @return 成功時0、エラー時1
 */
__attribute__((cold)) static int
parse_reflector_options(int argc, char *argv[], struct reflector_options *opts)
{
	opts->af_hint = AF_UNSPEC;
	opts->port = STAMP_PORT;
	opts->ptp_mode = false;
#ifndef _WIN32
	opts->debug_mode = false;
#endif
#ifdef __linux__
	opts->phc_requested = false;
#endif

	int opt;
	while ((opt = getopt(argc, argv, "46di:Pc")) != -1) {
		switch (opt) {
		case '4':
			opts->af_hint = AF_INET;
			break;
		case '6':
			opts->af_hint = AF_INET6;
			break;
		case 'd':
#ifndef _WIN32
			opts->debug_mode = true;
#else
			fprintf(stderr,
				"Warning: Debug mode not supported on "
				"Windows\n");
#endif
			break;
		case 'i':
#ifdef __linux__
			g_ifname = optarg;
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
		default:
			print_usage(argc > 0 ? argv[0] : "reflector");
			return 1;
		}
	}

	int remaining_args = argc - optind;
	if (remaining_args > 1) {
		print_usage(argc > 0 ? argv[0] : "reflector");
		return 1;
	}

	if (remaining_args > 0 &&
	    stamp_parse_port(argv[optind], &opts->port) != 0) {
		fprintf(stderr, "Invalid port: %s\n", argv[optind]);
		print_usage(argc > 0 ? argv[0] : "reflector");
		return 1;
	}

	return 0;
}

#ifndef _WIN32
/**
 * シグナルハンドラとファイアウォールルールの設定
 */
__attribute__((cold)) static void setup_signal_and_firewall(uint16_t port,
							    int socket_family)
{
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
	if (sigaction(SIGABRT, &sa, NULL) != 0) {
		fprintf(stderr,
			"Warning: sigaction(SIGABRT) failed: %s\n",
			strerror(errno));
	}

	// NOTE: SIGKILL/OOM killer は捕捉不可。ルール残留時は手動で対処:
	//   nft delete table inet stamp_reflector
	if (geteuid() == 0) {
		// TODO: atexit() が root 権限を必要とするため権限ドロップは未実装。
		// 将来的には CAP_NET_ADMIN のみ保持か systemd socket activation を検討。
		if (add_firewall_rule(port, socket_family) == 0) {
			if (atexit(remove_firewall_rule) != 0) {
				fprintf(stderr,
					"Warning: atexit() failed; firewall "
					"rule may not be cleaned up\n");
			}
		}
	}
}
#endif

static void print_reflected_info(
	const uint8_t *buffer,
	const struct sockaddr_storage *cliaddr,
	uint8_t ttl)
{
	const struct stamp_reflector_packet *packet =
		(const struct stamp_reflector_packet *)buffer;
	char addr_port_str[STAMP_ADDR_PORT_BUFSIZE];
	stamp_format_sockaddr_with_port(cliaddr,
					addr_port_str,
					sizeof(addr_port_str));
	const char *ttl_label =
		(cliaddr->ss_family == AF_INET6) ? "Hop Limit" : "TTL";
	printf("Reflected packet Seq: %" PRIu32 " from %s (%s: %d)\n",
	       (uint32_t)ntohl(packet->sender_seq_num),
	       addr_port_str,
	       ttl_label,
	       ttl);
}

/**
 * 1パケット分の受信・反射処理 (RFC 8762 Section 4.2)
 *
 * 受信→バリデーション→パディング→応答送信の4段階で処理する。
 */
__attribute__((hot)) static void handle_one_packet(
	SOCKET sockfd,
	uint8_t *buffer,
	int buffer_size,
	struct sockaddr_storage *cliaddr,
	socklen_t *len)
{
	uint8_t ttl = 0;
	uint32_t t2_sec = 0;
	uint32_t t2_frac = 0;

	/* Step 1: パケット受信（HW/SW タイムスタンプ付き） */
	int n = recv_stamp_packet(sockfd,
				  buffer,
				  buffer_size,
				  cliaddr,
				  len,
				  &ttl,
				  &t2_sec,
				  &t2_frac);
	if (n < 0) {
		if (!g_running) {
			return;
		}
#ifdef _WIN32
		if (WSAGetLastError() == WSAETIMEDOUT) {
			return;
		}
#else
		if (IS_WOULDBLOCK(errno)) {
			return;
		}
#endif
		PRINT_SOCKET_ERROR("recvfrom failed");
		return;
	}
	if (n == 0) {
		return;
	}

#ifndef _WIN32
	if (g_debug_mode) {
		char addr_port_str[STAMP_ADDR_PORT_BUFSIZE];
		stamp_format_sockaddr_with_port(cliaddr,
						addr_port_str,
						sizeof(addr_port_str));
		DEBUG_LOG("Received %d bytes from %s (family=%d, "
			  "addrlen=%d, ttl=%d)",
			  n,
			  addr_port_str,
			  cliaddr->ss_family,
			  (int)*len,
			  ttl);
	}
#endif

	/* Step 2: 入力バリデーション（Error Estimate・パケット長・TTL） */
	enum stamp_reflector_input_check_result input_check =
		stamp_check_reflector_input(buffer, n, ttl);

	if (unlikely(input_check == STAMP_REFLECTOR_INPUT_INVALID_PAYLOAD)) {
		fprintf(stderr,
			"Warning: invalid STAMP/TWAMP-Test payload received "
			"(%d bytes, invalid Error Estimate or too short); "
			"dropping\n",
			n);
		g_stats.packets_dropped++;
		return;
	}

	if (unlikely(input_check == STAMP_REFLECTOR_INPUT_MISSING_TTL)) {
		if (!g_warned_ttl_unavailable) {
			fprintf(stderr,
				"Warning: TTL/Hop Limit could not be obtained; "
				"dropping packets to preserve RFC 8762 "
				"Session-Sender TTL copy semantics\n");
			g_warned_ttl_unavailable = true;
		}
		g_stats.packets_dropped++;
		return;
	}

	/* Step 3: 規定サイズ未満のパケットをゼロパディング */
	int send_len = n;
	if (send_len < STAMP_BASE_PACKET_SIZE) {
		fprintf(stderr,
			"Warning: undersized STAMP packet received (%d "
			"bytes); will pad to %d bytes.\n",
			n,
			STAMP_BASE_PACKET_SIZE);
		memset(buffer + send_len,
		       0,
		       (size_t)(STAMP_BASE_PACKET_SIZE - send_len));
		send_len = STAMP_BASE_PACKET_SIZE;
	}

	/* Step 4: 応答パケットを構築して送信元へ返送 */
	if (reflect_packet(sockfd,
			   buffer,
			   send_len,
			   cliaddr,
			   *len,
			   ttl,
			   t2_sec,
			   t2_frac) == 0) {
		print_reflected_info(buffer, cliaddr, ttl);
	}
}

/**
 * 開始メッセージの表示
 */
__attribute__((cold)) static void
print_reflector_start_message(uint16_t port, int af_hint, int socket_family)
{
	const char *mode_str;
	if (af_hint == AF_UNSPEC) {
		mode_str = (socket_family == AF_INET6)
				   ? "dual-stack (IPv4+IPv6)"
				   : "IPv4";
	} else {
		mode_str = (socket_family == AF_INET6) ? "IPv6" : "IPv4";
	}
	printf("STAMP Reflector listening on port %u (%s)", port, mode_str);
	if (g_ptp_mode) {
		printf(" [PTP]");
	}
#ifdef __linux__
	if (g_phc_enabled) {
		printf(" [PHC]");
	}
#endif
	printf("...\n");
	printf("Press Ctrl+C to stop and show statistics\n");
}

/**
 * reflector
 * のプラットフォーム固有の起動後設定（WSARecvMsg/シグナル/ファイアウォール）
 */
__attribute__((cold)) static void
platform_post_init_reflector(SOCKET sockfd, uint16_t port, int socket_family)
{
#ifdef _WIN32
	(void)port;
	(void)socket_family;
	if (!stamp_init_wsa_recvmsg(sockfd, &g_wsa_recvmsg)) {
		fprintf(stderr,
			"Warning: WSARecvMsg not available; "
			"kernel timestamps disabled\n");
	}
	SetConsoleCtrlHandler(stamp_signal_handler, TRUE);
#else
	(void)sockfd;
	setup_signal_and_firewall(port, socket_family);
	if (g_debug_mode) {
		fprintf(stderr, "[DEBUG] Debug mode enabled\n");
	}
#endif
}

int main(int argc, char *argv[])
{
	AUTO_CLOSE_SOCKET SOCKET sockfd = INVALID_SOCKET;
	struct sockaddr_storage cliaddr;
	uint8_t buffer[STAMP_MAX_PACKET_SIZE];
	socklen_t len;
	int socket_family = AF_INET;
	int exit_code = 0;

#ifdef _WIN32
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}
#endif

	struct reflector_options opts;
	if (parse_reflector_options(argc, argv, &opts) != 0) {
		exit_code = 1;
		goto cleanup;
	}

	g_ptp_mode = opts.ptp_mode;
	g_error_estimate_nbo = htons(g_ptp_mode ? ERROR_ESTIMATE_PTP_DEFAULT
						: ERROR_ESTIMATE_DEFAULT);
#ifndef _WIN32
	g_debug_mode = opts.debug_mode;
	if (opts.port < 1024 && geteuid() != 0) {
		fprintf(stderr,
			"Warning: binding to privileged port %u may fail "
			"without root privileges.\n",
			opts.port);
	}
#endif

	sockfd = init_reflector_socket(opts.port,
				       opts.af_hint,
				       &socket_family,
				       REFLECTOR_IFNAME);
	if (SOCKET_ERROR_CHECK(sockfd)) {
		exit_code = 1;
		goto cleanup;
	}
#ifdef __linux__
	if (opts.phc_requested) {
		if (g_ifname == NULL) {
			fprintf(stderr, "Error: -c requires -i <interface>\n");
			exit_code = 1;
			goto cleanup;
		}
		if (stamp_init_phc(sockfd,
				   g_ifname,
				   &g_phc_fd,
				   &g_phc_clockid) == 0) {
			g_phc_enabled = true;
		}
	}
#endif
	platform_post_init_reflector(sockfd, opts.port, socket_family);
	print_reflector_start_message(opts.port, opts.af_hint, socket_family);

	while (__atomic_load_n(&g_running, __ATOMIC_SEQ_CST)) {
		len = sizeof(cliaddr);
		handle_one_packet(sockfd,
				  buffer,
				  sizeof(buffer),
				  &cliaddr,
				  &len);
	}

	print_statistics();

cleanup:
#ifdef __linux__
	if (g_phc_fd >= 0) {
		close(g_phc_fd);
		g_phc_fd = -1;
	}
#endif
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
