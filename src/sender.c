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
#define STAMP_ASYMMETRY_WARN_THRESHOLD_MS 10.0

// サンプル保持バッファの容量（percentile/PDV 用、-n/-w 指定時のみ確保）
#define STAMP_SAMPLE_INITIAL_CAP 256U
#define STAMP_SAMPLE_MAX_CAP	 ((size_t)10 * 1000 * 1000) // 暴走/OOM 防止

// 連続送信失敗の上限。-n は実送信本数で数えるため、宛先到達不能（連続 send 失敗）
// かつ -w 未指定だと -n の停止条件に到達できず無限ループに陥る。その救済として、
// この回数だけ連続で send が失敗したら測定を打ち切る（送信間隔 1 秒なので概ね
// この秒数で諦める）。成功すればカウンタはリセットされ、一過性の失敗では発火しない。
#define STAMP_MAX_CONSECUTIVE_SEND_FAILURES 10U

#ifdef __linux__
#define SENDER_IFNAME(opts) ((opts).ifname)
#else
#define SENDER_IFNAME(opts) (NULL)
#endif

static bool g_negative_delay_seen = false;
static bool g_oneway_mode = false;
// 出力形式（human/json/csv）。main() が CLI から設定
static enum output_format g_output_format = OUTPUT_HUMAN;
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
	// Welford アキュムレータ（min/avg/max/stddev を数値安定に集計）
	struct stamp_welford rtt;
	struct stamp_welford fwd;    // 往路遅延（one-way モード時）
	struct stamp_welford bwd;    // 復路遅延（one-way モード時）
	struct stamp_welford offset; // クロックオフセット（常時集計）
	// IPDV (RFC 3393): |D(i)-D(i-1)| のストリーミング集計（隣接パケットのみ）
	struct stamp_welford ipdv_rtt;
	struct stamp_welford ipdv_fwd;
	struct stamp_welford ipdv_bwd;
	double prev_rtt; // 直前に受信したパケットの各遅延（IPDV 用）
	double prev_fwd;
	double prev_bwd;
	uint32_t prev_seq; // 直前に受信したパケットの seq（連続性判定用）
	bool has_prev;	   // prev_* が有効か
};

// count==0 が Welford の未初期化マーカーなので全 0 初期化で十分
static struct sender_stats g_stats = {0};

// percentile/PDV 用の全サンプル（-n/-w 指定時のみ確保）。g_stats とは分離。
// IPDV はストリーミング集計するため seq は保持しない（rtt/fwd/bwd のみ）。
struct stamp_sample_buffer {
	double *rtt;
	double *fwd; // one-way モード時のみ確保
	double *bwd; // one-way モード時のみ確保
	size_t count;
	size_t cap;
};
static struct stamp_sample_buffer g_samples = {0};
static bool g_collect_samples = false; // (-n || -w) のとき true
static bool g_sample_oom_warned = false;

/**
 * サンプルバッファを new_cap 要素へ拡張し、既存 count 件をコピーして原子的に
 * 差し替える。rtt（one-way 時は fwd/bwd も）のいずれかの確保に失敗した場合は
 * g_samples を一切変更せず（旧バッファ・旧データを保持して）false を返す。
 * realloc を使わず malloc→memcpy→swap とすることで、片側だけ成長して系列長が
 * 食い違う（または無駄に確保したまま蓄積停止する）不整合を防ぐ。
 * @param new_cap 目標容量（g_samples.cap より大きいこと）
 * @param oneway one-way モード（fwd/bwd も確保するか）
 * @return 成功時 true
 */
static bool stamp_sample_buffer_grow_to(size_t new_cap, bool oneway)
{
	double *new_rtt = malloc(new_cap * sizeof(*new_rtt));
	double *new_fwd = NULL;
	double *new_bwd = NULL;
	if (oneway) {
		new_fwd = malloc(new_cap * sizeof(*new_fwd));
		new_bwd = malloc(new_cap * sizeof(*new_bwd));
	}
	if (new_rtt == NULL || (oneway && (new_fwd == NULL || new_bwd == NULL))) {
		free(new_rtt);
		free(new_fwd);
		free(new_bwd);
		return false;
	}

	size_t n = g_samples.count;
	if (n > 0) {
		memcpy(new_rtt, g_samples.rtt, n * sizeof(*new_rtt));
		if (oneway) {
			memcpy(new_fwd, g_samples.fwd, n * sizeof(*new_fwd));
			memcpy(new_bwd, g_samples.bwd, n * sizeof(*new_bwd));
		}
	}
	free(g_samples.rtt);
	g_samples.rtt = new_rtt;
	if (oneway) {
		free(g_samples.fwd);
		g_samples.fwd = new_fwd;
		free(g_samples.bwd);
		g_samples.bwd = new_bwd;
	}
	g_samples.cap = new_cap;
	return true;
}

/**
 * サンプルバッファの容量を確保（不足時に 2 倍成長）。
 * 成長失敗・上限到達時は警告を 1 回出して以後の蓄積を停止する（計測は継続）。
 * @param oneway one-way モード（fwd/bwd も確保するか）
 * @return 1 件書き込み可能なら true
 */
static bool stamp_sample_buffer_reserve(bool oneway)
{
	if (g_samples.count < g_samples.cap) {
		return true;
	}
	if (g_sample_oom_warned) {
		return false; // 既に上限到達/確保失敗済み
	}
	if (g_samples.cap >= STAMP_SAMPLE_MAX_CAP) {
		fprintf(stderr,
			"Warning: sample buffer reached %zu entries; "
			"percentiles use a truncated sample set\n",
			STAMP_SAMPLE_MAX_CAP);
		g_sample_oom_warned = true;
		return false;
	}

	size_t new_cap = g_samples.cap == 0 ? STAMP_SAMPLE_INITIAL_CAP
					    : g_samples.cap * 2;
	if (new_cap > STAMP_SAMPLE_MAX_CAP) {
		new_cap = STAMP_SAMPLE_MAX_CAP;
	}

	if (!stamp_sample_buffer_grow_to(new_cap, oneway)) {
		fprintf(stderr,
			"Warning: failed to grow sample buffer; "
			"percentiles use a truncated sample set\n");
		g_sample_oom_warned = true;
		return false;
	}
	return true;
}

/**
 * 最終サイズが既知（-n 指定）のとき、サンプルバッファを一括確保する。
 * 毎回の 2 倍成長・コピーを避ける最適化。失敗しても致命とせず、以後の動的成長に
 * フォールバックする（OOM ラッチも立てない）。
 * @param want 確保したい要素数（STAMP_SAMPLE_MAX_CAP で頭打ち）
 * @param oneway one-way モード（fwd/bwd も確保するか）
 */
static void stamp_sample_buffer_prereserve(size_t want, bool oneway)
{
	if (want > STAMP_SAMPLE_MAX_CAP) {
		want = STAMP_SAMPLE_MAX_CAP;
	}
	if (want <= g_samples.cap) {
		return; // 既に十分（want==0 を含む）
	}
	(void)stamp_sample_buffer_grow_to(want, oneway);
}

/**
 * サンプルをバッファに追加（容量不足時は成長）。成長失敗時は破棄する。
 */
static void stamp_sample_buffer_push(double rtt,
				     double fwd,
				     double bwd,
				     bool oneway)
{
	if (!stamp_sample_buffer_reserve(oneway)) {
		return;
	}
	size_t i = g_samples.count;
	g_samples.rtt[i] = rtt;
	if (oneway) {
		g_samples.fwd[i] = fwd;
		g_samples.bwd[i] = bwd;
	}
	g_samples.count++;
}

/**
 * サンプルバッファを解放（free(NULL) 安全。未確保でも呼べる）
 */
static void stamp_sample_buffer_free(void)
{
	free(g_samples.rtt);
	free(g_samples.fwd);
	free(g_samples.bwd);
	g_samples.rtt = NULL;
	g_samples.fwd = NULL;
	g_samples.bwd = NULL;
	g_samples.count = 0;
	g_samples.cap = 0;
}

// 系列ごとの分布指標（human / machine 出力で共用）
struct series_dist {
	double p50;
	double p95;
	double p99;
	double pdv;
};

/**
 * 系列のパーセンタイル・PDV をまとめて算出する（配列を破壊的にソート）。
 * human / machine 両出力でこの 1 箇所を共用し、指標定義の二重実装を避ける。
 */
__attribute__((nonnull(1))) static struct series_dist
compute_series_dist(double *arr, size_t n)
{
	struct series_dist d = {NAN, NAN, NAN, NAN};
	if (n == 0) {
		return d;
	}
	qsort(arr, n, sizeof(*arr), stamp_double_cmp);
	d.p50 = stamp_percentile_sorted(arr, n, 50.0);
	d.p95 = stamp_percentile_sorted(arr, n, 95.0);
	d.p99 = stamp_percentile_sorted(arr, n, 99.0);
	// PDV (RFC 5481) = p95 - 最小値。ソート済みで arr[0] が最小なので、
	// 算出済みの p95 を再利用する（p95 の二重計算を回避）
	d.pdv = d.p95 - arr[0];
	return d;
}

/**
 * 分布サマリ行を表示（配列を破壊的に昇順ソートし、percentile と PDV を出力）
 * @param label 系列名（"RTT" 等）
 * @param arr サンプル配列（ソートされる）
 * @param n 要素数
 */
static void print_distribution(const char *label, double *arr, size_t n)
{
	if (n == 0) {
		return;
	}
	struct series_dist d = compute_series_dist(arr, n);
	printf("%s p50/p95/p99 = %.3f/%.3f/%.3f ms\n",
	       label,
	       d.p50,
	       d.p95,
	       d.p99);
	printf("%s PDV (p95-min) = %.3f ms\n", label, d.pdv);
}

/**
 * IPDV (RFC 3393) 行を表示（隣接パケット間遅延変動の平均/最大）
 * @param label 系列名
 * @param ipdv IPDV の Welford アキュムレータ
 */
static void print_ipdv(const char *label, const struct stamp_welford *ipdv)
{
	if (stamp_welford_count(ipdv) == 0) {
		return;
	}
	printf("%s IPDV avg/max = %.3f/%.3f ms\n",
	       label,
	       stamp_welford_mean(ipdv),
	       stamp_welford_max(ipdv));
}

/**
 * 統計情報の表示（人間可読テキスト）
 */
__attribute__((cold)) static void print_statistics_human(void)
{
	printf("\n--- STAMP Statistics ---\n");
	printf("Packets sent: %u\n", g_stats.sent);
	printf("Packets received: %u\n", g_stats.received);
	printf("Packet loss: %.2f%%\n",
	       stamp_packet_loss(g_stats.sent, g_stats.received));
	printf("Timeouts: %u\n", g_stats.timeouts);
	if (g_stats.received > 0) {
		printf("RTT min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		       stamp_welford_min(&g_stats.rtt),
		       stamp_welford_mean(&g_stats.rtt),
		       stamp_welford_max(&g_stats.rtt),
		       stamp_welford_stddev(&g_stats.rtt));
		printf("Clock offset min/avg/max/stddev = "
		       "%.3f/%.3f/%.3f/%.3f ms\n",
		       stamp_welford_min(&g_stats.offset),
		       stamp_welford_mean(&g_stats.offset),
		       stamp_welford_max(&g_stats.offset),
		       stamp_welford_stddev(&g_stats.offset));
		print_ipdv("RTT     ", &g_stats.ipdv_rtt);
		if (g_oneway_mode) {
			printf("Forward  min/avg/max/jitter = "
			       "%.3f/%.3f/%.3f/%.3f ms\n",
			       stamp_welford_min(&g_stats.fwd),
			       stamp_welford_mean(&g_stats.fwd),
			       stamp_welford_max(&g_stats.fwd),
			       stamp_welford_stddev(&g_stats.fwd));
			printf("Backward min/avg/max/jitter = "
			       "%.3f/%.3f/%.3f/%.3f ms\n",
			       stamp_welford_min(&g_stats.bwd),
			       stamp_welford_mean(&g_stats.bwd),
			       stamp_welford_max(&g_stats.bwd),
			       stamp_welford_stddev(&g_stats.bwd));
			print_ipdv("Forward ", &g_stats.ipdv_fwd);
			print_ipdv("Backward", &g_stats.ipdv_bwd);
		}
		if (g_collect_samples && g_samples.count > 0) {
			if (g_sample_oom_warned) {
				printf("Note: percentiles/PDV use a truncated "
				       "sample set (sample limit reached)\n");
			}
			print_distribution("RTT     ",
					   g_samples.rtt,
					   g_samples.count);
			if (g_oneway_mode) {
				print_distribution("Forward ",
						   g_samples.fwd,
						   g_samples.count);
				print_distribution("Backward",
						   g_samples.bwd,
						   g_samples.count);
			}
		}
	}
}

// machine 出力用: 未集計(count==0)の Welford 値は NAN（JSON null/CSV 空）にする
__attribute__((nonnull(1))) static double
wf_min(const struct stamp_welford *w)
{
	return stamp_welford_count(w) == 0 ? (double)NAN : stamp_welford_min(w);
}
__attribute__((nonnull(1))) static double
wf_avg(const struct stamp_welford *w)
{
	return stamp_welford_count(w) == 0 ? (double)NAN : stamp_welford_mean(w);
}
__attribute__((nonnull(1))) static double
wf_max(const struct stamp_welford *w)
{
	return stamp_welford_count(w) == 0 ? (double)NAN : stamp_welford_max(w);
}
__attribute__((nonnull(1))) static double
wf_std(const struct stamp_welford *w)
{
	// 標本標準偏差(n-1)はサンプル数<2で未定義。min/avg/max と異なり 0 で
	// 偽装せず NAN（JSON null / CSV 空）を返し「欠損」を明示する。
	return stamp_welford_count(w) < 2 ? (double)NAN : stamp_welford_stddev(w);
}

/**
 * 統計情報を機械可読形式（JSON/CSV）で出力する。
 * @param servaddr ターゲットアドレス（target/family 整形用）
 */
__attribute__((cold, nonnull(1))) static void
print_statistics_machine(const struct sockaddr_storage *servaddr)
{
	char target[STAMP_ADDR_PORT_BUFSIZE];
	stamp_format_sockaddr_with_port(servaddr, target, sizeof(target));

	size_t n = g_samples.count;
	bool have_samples = g_collect_samples && n > 0;
	struct series_dist drtt = {NAN, NAN, NAN, NAN};
	struct series_dist dfwd = {NAN, NAN, NAN, NAN};
	struct series_dist dbwd = {NAN, NAN, NAN, NAN};
	if (have_samples) {
		drtt = compute_series_dist(g_samples.rtt, n);
		if (g_oneway_mode) {
			dfwd = compute_series_dist(g_samples.fwd, n);
			dbwd = compute_series_dist(g_samples.bwd, n);
		}
	}

	const struct stamp_report_field fields[] = {
		{"rtt_min_ms", wf_min(&g_stats.rtt)},
		{"rtt_avg_ms", wf_avg(&g_stats.rtt)},
		{"rtt_max_ms", wf_max(&g_stats.rtt)},
		{"rtt_stddev_ms", wf_std(&g_stats.rtt)},
		{"offset_min_ms", wf_min(&g_stats.offset)},
		{"offset_avg_ms", wf_avg(&g_stats.offset)},
		{"offset_max_ms", wf_max(&g_stats.offset)},
		{"offset_stddev_ms", wf_std(&g_stats.offset)},
		{"fwd_min_ms", wf_min(&g_stats.fwd)},
		{"fwd_avg_ms", wf_avg(&g_stats.fwd)},
		{"fwd_max_ms", wf_max(&g_stats.fwd)},
		{"fwd_stddev_ms", wf_std(&g_stats.fwd)},
		{"bwd_min_ms", wf_min(&g_stats.bwd)},
		{"bwd_avg_ms", wf_avg(&g_stats.bwd)},
		{"bwd_max_ms", wf_max(&g_stats.bwd)},
		{"bwd_stddev_ms", wf_std(&g_stats.bwd)},
		{"rtt_ipdv_avg_ms", wf_avg(&g_stats.ipdv_rtt)},
		{"rtt_ipdv_max_ms", wf_max(&g_stats.ipdv_rtt)},
		{"fwd_ipdv_avg_ms", wf_avg(&g_stats.ipdv_fwd)},
		{"fwd_ipdv_max_ms", wf_max(&g_stats.ipdv_fwd)},
		{"bwd_ipdv_avg_ms", wf_avg(&g_stats.ipdv_bwd)},
		{"bwd_ipdv_max_ms", wf_max(&g_stats.ipdv_bwd)},
		{"rtt_p50_ms", drtt.p50},
		{"rtt_p95_ms", drtt.p95},
		{"rtt_p99_ms", drtt.p99},
		{"rtt_pdv_ms", drtt.pdv},
		{"fwd_p50_ms", dfwd.p50},
		{"fwd_p95_ms", dfwd.p95},
		{"fwd_p99_ms", dfwd.p99},
		{"fwd_pdv_ms", dfwd.pdv},
		{"bwd_p50_ms", dbwd.p50},
		{"bwd_p95_ms", dbwd.p95},
		{"bwd_p99_ms", dbwd.p99},
		{"bwd_pdv_ms", dbwd.pdv},
	};

	struct stamp_report report = {
		.target = target,
		.family = stamp_family_str(servaddr->ss_family),
		.ptp = g_ptp_mode,
		.oneway = g_oneway_mode,
		.samples_truncated = g_sample_oom_warned,
		.packets_tx = g_stats.sent,
		.packets_rx = g_stats.received,
		.timeouts = g_stats.timeouts,
		.loss_ratio =
			stamp_packet_loss(g_stats.sent, g_stats.received) /
			100.0,
		.fields = fields,
		.field_count = sizeof(fields) / sizeof(fields[0]),
	};

	if (g_output_format == OUTPUT_JSON) {
		stamp_report_write_json(stdout, &report);
	} else {
		stamp_report_write_csv(stdout, &report);
	}
}

/**
 * 統計情報の表示（出力形式に応じて分岐）
 * @param servaddr ターゲットアドレス
 */
__attribute__((cold, nonnull(1))) static void
print_statistics(const struct sockaddr_storage *servaddr)
{
	if (g_output_format == OUTPUT_HUMAN) {
		print_statistics_human();
	} else {
		print_statistics_machine(servaddr);
	}
	// クロックスキュー警告は全モードで stderr に出す
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
		"Usage: %s [-4|-6] [-P] [-c] [-O] [-n count] [-w sec] "
		"[-o fmt] [-i iface] [server_ip|hostname] [port]\n",
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
	fprintf(stderr,
		"  -n    Number of packets to send, then stop "
		"(enables percentiles)\n");
	fprintf(stderr,
		"  -w    Measurement duration in seconds, then stop "
		"(enables percentiles)\n");
	fprintf(stderr,
		"  -o    Output format: human (default), json, or csv\n");
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
	stamp_welford_update(&g_stats.rtt, rtt);
}

/**
 * One-way delay 統計の更新と異常値警告
 */
static inline void update_oneway_stats(double forward_delay,
				       double backward_delay)
{
	stamp_welford_update(&g_stats.fwd, forward_delay);
	stamp_welford_update(&g_stats.bwd, backward_delay);

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
	if (g_output_format != OUTPUT_HUMAN) {
		return; // 機械可読モードでは毎パケット行を抑制
	}
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
 * IPDV (RFC 3393) 統計の更新。
 * 直前に受信したパケットと seq が連続する場合のみ |D(i)-D(i-1)| を集計する。
 * パケットロス等で seq が飛んだ場合は隣接性が崩れるため集計しない。
 */
static inline void update_ipdv_stats(double rtt,
				     double forward_delay,
				     double backward_delay,
				     uint32_t seq)
{
	if (g_stats.has_prev &&
	    stamp_seq_is_consecutive(g_stats.prev_seq, seq)) {
		stamp_welford_update(&g_stats.ipdv_rtt,
				     fabs(rtt - g_stats.prev_rtt));
		if (g_oneway_mode) {
			stamp_welford_update(
				&g_stats.ipdv_fwd,
				fabs(forward_delay - g_stats.prev_fwd));
			stamp_welford_update(
				&g_stats.ipdv_bwd,
				fabs(backward_delay - g_stats.prev_bwd));
		}
	}
	g_stats.prev_rtt = rtt;
	g_stats.prev_fwd = forward_delay;
	g_stats.prev_bwd = backward_delay;
	g_stats.prev_seq = seq;
	g_stats.has_prev = true;
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
	stamp_welford_update(&g_stats.offset, offset);
	if (g_oneway_mode) {
		update_oneway_stats(forward_delay, backward_delay);
	}
	update_ipdv_stats(rtt,
			  forward_delay,
			  backward_delay,
			  (uint32_t)ntohl(rx_packet->sender_seq_num));
	if (g_collect_samples) {
		stamp_sample_buffer_push(rtt,
					 forward_delay,
					 backward_delay,
					 g_oneway_mode);
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
	uint32_t count;		   // -n: 送信本数上限（0=無制限）
	uint32_t duration_sec;	   // -w: 計測秒数上限（0=無制限）
	enum output_format format; // -o: 出力形式（既定 human）
#ifdef __linux__
	const char *ifname;
	bool phc_requested;
#endif
};

/**
 * 出力形式文字列を enum に解析する。
 * @param arg "human" / "json" / "csv"
 * @param out 解析結果
 * @return 成功時 0、未知の形式なら -1
 */
__attribute__((nonnull(1, 2))) static int
parse_output_format(const char *arg, enum output_format *out)
{
	if (strcmp(arg, "human") == 0) {
		*out = OUTPUT_HUMAN;
	} else if (strcmp(arg, "json") == 0) {
		*out = OUTPUT_JSON;
	} else if (strcmp(arg, "csv") == 0) {
		*out = OUTPUT_CSV;
	} else {
		return -1;
	}
	return 0;
}

/**
 * 単一の getopt オプション文字を処理する。
 * @param opt オプション文字
 * @param opts 設定を格納する構造体
 * @return 継続可なら 0、エラー（呼び出し側で usage 表示）なら 1
 */
__attribute__((nonnull(2), cold)) static int
handle_sender_option(int opt, struct sender_options *opts)
{
	switch (opt) {
	case '4':
		opts->af_hint = AF_INET;
		return 0;
	case '6':
		opts->af_hint = AF_INET6;
		return 0;
	case 'i':
#ifdef __linux__
		opts->ifname = optarg;
#else
		fprintf(stderr,
			"Warning: -i option is only supported on Linux\n");
#endif
		return 0;
	case 'P':
		opts->ptp_mode = true;
		return 0;
	case 'c':
#ifdef __linux__
		opts->phc_requested = true;
#else
		fprintf(stderr,
			"Warning: -c option is only supported on Linux\n");
#endif
		return 0;
	case 'O':
		opts->oneway_mode = true;
		return 0;
	case 'n':
		if (stamp_parse_u32_range(optarg, &opts->count, UINT32_MAX) !=
		    0) {
			fprintf(stderr, "Invalid count: %s\n", optarg);
			return 1;
		}
		return 0;
	case 'w':
		if (stamp_parse_u32_range(optarg,
					  &opts->duration_sec,
					  UINT32_MAX) != 0) {
			fprintf(stderr, "Invalid duration: %s\n", optarg);
			return 1;
		}
		return 0;
	case 'o':
		if (parse_output_format(optarg, &opts->format) != 0) {
			fprintf(stderr, "Invalid output format: %s\n", optarg);
			return 1;
		}
		return 0;
	default:
		return 1;
	}
}

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
	opts->count = 0;
	opts->duration_sec = 0;
	opts->format = OUTPUT_HUMAN;
#ifdef __linux__
	opts->ifname = NULL;
	opts->phc_requested = false;
#endif

	int opt;
	while ((opt = getopt(argc, argv, "46i:PcOn:w:o:")) != -1) {
		if (handle_sender_option(opt, opts) != 0) {
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
	if (g_output_format != OUTPUT_HUMAN) {
		return; // 機械可読モードでは人間向けバナーを抑制
	}
	char addr_port_str[STAMP_ADDR_PORT_BUFSIZE];
	const char *family_str = stamp_family_str(servaddr->ss_family);
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

/**
 * 単調増加クロックのミリ秒値を取得する（-w の経過時間計測用）。
 * 壁時計（time()）と異なり NTP/手動のクロックステップに影響されない。
 * @param out_ms 取得したミリ秒値（非 NULL）
 * @return 成功時 true、取得失敗時 false
 */
__attribute__((nonnull(1))) static bool monotonic_now_ms(uint64_t *out_ms)
{
#ifdef _WIN32
	*out_ms = (uint64_t)GetTickCount64();
	return true;
#else
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return false;
	}
	*out_ms = (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
	return true;
#endif
}

/**
 * 受信タイムアウトを設定する（-w の残り時間に合わせて短縮するため毎回呼ぶ）。
 * 設定失敗は致命としない（既定タイムアウトのまま継続）。SO_RCVTIMEO=0 は
 * 「無制限」を意味するため、呼び出し側は 0 を渡さないこと。
 * @param sockfd 対象ソケット
 * @param sec 秒
 * @param usec マイクロ秒
 */
static void set_recv_timeout(SOCKET sockfd, long sec, long usec)
{
#ifdef _WIN32
	DWORD timeout_ms = (DWORD)(sec * 1000 + usec / 1000);
	(void)setsockopt(sockfd,
			 SOL_SOCKET,
			 SO_RCVTIMEO,
			 (const char *)&timeout_ms,
			 sizeof(timeout_ms));
#else
	(void)stamp_set_socket_timeouts(sockfd, sec, usec, false);
#endif
}

/**
 * -w 締切の処理。経過時間が上限に達していれば true（ループ脱出）を返す。
 * 締切までの残りが既定タイムアウト未満なら recv タイムアウトを残り時間へ短縮し、
 * 応答ロス時に -w を大きく超過するのを防ぐ。単調クロックを用いる。
 * @param sockfd 送信ソケット
 * @param duration_ms 計測上限（ミリ秒）
 * @param start_ms 計測開始時刻（単調クロックのミリ秒値）
 * @return 締切到達で true
 */
static bool sender_deadline_reached(SOCKET sockfd,
				    uint64_t duration_ms,
				    uint64_t start_ms)
{
	uint64_t now_ms;
	if (!monotonic_now_ms(&now_ms)) {
		return false; // 取得失敗時は締切判定をスキップ（次回再試行）
	}
	uint64_t elapsed = now_ms - start_ms;
	if (elapsed >= duration_ms) {
		return true;
	}
	uint64_t remain_ms = duration_ms - elapsed;
	if (remain_ms < (uint64_t)SOCKET_TIMEOUT_SEC * 1000U) {
		// -w は ping -w と同様のハード締切。残り時間で recv を打ち切るため、
		// 締切直前に送った最後の応答が締切後に到着すると 1 本だけ timeout
		// （= loss）として計上されうる（境界効果・計測長が伸びるほど軽微）。
		set_recv_timeout(sockfd,
				 (long)(remain_ms / 1000U),
				 (long)(remain_ms % 1000U) * 1000L);
	}
	return false;
}

/**
 * 測定ループ本体（送信→受信→統計更新）。
 * -n/-w 指定時は所定の本数・秒数で停止し、g_collect_samples を設定する。
 * @param sockfd 送信ソケット
 * @param opts CLI オプション
 * @return 成功時 0、開始時刻取得失敗時 -1
 */
__attribute__((nonnull(2))) static int
run_measurement_loop(SOCKET sockfd, const struct sender_options *opts)
{
	struct stamp_sender_packet tx_packet;
	uint32_t seq = 0;
	uint32_t sent_count = 0;	   // 実送信できた本数（seq は uint32_t ラップのため別管理）
	uint32_t consecutive_failures = 0; // 連続 send 失敗数（成功でリセット）
	uint64_t start_ms = 0;
	uint64_t duration_ms = (uint64_t)opts->duration_sec * 1000U;

	// -n/-w 指定時は有限計測し、終了時にパーセンタイルを算出する
	g_collect_samples = (opts->count != 0 || opts->duration_sec != 0);
	if (opts->duration_sec != 0) {
		if (!monotonic_now_ms(&start_ms)) {
			fprintf(stderr, "Failed to get start time\n");
			return -1;
		}
	}
	// -n 指定時は最終サイズが既知なので一括確保（毎回の成長コピーを回避）
	if (opts->count != 0) {
		stamp_sample_buffer_prereserve(opts->count, opts->oneway_mode);
	}

	uint8_t recv_buffer[STAMP_MAX_PACKET_SIZE];
	while (__atomic_load_n(&g_running, __ATOMIC_SEQ_CST)) {
		// -w 締切判定（ブロッキング受信の前に判定し、recv タイムアウトを
		// 残り時間へ詰める）
		if (opts->duration_sec != 0 &&
		    sender_deadline_reached(sockfd, duration_ms, start_ms)) {
			break;
		}

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
			sent_count++; // 実送信できたパケットのみ -n の対象
			consecutive_failures = 0;
		} else if (++consecutive_failures >=
			   STAMP_MAX_CONSECUTIVE_SEND_FAILURES) {
			// 宛先到達不能等で送信が連続失敗。-w 未指定でも無限ループに
			// ならないよう打ち切る（ここまでの結果は出力する）
			fprintf(stderr,
				"Aborting: %u consecutive send failures "
				"(target unreachable?)\n",
				consecutive_failures);
			break;
		}
		seq++; // uint32_t ラップは意図的（RFC 8762 準拠）
		// -n 到達で停止（スリープ前に脱出）
		if (opts->count != 0 && sent_count >= opts->count) {
			break;
		}
		sleep_with_interrupt_check();
	}
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
	g_output_format = opts.format;
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

	if (run_measurement_loop(sockfd, &opts) != 0) {
		exit_code = 1;
		goto cleanup;
	}

	print_statistics(&servaddr);

cleanup:
	stamp_sample_buffer_free();
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
