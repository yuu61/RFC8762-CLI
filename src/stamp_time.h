// RFC 8762 STAMP - タイムスタンプ取得・変換・計算関数

#ifndef STAMP_TIME_H
#define STAMP_TIME_H

#include "stamp_protocol.h"

// NTP小数部変換マクロ (丸め付き)（stamp_protocol.h から移設）
// ナノ秒からNTP小数部への変換: nsec * 2^32 / 10^9
#define NSEC_TO_NTP_FRAC(nsec)                                               \
	((uint32_t)(((uint64_t)(nsec) * NTP_FRAC_SCALE_INT + 500000000ULL) / \
		    NSEC_PER_SEC))

// マイクロ秒からNTP小数部への変換: usec * 2^32 / 10^6
#define USEC_TO_NTP_FRAC(usec)                                            \
	((uint32_t)(((uint64_t)(usec) * NTP_FRAC_SCALE_INT + 500000ULL) / \
		    USEC_PER_SEC))

#ifdef _WIN32
// Windows epoch から NTP epoch への変換定数（stamp_protocol.h から移設）
#define WINDOWS_TO_NTP_OFFSET 11644473600ULL
#define WINDOWS_TICKS_PER_SEC 10000000ULL
// FILETIME妥当性チェック用閾値: 2000-01-01 00:00:00 UTC
#define WINDOWS_FILETIME_Y2K_THRESHOLD 125911584000000000ULL

// Windows 100ナノ秒単位からNTP小数部への変換
#define WINDOWS_100NS_TO_NTP_FRAC(ticks)            \
	((uint32_t)((((uint64_t)(ticks) << 32) +    \
		     (WINDOWS_TICKS_PER_SEC / 2)) / \
		    WINDOWS_TICKS_PER_SEC))
#endif

/**
 * NTPタイムスタンプを取得 (RFC 5905)
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param frac 小数部分（ネットワークバイトオーダー）
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(1, 2))) static inline int stamp_get_ntp_timestamp(
	uint32_t *sec,
	uint32_t *frac)
{
#ifdef _WIN32
	FILETIME ft;
	ULARGE_INTEGER ui;
	GetSystemTimeAsFileTime(&ft);
	// cppcheck-suppress unreadVariable
	ui.LowPart = ft.dwLowDateTime;
	// cppcheck-suppress unreadVariable
	ui.HighPart = ft.dwHighDateTime;

	// Windows epoch: 1601-01-01, NTP epoch: 1900-01-01
	uint64_t unix_time = (ui.QuadPart / WINDOWS_TICKS_PER_SEC) -
			     WINDOWS_TO_NTP_OFFSET;
	uint64_t frac_100ns = ui.QuadPart % WINDOWS_TICKS_PER_SEC;

	*sec = htonl((uint32_t)(unix_time + NTP_OFFSET));
	*frac = htonl(WINDOWS_100NS_TO_NTP_FRAC(frac_100ns));
#else
#if defined(CLOCK_REALTIME)
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
		return -1;
	}
	// NTP Era 0 は 2036-02-07 に終了。uint32_t キャストにより
	// Era 0 の範囲 (1900–2036) 内で正しく動作する。
	*sec = htonl((uint32_t)((unsigned long)ts.tv_sec + NTP_OFFSET));
	*frac = htonl(NSEC_TO_NTP_FRAC(ts.tv_nsec));
#else
	// gettimeofday フォールバック
	struct timeval tv;
	if (gettimeofday(&tv, NULL) != 0) {
		return -1;
	}
	*sec = htonl((uint32_t)(tv.tv_sec + NTP_OFFSET));
	*frac = htonl(USEC_TO_NTP_FRAC(tv.tv_usec));
#endif
#endif

	return 0;
}

/**
 * NTPタイムスタンプをdouble型のUNIX時刻に変換
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param frac 小数部分（ネットワークバイトオーダー）
 * @return UNIX時刻（秒）
 */
__attribute__((pure)) static inline double stamp_ntp_to_double(uint32_t sec,
							       uint32_t frac)
{
	uint32_t s = ntohl(sec);
	uint32_t f = ntohl(frac);
	return (double)(s - NTP_OFFSET) + ((double)f / NTP_FRAC_SCALE);
}

/**
 * PTPタイムスタンプをdouble型のUNIX時刻に変換
 * PTP truncated format: 32-bit sec + 32-bit nanoseconds (0-999999999)
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param nsec ナノ秒部分（ネットワークバイトオーダー）
 * @return UNIX時刻（秒）
 */
__attribute__((pure)) static inline double stamp_ptp_to_double(uint32_t sec,
							       uint32_t nsec)
{
	uint32_t s = ntohl(sec);
	uint32_t n = ntohl(nsec);
	return (double)(s - NTP_OFFSET) + ((double)n / NSEC_PER_SEC_D);
}

/**
 * NTP小数部をナノ秒に変換
 * @param ntp_frac NTP小数部（ホストバイトオーダー）
 * @return ナノ秒
 */
__attribute__((const)) static inline uint32_t stamp_ntp_frac_to_nsec(uint32_t ntp_frac)
{
	return (uint32_t)(((uint64_t)ntp_frac * NSEC_PER_SEC + (1ULL << 31)) >>
			  32);
}

/**
 * ナノ秒をNTP小数部に変換
 * @param nsec ナノ秒
 * @return NTP小数部（ホストバイトオーダー）
 */
__attribute__((const)) static inline uint32_t stamp_nsec_to_ntp_frac(uint64_t nsec)
{
	uint64_t product;
	if (__builtin_mul_overflow(nsec, NTP_FRAC_SCALE_INT, &product)) {
		// nsec が想定範囲外（>= 2^32）の場合、最大値にクランプ
		nsec = NSEC_PER_SEC - 1;
		product = nsec * NTP_FRAC_SCALE_INT;
	}
	return (uint32_t)((product + 500000000ULL) / NSEC_PER_SEC);
}

/**
 * Error Estimate の Z-bit を判定して適切な変換関数にディスパッチ
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param frac 小数部分/ナノ秒部分（ネットワークバイトオーダー）
 * @param error_estimate Error Estimate フィールド（ホストバイトオーダー）
 * @return UNIX時刻（秒）
 */
__attribute__((pure)) static inline double
stamp_timestamp_to_double(uint32_t sec, uint32_t frac, uint16_t error_estimate)
{
	if (error_estimate & ERROR_ESTIMATE_Z_BIT) {
		return stamp_ptp_to_double(sec, frac);
	}
	return stamp_ntp_to_double(sec, frac);
}

/**
 * PTPタイムスタンプを取得 (CLOCK_REALTIME → PTP truncated format)
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param nsec ナノ秒部分（ネットワークバイトオーダー）
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(1, 2))) static inline int stamp_get_ptp_timestamp(
	uint32_t *sec,
	uint32_t *nsec)
{
#ifdef _WIN32
	FILETIME ft;
	ULARGE_INTEGER ui;
	GetSystemTimeAsFileTime(&ft);
	// cppcheck-suppress unreadVariable
	ui.LowPart = ft.dwLowDateTime;
	// cppcheck-suppress unreadVariable
	ui.HighPart = ft.dwHighDateTime;

	uint64_t unix_time = (ui.QuadPart / WINDOWS_TICKS_PER_SEC) -
			     WINDOWS_TO_NTP_OFFSET;
	uint64_t frac_100ns = ui.QuadPart % WINDOWS_TICKS_PER_SEC;
	_Static_assert((WINDOWS_TICKS_PER_SEC - 1) * 100ULL <= UINT32_MAX,
		       "Windows tick to nsec conversion overflows uint32_t");
	uint32_t ns = (uint32_t)(frac_100ns * 100ULL);

	*sec = htonl((uint32_t)(unix_time + NTP_OFFSET));
	*nsec = htonl(ns <= PTP_NSEC_MAX ? ns : PTP_NSEC_MAX);
#else
#if defined(CLOCK_REALTIME)
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
		return -1;
	}
	*sec = htonl((uint32_t)((unsigned long)ts.tv_sec + NTP_OFFSET));
	*nsec = htonl((uint32_t)ts.tv_nsec);
#else
	struct timeval tv;
	if (gettimeofday(&tv, NULL) != 0) {
		return -1;
	}
	*sec = htonl((uint32_t)(tv.tv_sec + NTP_OFFSET));
	*nsec = htonl((uint32_t)(tv.tv_usec * 1000));
#endif
#endif
	return 0;
}

/**
 * PTP/NTP タイムスタンプ取得ディスパッチャ
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param frac 小数部分（ネットワークバイトオーダー）
 * @param ptp_mode true=PTP形式, false=NTP形式
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(1, 2))) static inline int
stamp_get_timestamp(uint32_t *sec, uint32_t *frac, bool ptp_mode)
{
	if (ptp_mode) {
		return stamp_get_ptp_timestamp(sec, frac);
	}
	return stamp_get_ntp_timestamp(sec, frac);
}

#ifdef _WIN32
/**
 * FILETIME値をSTAMPタイムスタンプ（NTP/PTP形式）に変換
 * @param filetime Windows FILETIME値（1601-01-01からの100ナノ秒単位）
 * @param out_sec 秒部分を格納するポインタ（ネットワークバイトオーダー）
 * @param out_frac 小数部分を格納するポインタ（ネットワークバイトオーダー）
 * @param ptp_mode true=PTP形式, false=NTP形式
 * @return 変換成功時true、FILETIME値が不正な場合false
 */
static inline bool convert_filetime_to_stamp(UINT64 filetime,
					     uint32_t *out_sec,
					     uint32_t *out_frac,
					     bool ptp_mode)
{
	if (filetime < WINDOWS_FILETIME_Y2K_THRESHOLD) {
		return false;
	}

	uint64_t unix_time = (filetime / WINDOWS_TICKS_PER_SEC) -
			     WINDOWS_TO_NTP_OFFSET;
	uint64_t frac_100ns = filetime % WINDOWS_TICKS_PER_SEC;

	*out_sec = htonl((uint32_t)(unix_time + NTP_OFFSET));
	if (ptp_mode) {
		uint32_t ns = (uint32_t)(frac_100ns * 100ULL);
		*out_frac = htonl(ns <= PTP_NSEC_MAX ? ns : PTP_NSEC_MAX);
	} else {
		*out_frac = htonl(WINDOWS_100NS_TO_NTP_FRAC(frac_100ns));
	}
	return true;
}
#endif // _WIN32

#ifndef _WIN32
/**
 * timespec から PTP truncated format に変換
 * @param ts timespec構造体へのポインタ
 * @param sec PTP秒部分を格納するポインタ（ネットワークバイトオーダー）
 * @param nsec PTPナノ秒部分を格納するポインタ（ネットワークバイトオーダー）
 */
static inline void stamp_timespec_to_ptp(const struct timespec *ts,
					 uint32_t *sec,
					 uint32_t *nsec)
{
	*sec = htonl((uint32_t)((unsigned long)ts->tv_sec + NTP_OFFSET));
	*nsec = htonl((uint32_t)ts->tv_nsec);
}

/**
 * カーネルタイムスタンプからNTPタイムスタンプへの変換（timespec版）
 * @param ts timespec構造体へのポインタ
 * @param ntp_sec NTP秒部分を格納するポインタ
 * @param ntp_frac NTP小数部分を格納するポインタ
 */
static inline void stamp_timespec_to_ntp(const struct timespec *ts,
					 uint32_t *ntp_sec,
					 uint32_t *ntp_frac)
{
	*ntp_sec = htonl((uint32_t)((unsigned long)ts->tv_sec + NTP_OFFSET));
	*ntp_frac = htonl(NSEC_TO_NTP_FRAC(ts->tv_nsec));
}

/**
 * カーネルタイムスタンプからNTPタイムスタンプへの変換（timeval版）
 * @param tv timeval構造体へのポインタ
 * @param ntp_sec NTP秒部分を格納するポインタ
 * @param ntp_frac NTP小数部分を格納するポインタ
 */
static inline void stamp_timeval_to_ntp(const struct timeval *tv,
					uint32_t *ntp_sec,
					uint32_t *ntp_frac)
{
	*ntp_sec = htonl((uint32_t)((unsigned long)tv->tv_sec + NTP_OFFSET));
	*ntp_frac = htonl(USEC_TO_NTP_FRAC(tv->tv_usec));
}

/**
 * timespec から PTP/NTP ディスパッチャ
 * @param ts timespec構造体へのポインタ
 * @param sec 秒部分を格納するポインタ（ネットワークバイトオーダー）
 * @param frac
 * 小数部分/ナノ秒部分を格納するポインタ（ネットワークバイトオーダー）
 * @param ptp_mode true=PTP形式, false=NTP形式
 */
static inline void stamp_timespec_to_stamp(const struct timespec *ts,
					   uint32_t *sec,
					   uint32_t *frac,
					   bool ptp_mode)
{
	if (ptp_mode) {
		stamp_timespec_to_ptp(ts, sec, frac);
	} else {
		stamp_timespec_to_ntp(ts, sec, frac);
	}
}
#endif

// =============================================================================
// STAMP 計算関数（sender.c のインライン計算を共有化）
// =============================================================================

/**
 * 往路遅延を計算 (ミリ秒)
 * @param t1 送信タイムスタンプ (UNIX秒)
 * @param t2 反射器受信タイムスタンプ (UNIX秒)
 * @return 往路遅延 (ミリ秒)
 */
__attribute__((const)) static inline double stamp_forward_delay(double t1,
								double t2)
{
	return (t2 - t1) * MSEC_PER_SEC;
}

/**
 * 復路遅延を計算 (ミリ秒)
 * @param t3 反射器送信タイムスタンプ (UNIX秒)
 * @param t4 受信タイムスタンプ (UNIX秒)
 * @return 復路遅延 (ミリ秒)
 */
__attribute__((const)) static inline double stamp_backward_delay(double t3,
								 double t4)
{
	return (t4 - t3) * MSEC_PER_SEC;
}

/**
 * RTT (往復遅延) を計算 (ミリ秒)
 * @param forward_delay 往路遅延 (ミリ秒)
 * @param backward_delay 復路遅延 (ミリ秒)
 * @return RTT (ミリ秒)
 */
__attribute__((const)) static inline double stamp_rtt(double forward_delay,
						      double backward_delay)
{
	return forward_delay + backward_delay;
}

/**
 * クロックオフセットを計算 (ミリ秒)
 * @param t1 送信タイムスタンプ (UNIX秒)
 * @param t2 反射器受信タイムスタンプ (UNIX秒)
 * @param t3 反射器送信タイムスタンプ (UNIX秒)
 * @param t4 受信タイムスタンプ (UNIX秒)
 * @return クロックオフセット (ミリ秒)
 */
__attribute__((const)) static inline double stamp_clock_offset(double t1,
							       double t2,
							       double t3,
							       double t4)
{
	return ((t2 - t1) + (t3 - t4)) * 0.5 * MSEC_PER_SEC;
}

/**
 * パケットロス率を計算 (パーセント)
 * @param sent 送信パケット数
 * @param received 受信パケット数
 * @return パケットロス率 (%)
 */
__attribute__((const)) static inline double stamp_packet_loss(uint32_t sent,
							      uint32_t received)
{
	if (sent == 0) {
		return 0.0;
	}
	return 100.0 * (double)(sent - received) / (double)sent;
}

// =============================================================================
// Welford オンライン分散アルゴリズム（数値安定な平均・標準偏差・最小・最大）
// =============================================================================

/**
 * Welford のオンラインアルゴリズム用アキュムレータ。
 *
 * 平均・分散（標本標準偏差 n-1）・最小・最大を単一パス・O(1) メモリで
 * 数値安定に逐次計算する。旧 stamp_jitter の (sum_sq/count)-avg^2 方式は、
 * 平均 ≫ 標準偏差（網羅遅延 mean=100ms, std=0.001ms 等）の典型ケースで
 * 桁落ち（catastrophic cancellation）を起こすため、本方式で根治する。
 *
 * count==0 を未初期化マーカーとして扱い、最初のサンプルで min/max を確定する。
 * これにより負値（クロックオフセット等）でも正しく min/max を捕捉できる。
 */
struct stamp_welford {
	uint64_t count;
	double mean;
	double m2; // 平均からの偏差二乗和（分散 × (n-1)）
	double min;
	double max;
};

/**
 * Welford アキュムレータを初期化（全フィールド 0 クリア）
 * @param w アキュムレータ
 */
__attribute__((nonnull(1))) static inline void
stamp_welford_init(struct stamp_welford *w)
{
	w->count = 0;
	w->mean = 0.0;
	w->m2 = 0.0;
	w->min = 0.0;
	w->max = 0.0;
}

/**
 * Welford アキュムレータにサンプル x を追加
 * @param w アキュムレータ
 * @param x サンプル値
 */
__attribute__((nonnull(1))) static inline void
stamp_welford_update(struct stamp_welford *w, double x)
{
	w->count++;
	double delta = x - w->mean;
	w->mean += delta / (double)w->count;
	double delta2 = x - w->mean;
	w->m2 += delta * delta2;
	if (w->count == 1) {
		w->min = x;
		w->max = x;
	} else {
		if (x < w->min) {
			w->min = x;
		}
		if (x > w->max) {
			w->max = x;
		}
	}
}

/**
 * 平均を取得（サンプルなしの場合 0.0）
 * @param w アキュムレータ
 * @return 平均値
 */
__attribute__((pure, nonnull(1))) static inline double
stamp_welford_mean(const struct stamp_welford *w)
{
	return w->count == 0 ? 0.0 : w->mean;
}

/**
 * 標本標準偏差 (n-1) を取得
 * @param w アキュムレータ
 * @return 標本標準偏差。サンプル数 < 2 の場合 0.0
 */
__attribute__((pure, nonnull(1))) static inline double
stamp_welford_stddev(const struct stamp_welford *w)
{
	if (w->count < 2) {
		return 0.0;
	}
	double var = w->m2 / (double)(w->count - 1);
	return var > 0.0 ? sqrt(var) : 0.0;
}

/**
 * 最小値を取得（サンプルなしの場合 0.0）
 * @param w アキュムレータ
 * @return 最小値
 */
__attribute__((pure, nonnull(1))) static inline double
stamp_welford_min(const struct stamp_welford *w)
{
	return w->count == 0 ? 0.0 : w->min;
}

/**
 * 最大値を取得（サンプルなしの場合 0.0）
 * @param w アキュムレータ
 * @return 最大値
 */
__attribute__((pure, nonnull(1))) static inline double
stamp_welford_max(const struct stamp_welford *w)
{
	return w->count == 0 ? 0.0 : w->max;
}

/**
 * サンプル数を取得
 * @param w アキュムレータ
 * @return サンプル数
 */
__attribute__((pure, nonnull(1))) static inline uint64_t
stamp_welford_count(const struct stamp_welford *w)
{
	return w->count;
}

// =============================================================================
// パーセンタイル計算（全サンプル保持 → qsort → nearest-rank）
// =============================================================================

/**
 * qsort 用の double 比較関数。
 * NaN を末尾に寄せて全順序の破壊（qsort の未定義動作）を防ぐ。
 * @param a 比較対象 1 へのポインタ
 * @param b 比較対象 2 へのポインタ
 * @return a<b で負、a>b で正、等価で 0。NaN は他のあらゆる値より大きい扱い
 */
static inline int stamp_double_cmp(const void *a, const void *b)
{
	double x = *(const double *)a;
	double y = *(const double *)b;
	int nx = isnan(x) ? 1 : 0;
	int ny = isnan(y) ? 1 : 0;
	if (nx || ny) {
		return nx - ny; // NaN を末尾へ（NaN==NaN は 0）
	}
	return (x > y) - (x < y);
}

/**
 * 昇順ソート済み配列に対する nearest-rank パーセンタイル (RFC 7679 EDF)。
 * @param sorted 昇順ソート済み配列（非 NULL）
 * @param n 要素数
 * @param p パーセンタイル (0.0..100.0)
 * @return p パーセンタイル値。n==0 の場合 NAN。p=50 で中央値を兼ねる
 */
__attribute__((pure, nonnull(1))) static inline double
stamp_percentile_sorted(const double *sorted, size_t n, double p)
{
	if (n == 0) {
		return NAN;
	}
	if (n == 1) {
		return sorted[0];
	}
	// nearest-rank: rank = ceil(p/100 * n)、0 始まり添字に変換
	double rank = ceil(p / 100.0 * (double)n);
	size_t idx = rank <= 1.0 ? 0 : (size_t)rank - 1;
	if (idx >= n) {
		idx = n - 1;
	}
	return sorted[idx];
}

// =============================================================================
// 遅延変動（ジッタ）: IPDV (RFC 3393) / PDV (RFC 5481)
// =============================================================================

/**
 * 2 つの seq 番号が連続するか判定する（IPDV の隣接性判定）。
 * uint32_t のラップアラウンド（RFC 8762 準拠）を考慮する。
 * @param prev 直前パケットの seq
 * @param cur 今回パケットの seq
 * @return prev の次が cur なら true
 */
__attribute__((const)) static inline bool
stamp_seq_is_consecutive(uint32_t prev, uint32_t cur)
{
	return (uint32_t)(prev + 1) == cur;
}

/**
 * RFC 5481 PDV (Packet Delay Variation) = 高分位 − 最小。既定で p95 − min。
 * 最小値を基準とするため常に非負（IPDV と異なり符号を持たない）。
 * @param sorted 昇順ソート済み配列（非 NULL）
 * @param n 要素数
 * @return PDV。n==0 の場合 NAN
 */
__attribute__((pure, nonnull(1))) static inline double
stamp_pdv_from_sorted(const double *sorted, size_t n)
{
	if (n == 0) {
		return NAN;
	}
	return stamp_percentile_sorted(sorted, n, 95.0) - sorted[0];
}

#endif // STAMP_TIME_H
