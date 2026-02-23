// RFC 8762 STAMP - タイムスタンプ取得・変換・計算関数

#ifndef STAMP_TIME_H
#define STAMP_TIME_H

#include "stamp_protocol.h"

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
	if (__builtin_mul_overflow(nsec, 4294967296ULL, &product)) {
		// nsec が想定範囲外（>= 2^32）の場合、最大値にクランプ
		nsec = NSEC_PER_SEC - 1;
		product = nsec * 4294967296ULL;
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

/**
 * ジッター (標準偏差) を計算
 * @param sum 値の合計
 * @param sum_sq 値の二乗和
 * @param count サンプル数
 * @return ジッター (標準偏差)
 */
__attribute__((const)) static inline double stamp_jitter(double sum,
							 double sum_sq,
							 uint32_t count)
{
	if (count == 0) {
		return 0.0;
	}
	double avg = sum / count;
	double var = (sum_sq / count) - (avg * avg);
	return var > 0 ? sqrt(var) : 0.0;
}

/**
 * Error Estimate フィールドの multiplier 妥当性チェック
 * RFC 4656 Section 4.1.2: Multiplier MUST NOT be zero
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @return 妥当な場合1、不正な場合0
 */
static inline int validate_error_estimate_multiplier(const void *packet, int size)
{
	// Error Estimate は offset 12-13 にあるため、最低14バイト必要
	if (size < 14 || size > STAMP_MAX_PACKET_SIZE) {
		return 0;
	}
	const uint8_t *p = (const uint8_t *)packet;
	uint16_t ee = (uint16_t)((uint16_t)p[12] << 8 | p[13]);
	return (ee & ERROR_ESTIMATE_MULT_MASK) != 0 ? 1 : 0;
}

/**
 * Reflector受信前のSTAMP/TWAMP-Testペイロード妥当性チェック
 * 14-43バイトのTWAMP Light相互運用ペイロードも許容する。
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @return 妥当な場合1、不正な場合0
 */
static inline int
validate_stamp_test_payload_for_reflector(const void *packet, int size)
{
	return validate_error_estimate_multiplier(packet, size);
}

enum stamp_reflector_input_check_result {
	STAMP_REFLECTOR_INPUT_OK = 0,
	STAMP_REFLECTOR_INPUT_INVALID_PAYLOAD = 1,
	STAMP_REFLECTOR_INPUT_MISSING_TTL = 2,
};

/**
 * Reflector受信パケットの前段チェック（ペイロード妥当性 + TTL/HopLimit取得有無）
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @param sender_ttl 受信時TTL/HopLimit (0は未取得扱い)
 * @return enum stamp_reflector_input_check_result
 */
static inline enum stamp_reflector_input_check_result
stamp_check_reflector_input(const void *packet, int size, uint8_t sender_ttl)
{
	if (!validate_stamp_test_payload_for_reflector(packet, size)) {
		return STAMP_REFLECTOR_INPUT_INVALID_PAYLOAD;
	}
	if (sender_ttl == 0) {
		return STAMP_REFLECTOR_INPUT_MISSING_TTL;
	}
	return STAMP_REFLECTOR_INPUT_OK;
}

/**
 * STAMP反射パケットの妥当性チェック（サイズ + Error Estimate検証）
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @return 妥当な場合1、不正な場合0
 */
static inline int validate_stamp_packet(const void *packet, int size)
{
	if (size < STAMP_BASE_PACKET_SIZE) {
		return 0;
	}
	return validate_error_estimate_multiplier(packet, size);
}

#endif // STAMP_TIME_H
