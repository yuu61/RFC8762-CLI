// RFC 8762 STAMP - カーネルタイムスタンプ抽出 + HWタイムスタンプ + PHC

#ifndef STAMP_KERNEL_TS_H
#define STAMP_KERNEL_TS_H

#include "stamp_time.h"

// Linux: SO_TIMESTAMPINGフラグ（カーネルタイムスタンプ用）
#ifdef __linux__
#include <poll.h> // poll()
#include <linux/errqueue.h>
#include <linux/ethtool.h> // ETHTOOL_GET_TS_INFO, struct ethtool_ts_info
#include <linux/net_tstamp.h>
#include <linux/sockios.h> // SIOCETHTOOL, SIOCSHWTSTAMP
#include <net/if.h>	   // struct ifreq, IFNAMSIZ
#include <sys/ioctl.h>	   // ioctl()
// SCM_TIMESTAMPING: glibc <sys/socket.h>では未定義の場合がある
#ifndef SCM_TIMESTAMPING
#define SCM_TIMESTAMPING SO_TIMESTAMPING
#endif
#endif

#ifdef _WIN32
/**
 * WSARecvMsg関数ポインタの初期化
 * @param sockfd ソケットディスクリプタ
 * @param wsa_recvmsg 関数ポインタを格納するポインタ
 * @return 成功時true、失敗時false
 */
static inline bool stamp_init_wsa_recvmsg(SOCKET sockfd,
					  LPFN_WSARECVMSG *wsa_recvmsg)
{
	DWORD bytes = 0;
	GUID guid = WSAID_WSARECVMSG;

	if (WSAIoctl(sockfd,
		     SIO_GET_EXTENSION_FUNCTION_POINTER,
		     &guid,
		     sizeof(guid),
		     (void *)wsa_recvmsg,
		     sizeof(*wsa_recvmsg),
		     &bytes,
		     NULL,
		     NULL) == SOCKET_ERROR) {
		*wsa_recvmsg = NULL;
		return false;
	}
	return true;
}

/**
 * Windows: SIO_TIMESTAMPINGでカーネルタイムスタンプを有効化
 * @param sockfd ソケットディスクリプタ
 * @return 成功時true、失敗時false
 *
 * Windows 10 1903以降で利用可能。失敗してもユーザースペースタイムスタンプに
 * フォールバックするため、戻り値のチェックは必須ではない。
 */
static inline bool stamp_enable_kernel_timestamping_windows(SOCKET sockfd)
{
	TIMESTAMPING_CONFIG ts_config = {0};
	ts_config.Flags = TIMESTAMPING_FLAG_RX;
	ts_config.TxTimestampsBuffered = 0;
	DWORD bytes_returned = 0;

	if (WSAIoctl(sockfd,
		     SIO_TIMESTAMPING,
		     &ts_config,
		     sizeof(ts_config),
		     NULL,
		     0,
		     &bytes_returned,
		     NULL,
		     NULL) == 0) {
		fprintf(stderr,
			"Kernel timestamping enabled (SIO_TIMESTAMPING)\n");
		return true;
	}

	fprintf(stderr,
		"Warning: SIO_TIMESTAMPING not available (error %d); "
		"using userspace timestamps\n",
		WSAGetLastError());
	return false;
}

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

/**
 * Windows: 制御メッセージからカーネルタイムスタンプを抽出
 * @param msg WSARecvMsg()で受信したWSAMSG構造体へのポインタ（NULLは未定義動作）
 * @param out_sec 秒部分を格納するポインタ（NULLは未定義動作）
 * @param out_frac 小数部分を格納するポインタ（NULLは未定義動作）
 * @return タイムスタンプが見つかった場合true、そうでない場合false
 *
 * Windows 10 1903以降でSIO_TIMESTAMPINGが有効な場合、
 * SO_TIMESTAMP制御メッセージにFILETIME形式のタイムスタンプが含まれる。
 */
__attribute__((nonnull(1, 2, 3))) static inline bool
stamp_extract_kernel_timestamp_windows(WSAMSG *restrict msg,
				       uint32_t *restrict out_sec,
				       uint32_t *restrict out_frac,
				       bool ptp_mode)
{
	// MinGW WSA_CMSG_NXTHDR マクロの符号変換警告を抑制
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
	for (WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = WSA_CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    (cmsg->cmsg_type == SO_TIMESTAMP ||
		     cmsg->cmsg_type == SO_TIMESTAMP_ID)) {
			size_t header_len =
				WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR));
			if (cmsg->cmsg_len < header_len) {
				continue;
			}
			size_t data_len = cmsg->cmsg_len - header_len;
			if (data_len >= sizeof(UINT64)) {
				UINT64 filetime;
				memcpy(&filetime,
				       WSA_CMSG_DATA(cmsg),
				       sizeof(filetime));
				if (convert_filetime_to_stamp(filetime,
							      out_sec,
							      out_frac,
							      ptp_mode)) {
					return true;
				}
			}
		}
	}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
	return false;
}
#endif // _WIN32

#ifndef _WIN32

/**
 * SO_TIMESTAMPNS / SO_TIMESTAMP の有効化（フォールバック付き）
 * SO_TIMESTAMPNS が利用可能ならナノ秒精度、なければ SO_TIMESTAMP に降格。
 */
static inline void stamp_enable_so_timestamp(SOCKET sockfd)
{
#ifdef SO_TIMESTAMPNS
	int opt = 1;
	(void)setsockopt(sockfd,
			 SOL_SOCKET,
			 SO_TIMESTAMPNS,
			 &opt,
			 sizeof(opt));
#elif defined(SO_TIMESTAMP)
	int opt = 1;
	(void)setsockopt(sockfd,
			 SOL_SOCKET,
			 SO_TIMESTAMP,
			 &opt,
			 sizeof(opt));
#endif
}

#ifdef __linux__
#ifdef SCM_TIMESTAMPING
/**
 * SCM_TIMESTAMPING の3つの timespec から最適なタイムスタンプを選択
 * 優先順位: ts[2] (raw HW) > ts[0] (software) > ts[1] (legacy)
 * @return 選択された timespec へのポインタ、有効なものがない場合 NULL
 */
__attribute__((nonnull)) static inline const struct timespec *
select_best_scm_timestamp(const struct timespec ts[3])
{
	if (ts[2].tv_nsec >= 0 && ts[2].tv_nsec < (long)NSEC_PER_SEC &&
	    (ts[2].tv_sec != 0 || ts[2].tv_nsec != 0)) {
		return &ts[2];
	}
	if (ts[0].tv_nsec >= 0 && ts[0].tv_nsec < (long)NSEC_PER_SEC &&
	    (ts[0].tv_sec != 0 || ts[0].tv_nsec != 0)) {
		return &ts[0];
	}
	if (ts[1].tv_nsec >= 0 && ts[1].tv_nsec < (long)NSEC_PER_SEC &&
	    (ts[1].tv_sec != 0 || ts[1].tv_nsec != 0)) {
		return &ts[1];
	}
	return NULL;
}

/**
 * SCM_TIMESTAMPING 制御メッセージからタイムスタンプを抽出
 * @return 抽出成功時 true
 */
__attribute__((nonnull)) static inline bool extract_scm_timestamping(
	const struct cmsghdr *cmsg,
	uint32_t *out_sec,
	uint32_t *out_frac,
	bool ptp_mode)
{
	size_t required_len = CMSG_LEN(3 * sizeof(struct timespec));
	if ((size_t)cmsg->cmsg_len < required_len) {
		return false;
	}

	struct timespec ts[3];
	memcpy(ts, CMSG_DATA(cmsg), 3 * sizeof(struct timespec));

	const struct timespec *selected = select_best_scm_timestamp(ts);
	if (selected == NULL) {
		return false;
	}

	stamp_timespec_to_stamp(selected, out_sec, out_frac, ptp_mode);
	return true;
}
#endif // SCM_TIMESTAMPING
#endif // __linux__

#ifdef SCM_TIMESTAMPNS
/**
 * SCM_TIMESTAMPNS 制御メッセージからタイムスタンプを抽出
 * @return 抽出成功時 true
 */
__attribute__((nonnull)) static inline bool extract_scm_timestampns(
	const struct cmsghdr *cmsg,
	uint32_t *out_sec,
	uint32_t *out_frac,
	bool ptp_mode)
{
	if ((size_t)cmsg->cmsg_len < CMSG_LEN(sizeof(struct timespec))) {
		return false;
	}
	struct timespec ts;
	memcpy(&ts, CMSG_DATA(cmsg), sizeof(ts));
	if (ts.tv_nsec < 0 || ts.tv_nsec >= (long)NSEC_PER_SEC) {
		return false;
	}
	stamp_timespec_to_stamp(&ts, out_sec, out_frac, ptp_mode);
	return true;
}
#endif

#ifdef SCM_TIMESTAMP
/**
 * SCM_TIMESTAMP 制御メッセージからタイムスタンプを抽出
 * @return 抽出成功時 true
 */
__attribute__((nonnull)) static inline bool extract_scm_timestamp(
	const struct cmsghdr *cmsg,
	uint32_t *out_sec,
	uint32_t *out_frac,
	bool ptp_mode)
{
	if ((size_t)cmsg->cmsg_len < CMSG_LEN(sizeof(struct timeval))) {
		return false;
	}
	struct timeval tv;
	memcpy(&tv, CMSG_DATA(cmsg), sizeof(tv));
	if (tv.tv_usec < 0 || tv.tv_usec >= (long)USEC_PER_SEC) {
		return false;
	}
	if (ptp_mode) {
		struct timespec ts_conv;
		ts_conv.tv_sec = tv.tv_sec;
		ts_conv.tv_nsec = tv.tv_usec * 1000L;
		stamp_timespec_to_ptp(&ts_conv, out_sec, out_frac);
	} else {
		stamp_timeval_to_ntp(&tv, out_sec, out_frac);
	}
	return true;
}
#endif

/**
 * Linux: 制御メッセージからカーネルタイムスタンプを抽出
 * @param msg recvmsg()で受信したmsghdr構造体へのポインタ（NULLは未定義動作）
 * @param out_sec 秒部分を格納するポインタ（NULLは未定義動作）
 * @param out_frac 小数部分を格納するポインタ（NULLは未定義動作）
 * @return タイムスタンプが見つかった場合true、そうでない場合false
 *
 * 優先順位:
 *   1. SCM_TIMESTAMPING (SO_TIMESTAMPING) - 最も高精度
 *   2. SCM_TIMESTAMPNS (SO_TIMESTAMPNS) - ナノ秒精度
 *   3. SCM_TIMESTAMP (SO_TIMESTAMP) - マイクロ秒精度
 */
__attribute__((nonnull(1, 2, 3))) static inline bool
stamp_extract_kernel_timestamp_linux(struct msghdr *restrict msg,
				     uint32_t *restrict out_sec
				     __attribute__((unused)),
				     uint32_t *restrict out_frac
				     __attribute__((unused)),
				     bool ptp_mode __attribute__((unused)))
{
	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
#ifdef __linux__
#ifdef SCM_TIMESTAMPING
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMPING) {
			if (extract_scm_timestamping(cmsg,
						     out_sec,
						     out_frac,
						     ptp_mode)) {
				return true;
			}
			continue;
		}
#endif
#endif
#ifdef SCM_TIMESTAMPNS
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMPNS) {
			if (extract_scm_timestampns(cmsg,
						    out_sec,
						    out_frac,
						    ptp_mode)) {
				return true;
			}
			continue;
		}
#endif
#ifdef SCM_TIMESTAMP
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMP) {
			if (extract_scm_timestamp(cmsg,
						  out_sec,
						  out_frac,
						  ptp_mode)) {
				return true;
			}
			continue;
		}
#endif
	}
	return false;
}

#ifdef __linux__
/**
 * NIC のハードウェアタイムスタンプ能力を格納する構造体
 */
struct stamp_hwts_caps {
	bool rx_hw;    // RX ハードウェアタイムスタンプ対応
	bool tx_hw;    // TX ハードウェアタイムスタンプ対応
	int phc_index; // PHC デバイスインデックス (-1 = なし)
};

/**
 * NIC のハードウェアタイムスタンプ能力を検出
 * @param sockfd ソケットディスクリプタ
 * @param ifname インターフェース名 (NULL の場合はスキップ)
 * @param caps 検出結果を格納する構造体へのポインタ
 * @return 0=成功, -1=エラー
 */
__attribute__((nonnull(3))) static inline int stamp_detect_hwts_caps(
	int sockfd,
	const char *ifname,
	struct stamp_hwts_caps *caps)
{
	struct ethtool_ts_info ts_info;
	struct ifreq ifr;

	caps->rx_hw = false;
	caps->tx_hw = false;
	caps->phc_index = -1;

	if (ifname == NULL) {
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	memset(&ts_info, 0, sizeof(ts_info));
	ts_info.cmd = ETHTOOL_GET_TS_INFO;
	ifr.ifr_data = (char *)&ts_info;

	if (ioctl(sockfd, SIOCETHTOOL, &ifr) < 0) {
		return -1;
	}

	if (ts_info.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE) {
		caps->rx_hw = true;
	}
	if (ts_info.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE) {
		caps->tx_hw = true;
	}
	caps->phc_index = ts_info.phc_index;

	return 0;
}

/**
 * NIC のハードウェアタイムスタンプフィルタを設定
 * @param sockfd ソケットディスクリプタ
 * @param ifname インターフェース名
 * @param enable_tx TX タイムスタンプも有効にするか
 * @return 0=成功, -1=エラー
 */
static inline int stamp_configure_hwtstamp_filter(int sockfd,
						  const char *ifname,
						  bool enable_tx)
{
	struct ifreq ifr;
	struct hwtstamp_config hwconfig;

	if (ifname == NULL) {
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	memset(&hwconfig, 0, sizeof(hwconfig));
	hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;
	hwconfig.tx_type = enable_tx ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;

	ifr.ifr_data = (char *)&hwconfig;

	if (ioctl(sockfd, SIOCSHWTSTAMP, &ifr) < 0) {
		return -1;
	}

	return 0;
}

/**
 * CMSG からTXタイムスタンプを抽出（SCM_TIMESTAMPING: ts[2]>ts[0] 優先）
 * @return 抽出成功時 true
 */
__attribute__((nonnull(1, 2, 3))) static inline bool
extract_tx_timestamp_from_cmsg(struct msghdr *msg,
			       uint32_t *ntp_sec,
			       uint32_t *ntp_frac,
			       bool ptp_mode)
{
	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMPING) {
			size_t required_len =
				CMSG_LEN(3 * sizeof(struct timespec));
			if ((size_t)cmsg->cmsg_len < required_len) {
				continue;
			}
			struct timespec ts[3];
			memcpy(ts,
			       CMSG_DATA(cmsg),
			       3 * sizeof(struct timespec));

			if ((ts[2].tv_sec != 0 || ts[2].tv_nsec != 0) &&
			    ts[2].tv_nsec >= 0 &&
			    ts[2].tv_nsec < (long)NSEC_PER_SEC) {
				stamp_timespec_to_stamp(&ts[2],
							ntp_sec,
							ntp_frac,
							ptp_mode);
				return true;
			}
			if ((ts[0].tv_sec != 0 || ts[0].tv_nsec != 0) &&
			    ts[0].tv_nsec >= 0 &&
			    ts[0].tv_nsec < (long)NSEC_PER_SEC) {
				stamp_timespec_to_stamp(&ts[0],
							ntp_sec,
							ntp_frac,
							ptp_mode);
				return true;
			}
		}
	}
	return false;
}

/**
 * TX ハードウェアタイムスタンプを MSG_ERRQUEUE から取得
 * @param sockfd ソケットディスクリプタ
 * @param ntp_sec NTP秒部分を格納するポインタ
 * @param ntp_frac NTP小数部分を格納するポインタ
 * @return 取得成功時 true、失敗時 false
 */
__attribute__((nonnull(2, 3))) static inline bool
stamp_retrieve_tx_hw_timestamp(int sockfd,
			       uint32_t *ntp_sec,
			       uint32_t *ntp_frac,
			       bool ptp_mode)
{
	char control[STAMP_CMSG_BUFSIZE];
	char data;
	struct msghdr msg;
	struct iovec iov;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &data;
	iov.iov_len = sizeof(data);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	for (int retry = 0; retry < STAMP_TX_TS_MAX_RETRIES; retry++) {
		ssize_t n = recvmsg(sockfd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
		if (n < 0) {
			if (IS_WOULDBLOCK(errno)) {
				struct pollfd pfd = {
					.fd = sockfd,
					.events = POLLERR,
				};
				// poll() の最小タイムアウト 1ms で TX TS の到着を待機
				(void)poll(&pfd, 1, 1);
				msg.msg_controllen = sizeof(control);
				continue;
			}
			return false;
		}

		return extract_tx_timestamp_from_cmsg(&msg,
						      ntp_sec,
						      ntp_frac,
						      ptp_mode);
	}

	return false;
}

// =============================================================================
// PHC (PTP Hardware Clock) 連携
// =============================================================================

// FD_TO_CLOCKID / CLOCKID_TO_FD マクロ
// Linux カーネルの posix-timers で定義される変換マクロ
#ifndef FD_TO_CLOCKID
#define FD_TO_CLOCKID(fd) ((clockid_t)((((unsigned int)~(fd)) << 3) | 3))
#endif
#ifndef CLOCKID_TO_FD
#define CLOCKID_TO_FD(clk) ((unsigned int)~((clk) >> 3))
#endif

/**
 * PHC デバイスを開いて clockid を取得
 * @param phc_index PHC インデックス (ethtool_ts_info.phc_index)
 * @param fd 開いたファイルディスクリプタを格納するポインタ
 * @param clockid clock_gettime 用の clockid を格納するポインタ
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(2, 3))) static inline int
stamp_get_phc_clockid(int phc_index, int *fd, clockid_t *clockid)
{
	// "/dev/ptp" (8文字) + int最大10桁 + NUL = 19文字。32バイトで十分。
	// snprintf の戻り値チェックで切り詰めも検出。
	char phc_path[32];
	int ret = snprintf(phc_path, sizeof(phc_path), "/dev/ptp%d", phc_index);
	if (ret < 0 || (size_t)ret >= sizeof(phc_path)) {
		return -1;
	}

	int phc_fd = open(phc_path, O_RDONLY);
	if (phc_fd < 0) {
		return -1;
	}

	*fd = phc_fd;
	*clockid = FD_TO_CLOCKID(phc_fd);
	return 0;
}

/**
 * PHC クロックからタイムスタンプを取得
 * @param clockid PHC の clockid (FD_TO_CLOCKID で取得)
 * @param sec 秒部分を格納するポインタ（ネットワークバイトオーダー）
 * @param frac
 * 小数部分/ナノ秒部分を格納するポインタ（ネットワークバイトオーダー）
 * @param ptp_mode true=PTP形式, false=NTP形式
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(2, 3))) static inline int stamp_get_phc_timestamp(
	clockid_t clockid,
	uint32_t *sec,
	uint32_t *frac,
	bool ptp_mode)
{
	struct timespec ts;
	if (clock_gettime(clockid, &ts) != 0) {
		return -1;
	}
	stamp_timespec_to_stamp(&ts, sec, frac, ptp_mode);
	return 0;
}

/**
 * PHC クロックを検出・初期化する共通ヘルパー
 * @param sockfd ソケットディスクリプタ
 * @param ifname インターフェース名
 * @param phc_fd PHC ファイルディスクリプタを格納するポインタ
 * @param phc_clockid PHC clockid を格納するポインタ
 * @return 成功時0、失敗時-1
 */
static inline int stamp_init_phc(int sockfd,
				 const char *ifname,
				 int *phc_fd,
				 clockid_t *phc_clockid)
{
	struct stamp_hwts_caps caps;
	if (stamp_detect_hwts_caps(sockfd, ifname, &caps) != 0 ||
	    caps.phc_index < 0) {
		fprintf(stderr,
			"Warning: No PHC available on %s; using system clock\n",
			ifname);
		return -1;
	}
	if (stamp_get_phc_clockid(caps.phc_index, phc_fd, phc_clockid) != 0) {
		fprintf(stderr,
			"Warning: Failed to open /dev/ptp%d; using system "
			"clock\n",
			caps.phc_index);
		return -1;
	}
	fprintf(stderr, "PHC clock enabled: /dev/ptp%d\n", caps.phc_index);
	return 0;
}

#endif // __linux__

#endif // !_WIN32

#endif // STAMP_KERNEL_TS_H
