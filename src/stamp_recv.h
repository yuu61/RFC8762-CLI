// RFC 8762 STAMP - タイムスタンプ付きパケット受信 plumbing
// Sender / Reflector 共通の受信処理を集約する。
// カーネル/HW タイムスタンプ抽出・受信 TTL/Hop Limit 抽出・プラットフォーム別
// 受信パス（Linux recvmsg / Windows WSARecvMsg / recvfrom フォールバック）を
// 1 か所に統一し、双方が stamp_recv_with_timestamp() を呼び出す。
// タイムスタンプ形式はグローバル g_ptp_mode（stamp_time.h で extern 宣言）を参照する。

#ifndef STAMP_RECV_H
#define STAMP_RECV_H

#include "stamp_kernel_ts.h" // stamp_extract_kernel_timestamp_*
#include "stamp_protocol.h"  // STAMP_CMSG_BUFSIZE, IP_TTL_MAX
#include "stamp_time.h"	     // stamp_get_timestamp, g_ptp_mode

#ifdef _WIN32
/**
 * Windows: WSAMSG から TTL/Hop Limit を抽出
 */
static inline void stamp_extract_ttl_from_wsamsg(WSAMSG *msg, uint8_t *ttl)
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
			memcpy(&recv_ttl, WSA_CMSG_DATA(cmsg), sizeof(recv_ttl));
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
			memcpy(&recv_hop, WSA_CMSG_DATA(cmsg), sizeof(recv_hop));
			if (recv_hop >= 0 && recv_hop <= IP_TTL_MAX) {
				*ttl = (uint8_t)recv_hop;
			}
		}
#endif
	}
}

/**
 * Windows: WSARecvMsg によるタイムスタンプ付き受信
 * @param ttl     NULL なら TTL 抽出をスキップ
 * @param ts_sec/ts_frac NULL ならカーネルタイムスタンプ抽出をスキップ
 */
__attribute__((hot)) static inline int
stamp_recv_with_timestamp_wsa(SOCKET sockfd,
			      uint8_t *buffer,
			      size_t buffer_len,
			      struct sockaddr_storage *addr,
			      socklen_t *len,
			      uint8_t *ttl,
			      uint32_t *ts_sec,
			      uint32_t *ts_frac)
{
	WSABUF data_buf;
	WSAMSG msg;
	char control[STAMP_CMSG_BUFSIZE];
	DWORD bytes = 0;

	data_buf.buf = (CHAR *)buffer;
	data_buf.len = (ULONG)buffer_len;
	memset(&msg, 0, sizeof(msg));
	msg.name = (LPSOCKADDR)addr;
	msg.namelen = *len;
	msg.lpBuffers = &data_buf;
	msg.dwBufferCount = 1;
	msg.Control.buf = control;
	msg.Control.len = sizeof(control);

	if (g_wsa_recvmsg(sockfd, &msg, &bytes, NULL, NULL) == SOCKET_ERROR) {
		return -1;
	}

	*len = msg.namelen;

	if (ts_sec && ts_frac) {
		if (!stamp_extract_kernel_timestamp_windows(&msg,
							    ts_sec,
							    ts_frac,
							    g_ptp_mode)) {
			if (unlikely(stamp_get_timestamp(ts_sec,
							 ts_frac,
							 g_ptp_mode) != 0)) {
				fprintf(stderr,
					"Warning: Failed to get fallback "
					"receive timestamp\n");
				return -1;
			}
		}
	}

	if (ttl) {
		stamp_extract_ttl_from_wsamsg(&msg, ttl);
	}

	return (int)bytes;
}

/**
 * Windows: recvfrom フォールバック受信（WSARecvMsg 未使用時）
 * recvfrom では制御メッセージを得られないため TTL は抽出できず、
 * 呼び出し元（ディスパッチャ）が事前に 0 初期化した値がそのまま残る。
 * したがって ttl は引数に取らない。
 */
__attribute__((hot)) static inline int
stamp_recv_with_timestamp_fallback(SOCKET sockfd,
				   uint8_t *buffer,
				   size_t buffer_len,
				   struct sockaddr_storage *addr,
				   socklen_t *len,
				   uint32_t *ts_sec,
				   uint32_t *ts_frac)
{
	int n = recvfrom(sockfd,
			 (char *)buffer,
			 (int)buffer_len,
			 0,
			 (struct sockaddr *)addr,
			 len);
	if (n > 0 && ts_sec && ts_frac) {
		if (unlikely(stamp_get_timestamp(ts_sec, ts_frac, g_ptp_mode) !=
			     0)) {
			fprintf(stderr,
				"Warning: Failed to get fallback receive "
				"timestamp\n");
			return -1;
		}
	}
	return n;
}
#else
/**
 * Linux: cmsg から TTL/Hop Limit を抽出
 */
__attribute__((hot)) static inline void
stamp_extract_ttl_from_cmsg(struct msghdr *msg, uint8_t *ttl)
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

/**
 * Unix: recvmsg によるタイムスタンプ付き受信
 * @param ttl     NULL なら TTL 抽出をスキップ
 * @param ts_sec/ts_frac NULL ならカーネルタイムスタンプ抽出をスキップ
 */
__attribute__((hot)) static inline int
stamp_recv_with_timestamp_unix(SOCKET sockfd,
			       uint8_t *buffer,
			       size_t buffer_len,
			       struct sockaddr_storage *addr,
			       socklen_t *len,
			       uint8_t *ttl,
			       uint32_t *ts_sec,
			       uint32_t *ts_frac)
{
	struct msghdr msg;
	struct iovec iov;
	char control[STAMP_CMSG_BUFSIZE];

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buffer;
	iov.iov_len = buffer_len;
	msg.msg_name = addr;
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

	if (ts_sec && ts_frac) {
		if (!stamp_extract_kernel_timestamp_linux(&msg,
							  ts_sec,
							  ts_frac,
							  g_ptp_mode)) {
			if (unlikely(stamp_get_timestamp(ts_sec,
							 ts_frac,
							 g_ptp_mode) != 0)) {
				fprintf(stderr,
					"Warning: Failed to get fallback "
					"receive timestamp\n");
				return -1;
			}
		}
	}

	if (ttl) {
		stamp_extract_ttl_from_cmsg(&msg, ttl);
	}

	return (int)n;
}
#endif

/**
 * カーネル/HW タイムスタンプ付きでパケットを受信（プラットフォーム自動選択）
 *
 * @param ttl     受信 TTL/Hop Limit の格納先。NULL なら抽出しない（Sender 用）。
 * @param ts_sec/ts_frac 受信タイムスタンプの格納先（NTP/PTP 形式）。
 * @return 受信バイト数、エラー時 -1
 */
__attribute__((hot)) static inline int
stamp_recv_with_timestamp(SOCKET sockfd,
			  uint8_t *buffer,
			  size_t buffer_len,
			  struct sockaddr_storage *addr,
			  socklen_t *len,
			  uint8_t *ttl,
			  uint32_t *ts_sec,
			  uint32_t *ts_frac)
{
	// TTL 抽出ヘルパーは有効な cmsg を見つけたときのみ上書きするため、
	// 受信前にここで一度だけ既定値 0 に初期化する（全プラットフォーム共通）。
	if (ttl) {
		*ttl = 0;
	}

#ifdef _WIN32
	if (g_wsa_recvmsg == NULL) {
		return stamp_recv_with_timestamp_fallback(sockfd,
							  buffer,
							  buffer_len,
							  addr,
							  len,
							  ts_sec,
							  ts_frac);
	}
	return stamp_recv_with_timestamp_wsa(sockfd,
					     buffer,
					     buffer_len,
					     addr,
					     len,
					     ttl,
					     ts_sec,
					     ts_frac);
#else
	return stamp_recv_with_timestamp_unix(sockfd,
					      buffer,
					      buffer_len,
					      addr,
					      len,
					      ttl,
					      ts_sec,
					      ts_frac);
#endif
}

#endif // STAMP_RECV_H
