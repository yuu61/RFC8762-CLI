// RFC 8762 STAMP - アドレスユーティリティ（解決・整形・ポートパース）

#ifndef STAMP_NET_H
#define STAMP_NET_H

#include "stamp_protocol.h"

// アドレス:ポート表示用バッファ長（stamp_protocol.h から移設）
// IPv6 アドレス最大長 + "[]:port" 装飾分の余白
#define STAMP_ADDR_PORT_BUFSIZE (INET6_ADDRSTRLEN + 16)

/**
 * ポート番号のパース
 * @param arg ポート番号文字列
 * @param port パース結果を格納するポインタ
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(1, 2), cold)) static inline int stamp_parse_port(
	const char *restrict arg,
	uint16_t *restrict port)
{
	char *end = NULL;
	unsigned long value;

	if (*arg == '\0') {
		return -1;
	}

	errno = 0;
	value = strtoul(arg, &end, 10);

	if (errno == ERANGE || (end && *end != '\0') || value == 0 ||
	    value > STAMP_MAX_PORT) {
		return -1;
	}

	*port = (uint16_t)value;
	return 0;
}

// =============================================================================
// IPv4/IPv6 デュアルスタック対応ユーティリティ
// =============================================================================

/**
 * sockaddr_storage構造体のサイズを取得
 * @param family アドレスファミリ (AF_INET or AF_INET6)
 * @return 構造体サイズ
 */
__attribute__((const)) static inline socklen_t stamp_get_sockaddr_len(int family)
{
	return (family == AF_INET6) ? (socklen_t)sizeof(struct sockaddr_in6)
				    : (socklen_t)sizeof(struct sockaddr_in);
}

/**
 * sockaddr_storageからポート番号を取得
 * @param addr sockaddr_storage構造体へのポインタ
 * @return ポート番号（ホストバイトオーダー）、エラー時0
 */
static inline uint16_t stamp_sockaddr_get_port(const struct sockaddr_storage *addr)
{
	if (!addr) {
		return 0;
	}
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin =
			(const struct sockaddr_in *)addr;
		return ntohs(sin->sin_port);
	}
	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 =
			(const struct sockaddr_in6 *)addr;
		return ntohs(sin6->sin6_port);
	}
	return 0;
}

/**
 * sockaddr_storageをアドレス文字列に変換
 * @return 成功時buf、エラー時NULL
 */
__attribute__((nonnull(1, 2))) static inline const char *
stamp_sockaddr_to_string(const struct sockaddr_storage *restrict addr,
			 char *restrict buf,
			 size_t buflen)
{
	if (buflen == 0) {
		return NULL;
	}

	socklen_t addrlen = stamp_get_sockaddr_len(addr->ss_family);
#ifdef _WIN32
	// Windows: getnameinfo はバッファサイズに DWORD を要求
	if (getnameinfo((const struct sockaddr *)addr,
			addrlen,
			buf,
			(DWORD)buflen,
			NULL,
			0,
			NI_NUMERICHOST) != 0)
#else
	if (getnameinfo((const struct sockaddr *)addr,
			addrlen,
			buf,
			(socklen_t)buflen,
			NULL,
			0,
			NI_NUMERICHOST) != 0)
#endif
	{
		return NULL;
	}
	return buf;
}

/**
 * sockaddr_storageをアドレス文字列に変換（失敗時は"<unknown>"）
 */
static inline const char *stamp_sockaddr_to_string_safe(
	const struct sockaddr_storage *restrict addr,
	char *restrict buf,
	size_t buflen)
{
	if (!buf || buflen == 0) {
		return "<unknown>";
	}

	if (stamp_sockaddr_to_string(addr, buf, buflen) == NULL) {
		static const char unknown[] = "<unknown>";
		if (buflen >= sizeof(unknown)) {
			memcpy(buf, unknown, sizeof(unknown));
		} else {
			memcpy(buf, unknown, buflen - 1);
			buf[buflen - 1] = '\0';
		}
	}
	return buf;
}

/**
 * アドレス:ポート形式の文字列を生成（IPv6は[addr]:port形式）
 * buflenはSTAMP_ADDR_PORT_BUFSIZE以上を推奨
 */
// snprintf の切り詰めは設計上の意図的動作
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
static inline const char *stamp_format_sockaddr_with_port(
	const struct sockaddr_storage *addr,
	char *buf,
	size_t buflen)
{
	char addr_str[INET6_ADDRSTRLEN];

	if (!buf || buflen == 0) {
		return "";
	}

	if (!addr) {
		return (buf[0] = '\0', buf);
	}

	stamp_sockaddr_to_string_safe(addr, addr_str, sizeof(addr_str));
	uint16_t port = stamp_sockaddr_get_port(addr);

	if (addr->ss_family == AF_INET6) {
		snprintf(buf, buflen, "[%s]:%u", addr_str, port);
	} else {
		snprintf(buf, buflen, "%s:%u", addr_str, port);
	}
	return buf;
}
#pragma GCC diagnostic pop

/**
 * ホスト名/IPアドレスを解決してaddrinfoリストを取得
 * @param out_result 使用後はfreeaddrinfo()で解放が必要
 * @return 成功時0、エラー時-1
 */
static inline int stamp_resolve_address_list(const char *host,
					     uint16_t port,
					     int af_hint,
					     struct addrinfo **out_result)
{
	struct addrinfo hints;
	char port_str[16];
	int ret;

	if (!host || !out_result) {
		return -1;
	}

	// ホスト名の長さ検証（RFC 1035: 最大253文字）
	if (strlen(host) > MAX_HOSTNAME_LEN) {
		return -1;
	}

	snprintf(port_str, sizeof(port_str), "%u", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af_hint;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	// AI_ADDRCONFIG: ローカルシステムで利用可能なアドレスファミリのみ返す
	// IPv6が無効な環境でAAAAレコードを返さない
#ifdef AI_ADDRCONFIG
	hints.ai_flags = AI_ADDRCONFIG;
#endif

	ret = getaddrinfo(host, port_str, &hints, out_result);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

/**
 * ホスト名/IPアドレスを解決してsockaddr_storageに格納
 *
 * 注意: この関数はgetaddrinfo()が返すリストから最初にマッチする
 * IPv4/IPv6アドレスを返します。接続試行によるフォールバック
 * （例: IPv6接続失敗時にIPv4を試す）は実装していません。
 * 接続フォールバックが必要な場合は、stamp_resolve_address_list()を使用し、
 * 呼び出し元で各アドレスへの接続を順に試してください。
 *
 * @param af_hint AF_UNSPEC=自動, AF_INET, AF_INET6
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(1, 4, 5), cold)) static inline int stamp_resolve_address(
	const char *restrict host,
	uint16_t port,
	int af_hint,
	struct sockaddr_storage *restrict out_addr,
	socklen_t *out_addrlen)
{
	struct addrinfo *result;
	const struct addrinfo *rp;

	if (stamp_resolve_address_list(host, port, af_hint, &result) != 0) {
		return -1;
	}

	// 最初にマッチするIPv4/IPv6アドレスを返す（接続試行なし）
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
			memset(out_addr, 0, sizeof(*out_addr));
			memcpy(out_addr, rp->ai_addr, rp->ai_addrlen);
			*out_addrlen = (socklen_t)rp->ai_addrlen;
			freeaddrinfo(result);
			return 0;
		}
	}

	freeaddrinfo(result);
	return -1;
}

#endif // STAMP_NET_H
