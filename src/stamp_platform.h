// RFC 8762 STAMP - プラットフォーム抽象化 + getopt
// Windows/Linux クロスプラットフォーム対応

#ifndef STAMP_PLATFORM_H
#define STAMP_PLATFORM_H

// MSVC IntelliSense互換: GCC/Clang固有の__attribute__とPOSIX型を補完
#ifdef __INTELLISENSE__
#define __attribute__(x)
typedef long long ssize_t;
#endif

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// プラットフォーム固有のヘッダーとライブラリ
#ifdef _WIN32
// Windows環境: ヘッダー順序に依存関係あり (winsock2 → mswsock → windows)
// clang-format off
#define WIN32_LEAN_AND_MEAN
#include <signal.h>
#include <winsock2.h>
#include <ws2def.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
#define SOCKET_ERROR_CHECK(x) ((x) == INVALID_SOCKET)
#define CLOSE_SOCKET(x)	      closesocket(x)
#define SOCKET_ERRNO	      WSAGetLastError()
#else
// UNIX/Linux環境
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
typedef int SOCKET;
#define INVALID_SOCKET	      (-1)
#define SOCKET_ERROR_CHECK(x) ((x) < 0)
#define CLOSE_SOCKET(x)	      close(x)
#define SOCKET_ERRNO	      errno
#endif

// アドレス長のキャスト（connect/bind等のソケット関数用）
// Windows: int を期待、POSIX: socklen_t を期待
#ifdef _WIN32
#define ADDRLEN_CAST(x) ((int)(x))
#else
#define ADDRLEN_CAST(x) (x)
#endif

// POSIX では EAGAIN == EWOULDBLOCK が許容される（Linuxでは同値）
// -Wlogical-op 対策として単一比較に縮退させるマクロ
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN == EWOULDBLOCK)
#define IS_WOULDBLOCK(e) ((e) == EAGAIN)
#else
#define IS_WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#endif

// 分岐予測ヒント（GNU拡張、非対応コンパイラではno-op）
#if defined(__GNUC__) || defined(__clang__)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

// ユーティリティ定数
#define SLEEP_CHECK_INTERVAL_MS 100 // スリープ中の割り込みチェック間隔（ミリ秒）
#define MAX_HOSTNAME_LEN	253 // RFC 1035: ホスト名の最大長

// 構造体のパディングなしパッキング (GCC/Clang属性)
#define STAMP_PACKED __attribute__((packed))

// RAII-style auto-cleanup helpers (GNU __attribute__((cleanup)))
// スコープ離脱時に自動的にリソースを解放する
static inline void cleanup_socket(SOCKET *s)
{
	if (!SOCKET_ERROR_CHECK(*s)) {
		CLOSE_SOCKET(*s);
		*s = INVALID_SOCKET;
	}
}
#define AUTO_CLOSE_SOCKET __attribute__((cleanup(cleanup_socket)))

#ifndef _WIN32
static inline void cleanup_fd(int *fd)
{
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}
#define AUTO_CLOSE_FD __attribute__((cleanup(cleanup_fd)))
#endif

// =============================================================================
// 共通ユーティリティ（reflector.c, sender.c で使用）
// =============================================================================

// getopt() サポート
#ifdef _WIN32
// Windows: 標準getoptが利用できない環境向けの簡易実装
static char *g_stamp_optarg = NULL;
static int g_stamp_optind = 1;
static int g_stamp_optopt = 0;

/**
 * Windows用getopt()簡易実装
 * @return オプション文字、終了時-1、エラー時'?'
 */
static inline int stamp_getopt(int argc,
			       char *const argv[],
			       const char *optstring)
{
	if (g_stamp_optind >= argc || argv[g_stamp_optind] == NULL) {
		return -1;
	}

	char *arg = argv[g_stamp_optind];
	size_t arg_len = strlen(arg);
	if (arg_len < 2 || arg[0] != '-') {
		return -1;
	}
	// "--" は終端マーカー
	if (arg_len == 2 && arg[1] == '-') {
		g_stamp_optind++;
		return -1;
	}

	unsigned char opt = (unsigned char)arg[1];
	const char *p = strchr(optstring, (char)opt);
	if (p == NULL) {
		g_stamp_optopt = (int)opt;
		g_stamp_optind++;
		return '?';
	}

	g_stamp_optind++;
	if (p[1] == ':') {
		if (arg_len >= 3 && arg[2] != '\0') {
			g_stamp_optarg = (char *)&arg[2];
		} else if (g_stamp_optind < argc &&
			   argv[g_stamp_optind] != NULL) {
			g_stamp_optarg = argv[g_stamp_optind++];
		} else {
			g_stamp_optopt = (int)opt;
			return '?';
		}
	} else {
		// 余分な文字を拒否（例: "-4extra"）
		if (arg_len >= 3 && arg[2] != '\0') {
			g_stamp_optopt = (int)opt;
			return '?';
		}
	}
	return (int)opt;
}

// NOLINTBEGIN(readability-identifier-naming) -- POSIX getopt API互換マクロ
#define getopt stamp_getopt
#define optarg g_stamp_optarg
#define optind g_stamp_optind
#define optopt g_stamp_optopt
// NOLINTEND(readability-identifier-naming)
#else
// POSIX: 標準のgetoptを使用
#include <getopt.h>
#endif

// エラーメッセージ出力用マクロ
#define PRINT_SOCKET_ERROR(msg) fprintf(stderr, "%s: error %d\n", msg, SOCKET_ERRNO)

#endif // STAMP_PLATFORM_H
