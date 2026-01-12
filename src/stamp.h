// RFC 8762 STAMP (Simple Two-way Active Measurement Protocol) 実装
// Windows/Linux クロスプラットフォーム対応

#ifndef STAMP_H
#define STAMP_H

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>

// プラットフォーム固有のヘッダーとライブラリ
#ifdef _WIN32
// Windows環境
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <signal.h>
#define SOCKET_ERROR_CHECK(x) ((x) == INVALID_SOCKET)
#define CLOSE_SOCKET(x) closesocket(x)
#define SOCKET_ERRNO WSAGetLastError()
#else
// UNIX/Linux環境
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR_CHECK(x) ((x) < 0)
#define CLOSE_SOCKET(x) close(x)
#define SOCKET_ERRNO errno
#endif

// NTPタイムスタンプのオフセット (1900年1月1日から1970年1月1日までの秒数)
#define NTP_OFFSET 2208988800UL

// STAMPプロトコル定数
#define STAMP_PORT 862              // STAMP標準ポート番号 (RFC 8762 Section 4.1)
#define STAMP_BASE_PACKET_SIZE 44   // 基本パケットサイズ(RFC 4.2.1, 4.3.1) (バイト)
#define STAMP_MAX_PACKET_SIZE 65507 // UDPペイロード最大長
#define STAMP_MAX_SSID 65535        // セッションセンダーIDの最大値
#define NTP_FRAC_SCALE 4294967296.0 // 2^32

// タイムアウト設定
#define SOCKET_TIMEOUT_SEC 5
#define SOCKET_TIMEOUT_USEC 0

// コントロールメッセージバッファサイズ
// WSA_CMSG_SPACE/CMSG_SPACE マクロはMinGW環境で符号変換警告を出すため、
// 固定サイズを使用（TTL/HopLimit用intとtimespec両方に十分なサイズ）
#define STAMP_CMSG_BUFSIZE 64

// アドレス長のキャスト（connect/bind等のソケット関数用）
// Windows: int を期待、POSIX: socklen_t を期待
#ifdef _WIN32
#define ADDRLEN_CAST(x) ((int)(x))
#else
#define ADDRLEN_CAST(x) (x)
#endif

// ユーティリティ定数
#define FIREWALL_CMD_BUFSIZE 256    // ファイアウォールコマンドバッファサイズ
#define SLEEP_CHECK_INTERVAL_MS 100 // スリープ中の割り込みチェック間隔（ミリ秒）
#define MAX_HOSTNAME_LEN 253        // RFC 1035: ホスト名の最大長

// NTP小数部変換マクロ (丸め付き)
// ナノ秒からNTP小数部への変換: nsec * 2^32 / 10^9
#define NSEC_TO_NTP_FRAC(nsec) \
    ((uint32_t)(((uint64_t)(nsec) * 4294967296ULL + 500000000ULL) / 1000000000ULL))

// マイクロ秒からNTP小数部への変換: usec * 2^32 / 10^6
#define USEC_TO_NTP_FRAC(usec) \
    ((uint32_t)(((uint64_t)(usec) * 4294967296ULL + 500000ULL) / 1000000ULL))

#ifdef _WIN32
// Windows 100ナノ秒単位からNTP小数部への変換
#define WINDOWS_100NS_TO_NTP_FRAC(ticks) \
    ((uint32_t)((((uint64_t)(ticks) << 32) + (WINDOWS_TICKS_PER_SEC / 2)) / WINDOWS_TICKS_PER_SEC))
#endif

// Error Estimate フィールド (RFC 8762 Section 4.2.1, RFC 4656 Section 4.1.2)
// Format: |S|Z|Scale(6bits)|Multiplier(8bits)|
#define ERROR_ESTIMATE_S_BIT 0x8000      // Synchronized flag (bit 15)
#define ERROR_ESTIMATE_Z_BIT 0x4000      // Timestamp format: 0=NTP, 1=PTP (bit 14)
#define ERROR_ESTIMATE_SCALE_MASK 0x3F00 // Scale field (bits 8-13)
#define ERROR_ESTIMATE_MULT_MASK 0x00FF  // Multiplier field (bits 0-7)

// デフォルト Error Estimate: S=1 (synchronized), Z=0 (NTP), Scale=0, Multiplier=1
// エラー = Multiplier * 2^(-32) * 2^Scale 秒 = 1 * 2^(-32) 秒 ≈ 0.23 ns
#define ERROR_ESTIMATE_DEFAULT 0x8001

// Windows epoch から NTP epoch への変換定数
#ifdef _WIN32
#define WINDOWS_TO_NTP_OFFSET 11644473600ULL
#define WINDOWS_TICKS_PER_SEC 10000000ULL
#endif

// 構造体のパディングなしパッキング (GCC/Clang属性)
#define PACKED __attribute__((packed))

// RFC 8762 STAMPパケット構造体 (RFC 4.2.1)
// すべてのフィールドはネットワークバイトオーダー(ビッグエンディアン)で格納される
// unauthenticated mode の基本パケットサイズ: 44バイト
struct stamp_sender_packet
{
    uint32_t seq_num;        // シーケンス番号 (4 bytes)
    uint32_t timestamp_sec;  // タイムスタンプ 秒部分 (4 bytes)
    uint32_t timestamp_frac; // タイムスタンプ 小数部分 (4 bytes)
    uint16_t error_estimate; // エラー推定値 (2 bytes)
    uint8_t mbz[30];         // MBZ (Must Be Zero) - RFC 8762 Section 4.2.1 (30 bytes)
} PACKED;

// RFC 8762 STAMPパケット構造体 (RFC 4.3.1)
// unauthenticated mode の基本パケットサイズ: 44バイト
struct stamp_reflector_packet
{
    uint32_t seq_num;        // シーケンス番号 (4 bytes)
    uint32_t timestamp_sec;  // 送信タイムスタンプ 秒部分 (4 bytes)
    uint32_t timestamp_frac; // 送信タイムスタンプ 小数部分 (4 bytes)
    uint16_t error_estimate; // エラー推定値 (2 bytes)
    uint16_t mbz_1;          // MBZ (Must Be Zero) - RFC 8762 Section 4.3.1 (2 bytes)
    uint32_t rx_sec;         // 受信タイムスタンプ 秒部分 (4 bytes)
    uint32_t rx_frac;        // 受信タイムスタンプ 小数部分 (4 bytes)
    uint32_t sender_seq_num; // Session-Sender Sequence Number (4 bytes)
    uint32_t sender_ts_sec;  // Session-Sender Timestamp 秒部分 (4 bytes)
    uint32_t sender_ts_frac; // Session-Sender Timestamp 小数部分 (4 bytes)
    uint16_t sender_err_est; // Session-Sender Error Estimate (2 bytes)
    uint16_t mbz_2;          // MBZ (Must Be Zero) - RFC 8762 Section 4.3.1 (2 bytes)
    uint8_t sender_ttl;      // Session-Sender TTL/Hop Limit (1 byte)
    uint8_t mbz_3[3];        // MBZ (Must Be Zero) - RFC 8762 Section 4.3.1 (3 bytes)
} PACKED;

#undef PACKED

/**
 * NTPタイムスタンプを取得 (RFC 5905 準拠)
 * 高頻度呼び出しのためinline化して関数呼び出しオーバーヘッドを削減
 * @param sec  秒部分を格納するポインタ (ネットワークバイトオーダー)
 * @param frac 小数部分を格納するポインタ (ネットワークバイトオーダー)
 * @return 成功時0、エラー時-1
 */
static inline int get_ntp_timestamp(uint32_t *sec, uint32_t *frac)
{
    if (!sec || !frac)
    {
        return -1;
    }

#ifdef _WIN32
    // Windows: GetSystemTimeAsFileTime を使用
    FILETIME ft;
    ULARGE_INTEGER ui;
    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;

    // Windows epoch: 1601-01-01, NTP epoch: 1900-01-01
    uint64_t unix_time = (ui.QuadPart / WINDOWS_TICKS_PER_SEC) - WINDOWS_TO_NTP_OFFSET;
    uint64_t frac_100ns = ui.QuadPart % WINDOWS_TICKS_PER_SEC;

    *sec = htonl((uint32_t)(unix_time + NTP_OFFSET));
    *frac = htonl(WINDOWS_100NS_TO_NTP_FRAC(frac_100ns));
#else
#if defined(CLOCK_REALTIME)
    // UNIX/Linux: clock_gettime を使用
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        return -1;
    }
    *sec = htonl((uint32_t)((unsigned long)ts.tv_sec + NTP_OFFSET));
    *frac = htonl(NSEC_TO_NTP_FRAC(ts.tv_nsec));
#else
    // UNIX/Linux: clock_gettime が使えない場合は gettimeofday にフォールバック
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
    {
        return -1;
    }
    *sec = htonl((uint32_t)(tv.tv_sec + NTP_OFFSET));
    *frac = htonl(USEC_TO_NTP_FRAC(tv.tv_usec));
#endif
#endif

    return 0;
}

/**
 * NTPタイムスタンプをdouble型のUNIX時刻に変換 (RFC 5905 準拠)
 * 高頻度呼び出しのためinline化して関数呼び出しオーバーヘッドを削減
 * @param sec  秒部分 (ネットワークバイトオーダー)
 * @param frac 小数部分 (ネットワークバイトオーダー)
 * @return UNIX時刻 (1970年1月1日からの秒数)
 */
static inline double ntp_to_double(uint32_t sec, uint32_t frac)
{
    uint32_t s = ntohl(sec);
    uint32_t f = ntohl(frac);
    return (double)(s - NTP_OFFSET) + ((double)f / NTP_FRAC_SCALE);
}

/**
 * STAMPパケットの基本的な妥当性チェック (RFC 8762 Section 4 準拠)
 * @param packet チェックするパケット
 * @param size パケットサイズ
 * @return 妥当な場合1、不正な場合0
 */
static inline int validate_stamp_packet(const void *packet, int size)
{
    if (!packet || size < STAMP_BASE_PACKET_SIZE)
    {
        return 0;
    }
    return 1;
}

// =============================================================================
// 共通ユーティリティ（reflector.c, sender.c で使用）
// =============================================================================

// getopt() サポート
#ifdef _WIN32
// Windows: 標準getoptが利用できない環境向けの簡易実装
static char *stamp_optarg = NULL;
static int stamp_optind = 1;
static int stamp_optopt = 0;

/**
 * Windows用getopt()簡易実装
 * POSIXのgetopt()と互換性のある基本的なオプション解析を提供
 * @param argc 引数の数
 * @param argv 引数配列
 * @param optstring オプション文字列（':'で引数必須を指定）
 * @return オプション文字、終了時-1、エラー時'?'
 */
static inline int stamp_getopt(int argc, char *const argv[], const char *optstring)
{
    if (stamp_optind >= argc || argv[stamp_optind] == NULL)
        return -1;

    const char *arg = argv[stamp_optind];
    // 境界チェック: 最低2文字必要（'-' + オプション文字）
    size_t arg_len = strlen(arg);
    if (arg_len < 2 || arg[0] != '-')
        return -1;
    // 「--」は終端マーカー（arg_len == 2 && arg[1] == '-'で検出）
    if (arg_len == 2 && arg[1] == '-')
    {
        stamp_optind++;
        return -1;
    }

    char opt = arg[1];
    const char *p = strchr(optstring, opt);
    if (p == NULL)
    {
        stamp_optopt = opt;
        stamp_optind++;
        return '?';
    }

    stamp_optind++;
    // 以下、arg[2]へのアクセスは arg_len >= 3 の条件により境界チェック済み
    if (p[1] == ':')
    {
        // オプションが引数を要求する場合
        if (arg_len >= 3 && arg[2] != '\0')
        {
            stamp_optarg = (char *)&arg[2];
        }
        else if (stamp_optind < argc && argv[stamp_optind] != NULL)
        {
            stamp_optarg = argv[stamp_optind++];
        }
        else
        {
            stamp_optopt = opt;
            return '?';
        }
    }
    else
    {
        // オプションが引数を要求しない場合: 余分な文字を拒否（例: "-4extra"）
        if (arg_len >= 3 && arg[2] != '\0')
        {
            stamp_optopt = opt;
            return '?';
        }
    }
    return opt;
}

#define getopt stamp_getopt
#define optarg stamp_optarg
#define optind stamp_optind
#define optopt stamp_optopt
#else
// POSIX: 標準のgetoptを使用
#include <getopt.h>
#endif

// エラーメッセージ出力用マクロ
#define PRINT_SOCKET_ERROR(msg) fprintf(stderr, "%s: error %d\n", msg, SOCKET_ERRNO)

// グローバル変数（シグナルハンドラからアクセス）
#ifdef STAMP_DEFINE_GLOBALS
volatile sig_atomic_t g_running = 1;
#else
extern volatile sig_atomic_t g_running;
#endif

/**
 * シグナルハンドラ（Ctrl+C対応）
 */
#ifdef _WIN32
static inline BOOL WINAPI stamp_signal_handler(DWORD signal)
{
    if (signal == CTRL_C_EVENT)
    {
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
static inline void stamp_signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        g_running = 0;
    }
}
#endif

/**
 * ポート番号のパース
 * @param arg ポート番号文字列
 * @param port パース結果を格納するポインタ
 * @return 成功時0、エラー時-1
 */
static inline int parse_port(const char *arg, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

    if (!arg || !port)
    {
        return -1;
    }

    // 空文字列のチェック
    if (*arg == '\0')
    {
        return -1;
    }

    // オーバーフロー検出のためerrnoをリセット
    errno = 0;
    value = strtoul(arg, &end, 10);

    // エラーチェック:
    // 1. strtoul()がオーバーフロー時にULONG_MAXを返しerrnoにERANGEを設定
    // 2. 変換後に残りの文字がある（例: "123abc"）
    // 3. ポート番号の有効範囲外（0または65535超）
    if (errno == ERANGE || (end && *end != '\0') || value == 0 || value > 65535)
    {
        return -1;
    }

    *port = (uint16_t)value;
    return 0;
}

#ifdef _WIN32
/**
 * WSARecvMsg関数ポインタの初期化
 * @param sockfd ソケットディスクリプタ
 * @param wsa_recvmsg 関数ポインタを格納するポインタ
 * @return 成功時true、失敗時false
 */
static inline bool init_wsa_recvmsg(SOCKET sockfd, LPFN_WSARECVMSG *wsa_recvmsg)
{
    DWORD bytes = 0;
    GUID guid = WSAID_WSARECVMSG;

    if (WSAIoctl(sockfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 wsa_recvmsg, sizeof(*wsa_recvmsg),
                 &bytes, NULL, NULL) == SOCKET_ERROR)
    {
        *wsa_recvmsg = NULL;
        return false;
    }
    return true;
}
#endif

#ifndef _WIN32
/**
 * カーネルタイムスタンプからNTPタイムスタンプへの変換（timespec版）
 * @param ts timespec構造体へのポインタ
 * @param ntp_sec NTP秒部分を格納するポインタ
 * @param ntp_frac NTP小数部分を格納するポインタ
 */
static inline void timespec_to_ntp(const struct timespec *ts,
                                   uint32_t *ntp_sec, uint32_t *ntp_frac)
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
static inline void timeval_to_ntp(const struct timeval *tv,
                                  uint32_t *ntp_sec, uint32_t *ntp_frac)
{
    *ntp_sec = htonl((uint32_t)((unsigned long)tv->tv_sec + NTP_OFFSET));
    *ntp_frac = htonl(USEC_TO_NTP_FRAC(tv->tv_usec));
}
#endif

// =============================================================================
// IPv4/IPv6 デュアルスタック対応ユーティリティ
// =============================================================================

/**
 * sockaddr_storage構造体のサイズを取得
 * @param family アドレスファミリ (AF_INET or AF_INET6)
 * @return 構造体サイズ
 */
static inline socklen_t get_sockaddr_len(int family)
{
    return (family == AF_INET6) ? (socklen_t)sizeof(struct sockaddr_in6)
                                : (socklen_t)sizeof(struct sockaddr_in);
}

/**
 * sockaddr_storageからポート番号を取得
 * @param addr sockaddr_storage構造体へのポインタ
 * @return ポート番号（ホストバイトオーダー）、エラー時0
 */
static inline uint16_t sockaddr_get_port(const struct sockaddr_storage *addr)
{
    if (!addr)
        return 0;
    if (addr->ss_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        return ntohs(sin->sin_port);
    }
    else if (addr->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        return ntohs(sin6->sin6_port);
    }
    return 0;
}

/**
 * sockaddr_storageをアドレス文字列に変換
 * getnameinfo()を使用してIPv4/IPv6両対応
 * @param addr sockaddr_storage構造体へのポインタ
 * @param buf 出力バッファ
 * @param buflen バッファサイズ（INET6_ADDRSTRLEN以上推奨）
 * @return 成功時buf、エラー時NULL
 */
static inline const char *sockaddr_to_string(const struct sockaddr_storage *addr,
                                             char *buf, size_t buflen)
{
    if (!addr || !buf || buflen == 0)
        return NULL;

    socklen_t addrlen = get_sockaddr_len(addr->ss_family);
#ifdef _WIN32
    // Windows: getnameinfo expects DWORD for buffer size
    if (getnameinfo((const struct sockaddr *)addr, addrlen,
                    buf, (DWORD)buflen, NULL, 0, NI_NUMERICHOST) != 0)
#else
    if (getnameinfo((const struct sockaddr *)addr, addrlen,
                    buf, (socklen_t)buflen, NULL, 0, NI_NUMERICHOST) != 0)
#endif
    {
        return NULL;
    }
    return buf;
}

/**
 * sockaddr_storageをアドレス文字列に変換（フォールバック付き）
 * 変換に失敗した場合は"<unknown>"を返す
 * @param addr sockaddr_storage構造体へのポインタ
 * @param buf 出力バッファ
 * @param buflen バッファサイズ（INET6_ADDRSTRLEN以上推奨）
 * @return 常にbuf（変換失敗時は"<unknown>"が格納される）
 */
static inline const char *sockaddr_to_string_safe(const struct sockaddr_storage *addr,
                                                  char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return "<unknown>";

    if (sockaddr_to_string(addr, buf, buflen) == NULL)
    {
        snprintf(buf, buflen, "<unknown>");
    }
    return buf;
}

/**
 * sockaddr_storageをポート番号付きアドレス文字列にフォーマット
 * IPv6の場合は[addr]:port形式、IPv4の場合はaddr:port形式
 * @param addr sockaddr_storage構造体へのポインタ
 * @param buf 出力バッファ
 * @param buflen バッファサイズ
 * @return 常にbuf
 */
static inline const char *format_sockaddr_with_port(const struct sockaddr_storage *addr,
                                                    char *buf, size_t buflen)
{
    char addr_str[INET6_ADDRSTRLEN];

    if (!buf || buflen == 0)
        return "";

    sockaddr_to_string_safe(addr, addr_str, sizeof(addr_str));
    uint16_t port = sockaddr_get_port(addr);

    if (addr && addr->ss_family == AF_INET6)
    {
        snprintf(buf, buflen, "[%s]:%u", addr_str, port);
    }
    else
    {
        snprintf(buf, buflen, "%s:%u", addr_str, port);
    }
    return buf;
}

/**
 * ホスト名またはIPアドレス文字列を解決してaddrinfoリストを取得
 * getaddrinfo()を使用してIPv4/IPv6両方に対応
 * @param host ホスト名またはIPアドレス文字列（MAX_HOSTNAME_LEN以下）
 * @param port ポート番号
 * @param af_hint アドレスファミリのヒント (AF_UNSPEC=自動, AF_INET, AF_INET6)
 * @param out_result getaddrinfo()の結果（使用後はfreeaddrinfo()が必要）
 * @return 成功時0、エラー時-1
 */
static inline int resolve_address_list(const char *host, uint16_t port, int af_hint,
                                       struct addrinfo **out_result)
{
    struct addrinfo hints;
    char port_str[16];
    int ret;

    if (!host || !out_result)
        return -1;

    // ホスト名の長さ検証（RFC 1035: 最大253文字）
    if (strlen(host) > MAX_HOSTNAME_LEN)
    {
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
    if (ret != 0)
    {
        return -1;
    }

    return 0;
}

/**
 * ホスト名またはIPアドレス文字列を解決してsockaddr_storageに格納
 * getaddrinfo()を使用してIPv4/IPv6両方に対応
 * resolve_address_list()で取得したアドレスリストから最初のIPv4/IPv6エントリを使用します。
 * 接続失敗時のフォールバックが必要な場合は、resolve_address_list()で順に試行してください。
 * @param host ホスト名またはIPアドレス文字列
 * @param port ポート番号
 * @param af_hint アドレスファミリのヒント (AF_UNSPEC=自動, AF_INET, AF_INET6)
 * @param out_addr 解決結果を格納するsockaddr_storage構造体
 * @param out_addrlen 構造体サイズを格納するポインタ
 * @return 成功時0、エラー時-1
 */
static inline int resolve_address(const char *host, uint16_t port, int af_hint,
                                  struct sockaddr_storage *out_addr,
                                  socklen_t *out_addrlen)
{
    struct addrinfo *result, *rp;

    if (!host || !out_addr || !out_addrlen)
        return -1;

    if (resolve_address_list(host, port, af_hint, &result) != 0)
    {
        return -1;
    }

    // getaddrinfo()が返すアドレスリストを順に処理
    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6)
        {
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

#endif
