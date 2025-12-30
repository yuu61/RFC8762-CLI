// RFC 8762 STAMP (Simple Two-way Active Measurement Protocol) 実装
// Windows/Linux クロスプラットフォーム対応

#ifndef STAMP_H
#define STAMP_H

#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma comment(lib, "ws2_32.lib")
#pragma GCC diagnostic pop
#define SOCKET_ERROR_CHECK(x) ((x) == INVALID_SOCKET)
#define CLOSE_SOCKET(x) closesocket(x)
#define SOCKET_ERRNO WSAGetLastError()
#else
// UNIX/Linux環境
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
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

// Error Estimate フィールド (RFC 8762 Section 4.2.1, RFC 4656 Section 4.1.2)
// Format: |S|Z|Scale(6bits)|Multiplier(8bits)|
#define ERROR_ESTIMATE_S_BIT      0x8000  // Synchronized flag (bit 15)
#define ERROR_ESTIMATE_Z_BIT      0x4000  // Timestamp format: 0=NTP, 1=PTP (bit 14)
#define ERROR_ESTIMATE_SCALE_MASK 0x3F00  // Scale field (bits 8-13)
#define ERROR_ESTIMATE_MULT_MASK  0x00FF  // Multiplier field (bits 0-7)

// デフォルト Error Estimate: S=1 (synchronized), Z=0 (NTP), Scale=0, Multiplier=1
// エラー = Multiplier * 2^(-32) * 2^Scale 秒 = 1 * 2^(-32) 秒 ≈ 0.23 ns
#define ERROR_ESTIMATE_DEFAULT    0x8001

// Windows epoch から NTP epoch への変換定数
#ifdef _WIN32
#define WINDOWS_TO_NTP_OFFSET 11644473600ULL
#define WINDOWS_TICKS_PER_SEC 10000000ULL
#endif

// 構造体のパディングなしパッキング (プラットフォーム対応)
#ifdef _WIN32
#pragma pack(push, 1)
#define PACKED
#else
#define PACKED __attribute__((packed))
#endif

// RFC 8762 STAMPパケット構造体 (RFC 4.2.1)
// すべてのフィールドはネットワークバイトオーダー(ビッグエンディアン)で格納される
// unauthenticated mode の基本パケットサイズ: 44バイト
struct stamp_sender_packet
{
    uint32_t seq_num;        // シーケンス番号 (4 bytes)
    uint32_t timestamp_sec;  // タイムスタンプ 秒部分 (4 bytes)
    uint32_t timestamp_frac; // タイムスタンプ 小数部分 (4 bytes)
    uint16_t error_estimate; // エラー推定値 (2 bytes)
    uint8_t mbz[30];         // MBZ (30 bytes)
} PACKED;

// RFC 8762 STAMPパケット構造体 (RFC 4.3.1)
// unauthenticated mode の基本パケットサイズ: 44バイト
struct stamp_reflector_packet
{
    uint32_t seq_num;        // シーケンス番号 (4 bytes)
    uint32_t timestamp_sec;  // 送信タイムスタンプ 秒部分 (4 bytes)
    uint32_t timestamp_frac; // 送信タイムスタンプ 小数部分 (4 bytes)
    uint16_t error_estimate; // エラー推定値 (2 bytes)
    uint16_t mbz_1;          // MBZ (2 bytes)
    uint32_t rx_sec;         // 受信タイムスタンプ 秒部分 (4 bytes)
    uint32_t rx_frac;        // 受信タイムスタンプ 小数部分 (4 bytes)
    uint32_t sender_seq_num; // Session-Sender Sequence Number (4 bytes)
    uint32_t sender_ts_sec;  // Session-Sender Timestamp 秒部分 (4 bytes)
    uint32_t sender_ts_frac; // Session-Sender Timestamp 小数部分 (4 bytes)
    uint16_t sender_err_est; // Session-Sender Error Estimate (2 bytes)
    uint16_t mbz_2;          // MBZ (2 bytes)
    uint8_t sender_ttl;      // Session-Sender TTL/Hop Limit (1 byte)
    uint8_t mbz_3[3];        // MBZ (3 bytes)
} PACKED;

#ifdef _WIN32
#pragma pack(pop)
#endif
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
    double fraction = (double)frac_100ns * NTP_FRAC_SCALE / (double)WINDOWS_TICKS_PER_SEC;
    *frac = htonl((uint32_t)fraction);
#else
#if defined(CLOCK_REALTIME)
    // UNIX/Linux: clock_gettime を使用
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        return -1;
    }
    *sec = htonl((uint32_t)(ts.tv_sec + NTP_OFFSET));
    double fraction = (double)ts.tv_nsec * NTP_FRAC_SCALE / 1000000000.0;
    *frac = htonl((uint32_t)fraction);
#else
    // UNIX/Linux: clock_gettime が使えない場合は gettimeofday にフォールバック
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
    {
        return -1;
    }
    *sec = htonl((uint32_t)(tv.tv_sec + NTP_OFFSET));
    double fraction = (double)tv.tv_usec * NTP_FRAC_SCALE / 1000000.0;
    *frac = htonl((uint32_t)fraction);
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

    value = strtoul(arg, &end, 10);
    if (*arg == '\0' || (end && *end != '\0') || value == 0 || value > 65535)
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
    *ntp_sec = htonl((uint32_t)(ts->tv_sec + NTP_OFFSET));
    double fraction = (double)ts->tv_nsec * NTP_FRAC_SCALE / 1000000000.0;
    *ntp_frac = htonl((uint32_t)fraction);
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
    *ntp_sec = htonl((uint32_t)(tv->tv_sec + NTP_OFFSET));
    double fraction = (double)tv->tv_usec * NTP_FRAC_SCALE / 1000000.0;
    *ntp_frac = htonl((uint32_t)fraction);
}
#endif

#endif
