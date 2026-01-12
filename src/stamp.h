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
// 固定サイズを使用。128バイトはSO_TIMESTAMPING（3つのtimespec = 24バイト）、
// TTL/HopLimit用int、および制御メッセージヘッダを格納するのに十分なサイズ。
#define STAMP_CMSG_BUFSIZE 128

// Linux: SO_BUSY_POLLの設定値（マイクロ秒）
// デフォルトでは0（無効）とし、高負荷となるビジーポーリングは
// 高度なチューニングオプションとして明示的に有効化することを推奨。
// 必要に応じて、コンパイル時に -DSTAMP_BUSY_POLL_USEC=50 などで上書き可能。
#ifndef STAMP_BUSY_POLL_USEC
#define STAMP_BUSY_POLL_USEC 0
#endif

// Linux: SO_TIMESTAMPINGフラグ（カーネルタイムスタンプ用）
#ifdef __linux__
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#endif

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

// Windows: SIO_TIMESTAMPING サポート (Windows 10 1903以降)
// MinGW/MSYS2では定義されていない可能性があるため手動で定義
#include <mstcpip.h>

#ifndef SIO_TIMESTAMPING
#define SIO_TIMESTAMPING _WSAIOW(IOC_VENDOR, 235)
#endif

#ifndef SO_TIMESTAMP
#define SO_TIMESTAMP 0x300A
#endif

// TIMESTAMPING_CONFIG構造体（MinGWで未定義の場合）
#ifndef TIMESTAMPING_FLAG_RX
#define TIMESTAMPING_FLAG_RX 0x1
#define TIMESTAMPING_FLAG_TX 0x2

typedef struct _TIMESTAMPING_CONFIG {
    ULONG Flags;
    USHORT TxTimestampsBuffered;
} TIMESTAMPING_CONFIG, *PTIMESTAMPING_CONFIG;

// 受信タイムスタンプ用の制御メッセージ
#define SO_TIMESTAMP_ID 0x300B
#endif

#endif // _WIN32

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
 * NTPタイムスタンプを取得 (RFC 5905)
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param frac 小数部分（ネットワークバイトオーダー）
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(1, 2)))
static inline int get_ntp_timestamp(uint32_t *sec, uint32_t *frac)
{
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
 * NTPタイムスタンプをdouble型のUNIX時刻に変換
 * @param sec  秒部分（ネットワークバイトオーダー）
 * @param frac 小数部分（ネットワークバイトオーダー）
 * @return UNIX時刻（秒）
 */
__attribute__((pure))
static inline double ntp_to_double(uint32_t sec, uint32_t frac)
{
    uint32_t s = ntohl(sec);
    uint32_t f = ntohl(frac);
    return (double)(s - NTP_OFFSET) + ((double)f / NTP_FRAC_SCALE);
}

/**
 * STAMPパケットの妥当性チェック（サイズのみ検証）
 * @param packet パケットデータへのポインタ（NULLは未定義動作）
 * @param size パケットサイズ（バイト）
 * @return 妥当な場合1、不正な場合0
 * @note パケット内容（MBZフィールド等）は検証しない。サイズが
 *       STAMP_BASE_PACKET_SIZE以上であれば妥当と判定する。
 *       現在の実装ではpacketの内容を検査しないため、pure属性は使用しない。
 */
__attribute__((nonnull(1)))
static inline int validate_stamp_packet(const void *packet, int size)
{
    (void)packet; // nonnull属性で保証、将来の拡張用に残す
    return size >= STAMP_BASE_PACKET_SIZE;
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
    if (p[1] == ':')
    {
        // オプションが引数を要求する場合
        // arg[2]へのアクセスは arg_len >= 3 により境界チェックされている
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
        // arg[2]へのアクセスは arg_len >= 3 により境界チェックされている
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
__attribute__((nonnull(1, 2)))
static inline int parse_port(const char *arg, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

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

/**
 * Windows: SIO_TIMESTAMPINGでカーネルタイムスタンプを有効化
 * @param sockfd ソケットディスクリプタ
 * @return 成功時true、失敗時false
 *
 * Windows 10 1903以降で利用可能。失敗してもユーザースペースタイムスタンプに
 * フォールバックするため、戻り値のチェックは必須ではない。
 */
static inline bool enable_kernel_timestamping_windows(SOCKET sockfd)
{
    TIMESTAMPING_CONFIG ts_config = {0};
    ts_config.Flags = TIMESTAMPING_FLAG_RX; // 受信タイムスタンプを有効化
    ts_config.TxTimestampsBuffered = 0;
    DWORD bytes_returned = 0;

    if (WSAIoctl(sockfd, SIO_TIMESTAMPING,
                 &ts_config, sizeof(ts_config),
                 NULL, 0, &bytes_returned, NULL, NULL) == 0)
    {
        printf("Kernel timestamping enabled (SIO_TIMESTAMPING)\n");
        return true;
    }
    else
    {
        // Windows 10 1903未満では失敗する可能性がある
        // フォールバック: ユーザースペースタイムスタンプを使用
        fprintf(stderr, "Warning: SIO_TIMESTAMPING not available (error %d); using userspace timestamps\n",
                WSAGetLastError());
        return false;
    }
}

/**
 * Windows: 制御メッセージからカーネルタイムスタンプを抽出
 * @param msg WSARecvMsg()で受信したWSAMSG構造体へのポインタ（NULLは未定義動作）
 * @param ntp_sec NTP秒部分を格納するポインタ（NULLは未定義動作）
 * @param ntp_frac NTP小数部分を格納するポインタ（NULLは未定義動作）
 * @return タイムスタンプが見つかった場合true、そうでない場合false
 *
 * Windows 10 1903以降でSIO_TIMESTAMPINGが有効な場合、
 * SO_TIMESTAMP制御メッセージにFILETIME形式のタイムスタンプが含まれる。
 */
__attribute__((nonnull(1, 2, 3)))
static inline bool extract_kernel_timestamp_windows(WSAMSG *msg,
                                                     uint32_t *ntp_sec,
                                                     uint32_t *ntp_frac)
{
    // MinGW WSA_CMSG_NXTHDR マクロの符号変換警告を抑制
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
    for (WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = WSA_CMSG_NXTHDR(msg, cmsg))
    {
        // SO_TIMESTAMP または SO_TIMESTAMP_ID: カーネルタイムスタンプ
        // SIO_TIMESTAMPINGで有効化した場合、SO_TIMESTAMP_IDで返される
        if (cmsg->cmsg_level == SOL_SOCKET &&
            (cmsg->cmsg_type == SO_TIMESTAMP || cmsg->cmsg_type == SO_TIMESTAMP_ID))
        {
            // FILETIME形式（Windows epoch: 1601-01-01からの100ナノ秒単位）
            // cmsg_lenでデータサイズを検証
            size_t data_len = cmsg->cmsg_len - WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR));
            if (data_len >= sizeof(UINT64))
            {
                UINT64 filetime;
                memcpy(&filetime, WSA_CMSG_DATA(cmsg), sizeof(filetime));

                // 妥当性チェック: 2000年以降のタイムスタンプか確認
                // 2000-01-01 00:00:00 UTC = 125911584000000000 (100ns ticks since 1601)
                if (filetime >= 125911584000000000ULL)
                {
                    // NTPタイムスタンプに変換
                    uint64_t unix_time = (filetime / WINDOWS_TICKS_PER_SEC) - WINDOWS_TO_NTP_OFFSET;
                    uint64_t frac_100ns = filetime % WINDOWS_TICKS_PER_SEC;

                    *ntp_sec = htonl((uint32_t)(unix_time + NTP_OFFSET));
                    *ntp_frac = htonl(WINDOWS_100NS_TO_NTP_FRAC(frac_100ns));
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

/**
 * Linux: 制御メッセージからカーネルタイムスタンプを抽出
 * @param msg recvmsg()で受信したmsghdr構造体へのポインタ
 * @param ntp_sec NTP秒部分を格納するポインタ
 * @param ntp_frac NTP小数部分を格納するポインタ
 * @return タイムスタンプが見つかった場合true、そうでない場合false
 *
 * 優先順位:
 *   1. SCM_TIMESTAMPING (SO_TIMESTAMPING) - 最も高精度
 *   2. SCM_TIMESTAMPNS (SO_TIMESTAMPNS) - ナノ秒精度
 *   3. SCM_TIMESTAMP (SO_TIMESTAMP) - マイクロ秒精度
 */
static inline bool extract_kernel_timestamp_linux(struct msghdr *msg,
                                                   uint32_t *ntp_sec,
                                                   uint32_t *ntp_frac)
{
    if (!msg || !ntp_sec || !ntp_frac)
        return false;

    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
#ifdef __linux__
#ifdef SCM_TIMESTAMPING
        // SO_TIMESTAMPING: より高精度なカーネルタイムスタンプ
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING)
        {
            // cmsg_len を検証して、必要な timespec 配列が格納されていることを確認する
            size_t required_len = CMSG_LEN(3 * sizeof(struct timespec));
            if ((size_t)cmsg->cmsg_len < required_len)
            {
                // 不完全な制御メッセージは無視
                continue;
            }

            // struct scm_timestamping contains 3 timespec: sw, hw, raw
            struct timespec *ts = (struct timespec *)CMSG_DATA(cmsg);
            // 可能であれば非ゼロのタイムスタンプを優先して選択するが、
            // (0,0) も有効なタイムスタンプ値であるため、すべてゼロでも ts[0] を使用する
            struct timespec *selected = &ts[0];
            for (int i = 0; i < 3; i++)
            {
                if (ts[i].tv_sec != 0 || ts[i].tv_nsec != 0)
                {
                    selected = &ts[i];
                    break;
                }
            }

            timespec_to_ntp(selected, ntp_sec, ntp_frac);
            return true;
        }
#endif
#endif
#ifdef SCM_TIMESTAMPNS
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS)
        {
            struct timespec *ts = (struct timespec *)CMSG_DATA(cmsg);
            timespec_to_ntp(ts, ntp_sec, ntp_frac);
            return true;
        }
#endif
#ifdef SCM_TIMESTAMP
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP)
        {
            struct timeval *tv = (struct timeval *)CMSG_DATA(cmsg);
            timeval_to_ntp(tv, ntp_sec, ntp_frac);
            return true;
        }
#endif
    }
    return false;
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
__attribute__((const))
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
 * @return 成功時buf、エラー時NULL
 */
__attribute__((nonnull(1, 2)))
static inline const char *sockaddr_to_string(const struct sockaddr_storage *addr,
                                             char *buf, size_t buflen)
{
    if (buflen == 0)
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
 * sockaddr_storageをアドレス文字列に変換（失敗時は"<unknown>"）
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
 * アドレス:ポート形式の文字列を生成（IPv6は[addr]:port形式）
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
 * ホスト名/IPアドレスを解決してaddrinfoリストを取得
 * @param out_result 使用後はfreeaddrinfo()で解放が必要
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
 * ホスト名/IPアドレスを解決してsockaddr_storageに格納
 *
 * 注意: この関数はgetaddrinfo()が返すリストから最初にマッチする
 * IPv4/IPv6アドレスを返します。接続試行によるフォールバック
 * （例: IPv6接続失敗時にIPv4を試す）は実装していません。
 * 接続フォールバックが必要な場合は、resolve_address_list()を使用し、
 * 呼び出し元で各アドレスへの接続を順に試してください。
 *
 * @param af_hint AF_UNSPEC=自動, AF_INET, AF_INET6
 * @return 成功時0、エラー時-1
 */
__attribute__((nonnull(1, 4, 5)))
static inline int resolve_address(const char *host, uint16_t port, int af_hint,
                                  struct sockaddr_storage *out_addr,
                                  socklen_t *out_addrlen)
{
    struct addrinfo *result, *rp;

    if (resolve_address_list(host, port, af_hint, &result) != 0)
    {
        return -1;
    }

    // 最初にマッチするIPv4/IPv6アドレスを返す（接続試行なし）
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
