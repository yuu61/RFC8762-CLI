// RFC 8762 STAMP Reflector実装
// Senderからのパケットを受信し、タイムスタンプを付けて返送する

#define STAMP_DEFINE_GLOBALS
#include "stamp.h"
#ifdef _WIN32
#include <mswsock.h>
#endif

// 分岐予測ヒント（GNU拡張）
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define PORT STAMP_PORT // STAMP標準ポート番号

// セッション統計情報
struct reflector_stats
{
    uint32_t packets_reflected;
    uint32_t packets_dropped;
};

static struct reflector_stats g_stats = {0, 0};

#ifndef _WIN32
// ファイアウォール管理用のグローバル変数
static uint16_t g_firewall_port = 0;
static int g_firewall_family = AF_UNSPEC;
static volatile sig_atomic_t g_firewall_rule_added = 0;

// ランタイムデバッグフラグ
static bool g_debug_mode = false;

/**
 * デバッグログ出力マクロ
 */
#define DEBUG_LOG(fmt, ...)                                 \
    do                                                      \
    {                                                       \
        if (g_debug_mode)                                   \
        {                                                   \
            fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
        }                                                   \
    } while (0)

/**
 * ファイアウォールルールを追加（nftables使用）
 * @return 成功時0、エラー時-1
 */
static int add_firewall_rule(uint16_t port,
                             __attribute__((unused)) int family)
{
    char cmd[FIREWALL_CMD_BUFSIZE];
    // nftables inet family handles both IPv4 and IPv6

    // root権限チェック
    if (geteuid() != 0)
    {
        return -1;
    }

    if (port == 0)
    {
        fprintf(stderr, "Error: Invalid port number for firewall rule: %u\n", port);
        return -1;
    }

    // nftables: inet family (IPv4+IPv6) のテーブルを作成
    snprintf(cmd, sizeof(cmd),
             "nft add table inet stamp_reflector 2>/dev/null");
    if (system(cmd) != 0)
    {
        fprintf(stderr, "Warning: Failed to create nftables table\n");
        return -1;
    }

    // input チェーンを作成（filter type, input hook, priority 0）
    snprintf(cmd, sizeof(cmd),
             "nft add chain inet stamp_reflector input "
             "'{ type filter hook input priority 0 ; }' 2>/dev/null");
    if (system(cmd) != 0)
    {
        fprintf(stderr, "Warning: Failed to create nftables chain\n");
        // テーブルをクリーンアップ（失敗しても続行）
        int ignored = system("nft delete table inet stamp_reflector 2>/dev/null");
        (void)ignored;
        return -1;
    }

    // UDPポートを許可するルールを追加
    snprintf(cmd, sizeof(cmd),
             "nft add rule inet stamp_reflector input udp dport %u accept",
             port);
    if (system(cmd) != 0)
    {
        fprintf(stderr, "Warning: Failed to add nftables rule for port %u\n", port);
        // テーブルをクリーンアップ（失敗しても続行）
        int ignored2 = system("nft delete table inet stamp_reflector 2>/dev/null");
        (void)ignored2;
        return -1;
    }

    printf("Firewall rule added for UDP port %u (IPv4+IPv6 via nftables)\n", port);
    g_firewall_port = port;
    g_firewall_family = family;
    g_firewall_rule_added = 1;
    return 0;
}

/**
 * ファイアウォールルールを削除
 */
static void remove_firewall_rule(void)
{
    uint16_t port;

    // アトミックにフラグをチェックしてクリア（二重実行防止）
    if (!g_firewall_rule_added)
    {
        return;
    }
    g_firewall_rule_added = 0;

    port = g_firewall_port;

    if (port == 0)
    {
        return;
    }

    // nftables: テーブルごと削除（ルールも自動的に削除される）
    if (system("nft delete table inet stamp_reflector 2>/dev/null") == 0)
    {
        printf("Firewall rules removed for UDP port %u (nftables table deleted)\n", port);
    }
    else
    {
        fprintf(stderr, "Warning: Failed to remove nftables table\n");
    }

    // グローバル状態をクリア
    g_firewall_port = 0;
    g_firewall_family = AF_UNSPEC;
}
#endif

/**
 * 統計情報の表示
 */
static void print_statistics(void)
{
    printf("\n--- STAMP Reflector Statistics ---\n");
    printf("Packets reflected: %u\n", g_stats.packets_reflected);
    printf("Packets dropped: %u\n", g_stats.packets_dropped);
}

/**
 * 使用方法の表示
 * @param prog プログラム名
 */
static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-4|-6] [-d] [port]\n", prog ? prog : "reflector");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -4    IPv4 only\n");
    fprintf(stderr, "  -6    IPv6 only\n");
    fprintf(stderr, "  -d    Enable debug output\n");
    fprintf(stderr, "  (default: dual-stack, accepting both IPv4 and IPv6)\n");
}

#ifdef _WIN32
static LPFN_WSARECVMSG g_wsa_recvmsg = NULL;
#endif

/**
 * リスニングソケットの初期化
 * @return ソケットディスクリプタ、エラー時INVALID_SOCKET
 */
static SOCKET init_reflector_socket(uint16_t port, int af_hint, int *out_family)
{
    SOCKET sockfd;
    struct sockaddr_storage servaddr;
    int opt = 1;
    int family;
    int try_ipv4_fallback = (af_hint == AF_UNSPEC);

    // デュアルスタック: IPv6を優先（IPV6_V6ONLY=0でIPv4も受け入れ可能）
    if (af_hint == AF_UNSPEC)
    {
        family = AF_INET6;
    }
    else
    {
        family = af_hint;
    }

    // ソケット作成とバインドをループで試行（IPv6失敗時にIPv4にフォールバック）
    for (int retry = 0; retry < 2; retry++)
    {
        // 2回目のループ時はIPv4を試行
        if (retry == 1)
        {
            family = AF_INET;
        }

        // UDPソケットの作成
        sockfd = socket(family, SOCK_DGRAM, 0);
        if (SOCKET_ERROR_CHECK(sockfd))
        {
            if (try_ipv4_fallback && family == AF_INET6)
            {
                // IPv6失敗、IPv4にフォールバック
                continue;
            }
            PRINT_SOCKET_ERROR("socket creation failed");
            return INVALID_SOCKET;
        }

        // SO_REUSEADDRオプションの設定
        /* SO_REUSEADDRが設定できなくても致命的ではない。
         * リスタート時に同じポートをすぐに再利用できない可能性があるだけなので、
         * 警告を出して処理を継続する。
         */
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                       (const char *)&opt, sizeof(opt)) < 0)
        {
            PRINT_SOCKET_ERROR("setsockopt SO_REUSEADDR failed");
            fprintf(stderr, "Continuing without address reuse (port may not be immediately reusable after restart)\n");
        }

        // IPv6デュアルスタック設定
        if (family == AF_INET6 && af_hint == AF_UNSPEC)
        {
            int v6only = 0; // デュアルスタック有効化
#ifdef IPV6_V6ONLY
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
                           (const char *)&v6only, sizeof(v6only)) < 0)
            {
                // デュアルスタック非対応の場合は無視
            }
#endif
        }

#ifdef _WIN32
        // Windows: ソケットタイムアウトを設定（Ctrl+Cで終了できるようにする）
        {
            DWORD timeout_ms = 1000; // 1秒
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&timeout_ms, sizeof(timeout_ms));
        }

        // Windows: SIO_TIMESTAMPINGでカーネルタイムスタンプを有効化
        // Windows 10 1903以降で利用可能
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
            }
            else
            {
                // Windows 10 1903未満では失敗する可能性がある
                // フォールバック: ユーザースペースタイムスタンプを使用
                fprintf(stderr, "Warning: SIO_TIMESTAMPING not available (error %d); using userspace timestamps\n",
                        WSAGetLastError());
            }
        }
#endif

        // 受信TTL/Hop Limit取得の有効化 (可能な場合)
        if (family == AF_INET)
        {
#ifdef IP_RECVTTL
            int recv_ttl = 1;
            if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL,
                           (const char *)&recv_ttl, sizeof(recv_ttl)) < 0)
            {
                fprintf(stderr, "Warning: IP_RECVTTL failed (error %d); TTL info may be unavailable\n", SOCKET_ERRNO);
            }
#else
            fprintf(stderr, "Warning: IP_RECVTTL not available on this platform; TTL info will be unavailable\n");
#endif
        }
        else
        {
#ifdef IPV6_RECVHOPLIMIT
            int recv_hop = 1;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                           (const char *)&recv_hop, sizeof(recv_hop)) < 0)
            {
                fprintf(stderr, "Warning: IPV6_RECVHOPLIMIT failed (error %d); Hop Limit info may be unavailable\n", SOCKET_ERRNO);
            }
#elif defined(IPV6_HOPLIMIT)
            // Windows: IPV6_HOPLIMITを試行
            int recv_hop = 1;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_HOPLIMIT,
                           (const char *)&recv_hop, sizeof(recv_hop)) < 0)
            {
                fprintf(stderr, "Warning: IPV6_HOPLIMIT failed (error %d); Hop Limit info may be unavailable\n", SOCKET_ERRNO);
            }
#else
            fprintf(stderr, "Warning: IPV6_RECVHOPLIMIT/IPV6_HOPLIMIT not available on this platform; Hop Limit info will be unavailable\n");
#endif
        }

#ifndef _WIN32
        // カーネルタイムスタンプの有効化 (SO_TIMESTAMPNS: ナノ秒精度)
#ifdef SO_TIMESTAMPNS
        {
            int ts_opt = 1;
            (void)setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPNS, &ts_opt, sizeof(ts_opt));
        }
#elif defined(SO_TIMESTAMP)
        {
            int ts_opt = 1;
            (void)setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, &ts_opt, sizeof(ts_opt));
        }
#endif

#ifdef __linux__
        // SO_BUSY_POLL: ビジーポーリングでレイテンシ削減
        // NICドライバがNAPIをサポートしている場合に効果的
#ifdef SO_BUSY_POLL
        {
            int busy_poll = STAMP_BUSY_POLL_USEC;
            if (setsockopt(sockfd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll)) < 0)
            {
                // 失敗しても致命的ではない（カーネル設定で無効化されている場合がある）
                DEBUG_LOG("SO_BUSY_POLL not available (error %d)", errno);
            }
            else
            {
                DEBUG_LOG("SO_BUSY_POLL enabled (%d usec)", busy_poll);
            }
        }
#endif

        // SO_TIMESTAMPING: カーネルレベルの送受信タイムスタンプ
        // より正確なT2/T3タイムスタンプを取得可能
#ifdef SO_TIMESTAMPING
        {
            int ts_flags = SOF_TIMESTAMPING_RX_SOFTWARE |
                           SOF_TIMESTAMPING_TX_SOFTWARE |
                           SOF_TIMESTAMPING_SOFTWARE;
            if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &ts_flags, sizeof(ts_flags)) < 0)
            {
                DEBUG_LOG("SO_TIMESTAMPING not available (error %d)", errno);
            }
            else
            {
                DEBUG_LOG("SO_TIMESTAMPING enabled");
            }
        }
#endif
#endif // __linux__
#endif

        // サーバーアドレスの設定
        memset(&servaddr, 0, sizeof(servaddr));
        if (family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)&servaddr;
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = INADDR_ANY;
            sin->sin_port = htons(port);
        }
        else
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&servaddr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = in6addr_any;
            sin6->sin6_port = htons(port);
        }

        // バインド
        if (bind(sockfd, (const struct sockaddr *)&servaddr, get_sockaddr_len(family)) < 0)
        {
            // IPv6バインドが失敗した場合、IPv4にフォールバック
            if (try_ipv4_fallback && family == AF_INET6)
            {
                CLOSE_SOCKET(sockfd);
                continue;
            }
            PRINT_SOCKET_ERROR("bind failed");
            CLOSE_SOCKET(sockfd);
            return INVALID_SOCKET;
        }

        // 成功
        if (out_family)
            *out_family = family;
        return sockfd;
    }

    // ここに到達するのはIPv6/IPv4両方失敗した場合のみ
    PRINT_SOCKET_ERROR("Failed to create socket for both IPv6 and IPv4");
    return INVALID_SOCKET;
}

/**
 * STAMPパケットの反射処理
 * @return 成功時0、エラー時-1
 *
 * 注: この関数はホットパスであり、インライン化によりオーバーヘッドを削減する。
 * GCC属性:
 *   - always_inline: 関数呼び出しオーバーヘッドを排除
 *   - hot: キャッシュ最適化のヒント
 */
static inline __attribute__((always_inline, hot))
int reflect_packet(SOCKET sockfd, uint8_t *buffer, int send_len,
                   const struct sockaddr_storage *cliaddr, socklen_t len, uint8_t ttl,
                   uint32_t t2_sec, uint32_t t2_frac)
{
    struct stamp_sender_packet sender;
    struct stamp_reflector_packet *packet;
    uint32_t t3_sec, t3_frac;

    // バッファサイズの厳密な検証
    if (unlikely(send_len <= 0 || send_len > STAMP_MAX_PACKET_SIZE))
    {
        fprintf(stderr, "Invalid packet size: %d (valid range: 1-%d)\n",
                send_len, STAMP_MAX_PACKET_SIZE);
        return -1;
    }
    // 最小パケットサイズの確認（パディング後のサイズで判定）
    if (send_len < STAMP_BASE_PACKET_SIZE)
    {
        // パディングは呼び出し元で実施済みだが、念のため確認
        fprintf(stderr, "Warning: packet size %d < minimum %d\n",
                send_len, STAMP_BASE_PACKET_SIZE);
    }

    memset(&sender, 0, sizeof(sender));
    size_t copy_len = (size_t)(send_len < (int)sizeof(sender) ? send_len : (int)sizeof(sender));
    memcpy(&sender, buffer, copy_len);

    packet = (struct stamp_reflector_packet *)buffer;

    // Session-Senderの情報を保存（reflectorパケット用）
    packet->seq_num = sender.seq_num;        // Seq Numをコピー（stateless mode）
    packet->sender_seq_num = sender.seq_num; // Session-Sender Sequence Number
    packet->sender_ts_sec = sender.timestamp_sec;
    packet->sender_ts_frac = sender.timestamp_frac;
    packet->sender_err_est = sender.error_estimate;
    packet->sender_ttl = ttl; // TTL/Hop Limitをコピー（RFC 4.3.1）

    // Reflectorタイムスタンプを記録
    packet->rx_sec = t2_sec; // Receive Timestamp
    packet->rx_frac = t2_frac;
    packet->error_estimate = htons(ERROR_ESTIMATE_DEFAULT);
    packet->mbz_1 = 0; // MBZフィールド
    packet->mbz_2 = 0; // MBZフィールド
    memset(packet->mbz_3, 0, sizeof(packet->mbz_3));

    // T3: 送信時刻の取得（sendto()直前で取得してオーバーヘッドを最小化）
    // 注: パケットヘッダー設定後、sendto()直前でT3を取得することで
    // T2-T3間の処理時間をより正確に反映する
    if (unlikely(get_ntp_timestamp(&t3_sec, &t3_frac) != 0))
    {
        fprintf(stderr, "Failed to get T3 timestamp\n");
        return -1;
    }
    packet->timestamp_sec = t3_sec;
    packet->timestamp_frac = t3_frac;

    // パケットの返送（T3取得直後に送信）
    ssize_t send_result = sendto(sockfd, (const char *)buffer, (size_t)send_len, 0,
                                 (const struct sockaddr *)cliaddr, len);
    if (unlikely(send_result < 0))
    {
        int err = SOCKET_ERRNO;
        char addr_str[INET6_ADDRSTRLEN];
        sockaddr_to_string_safe(cliaddr, addr_str, sizeof(addr_str));
        fprintf(stderr, "sendto failed: error=%d, dest=%s, addrlen=%d, family=%d, send_len=%d\n",
                err, addr_str, (int)len, cliaddr->ss_family, send_len);
        g_stats.packets_dropped++;
        return -1;
    }

    g_stats.packets_reflected++;
    return 0;
}

/**
 * STAMPパケットの受信（タイムスタンプ付き）
 * @return 受信バイト数、エラー時-1
 *
 * 注: この関数はホットパスであり、インライン化によりオーバーヘッドを削減する。
 */
static inline __attribute__((always_inline, hot))
int recv_stamp_packet(SOCKET sockfd, uint8_t *buffer, int buffer_len,
                      struct sockaddr_storage *cliaddr, socklen_t *len, uint8_t *ttl,
                      uint32_t *t2_sec, uint32_t *t2_frac,
                      __attribute__((unused)) int socket_family)
{
#ifdef _WIN32
    if (ttl)
    {
        *ttl = 0;
    }

    if (g_wsa_recvmsg == NULL)
    {
        int n = recvfrom(sockfd, (char *)buffer, buffer_len, 0, (struct sockaddr *)cliaddr, len);
        if (n > 0 && t2_sec && t2_frac)
        {
            get_ntp_timestamp(t2_sec, t2_frac);
        }
        return n;
    }

    WSABUF data_buf;
    WSAMSG msg;
    char control[STAMP_CMSG_BUFSIZE];
    DWORD bytes = 0;

    data_buf.buf = (CHAR *)buffer;
    data_buf.len = (ULONG)buffer_len;
    memset(&msg, 0, sizeof(msg));
    msg.name = (LPSOCKADDR)cliaddr;
    msg.namelen = *len;
    msg.lpBuffers = &data_buf;
    msg.dwBufferCount = 1;
    msg.Control.buf = control;
    msg.Control.len = sizeof(control);

    if (g_wsa_recvmsg(sockfd, &msg, &bytes, NULL, NULL) == SOCKET_ERROR)
    {
        return -1;
    }

    *len = msg.namelen;

    // カーネルタイムスタンプを抽出（共通関数を使用）
    bool timestamp_found = false;
    if (t2_sec && t2_frac)
    {
        timestamp_found = extract_kernel_timestamp_windows(&msg, t2_sec, t2_frac);
        if (!timestamp_found)
        {
            get_ntp_timestamp(t2_sec, t2_frac);
        }
    }

    // TTL/Hop Limitを取得（reflector固有の処理）
    if (ttl)
    {
        WSACMSGHDR *cmsg;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
        for (cmsg = WSA_CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = WSA_CMSG_NXTHDR(&msg, cmsg))
        {
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
            // IPv4 TTL
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
            {
                int recv_ttl;
                memcpy(&recv_ttl, WSA_CMSG_DATA(cmsg), sizeof(recv_ttl));
                if (recv_ttl >= 0 && recv_ttl <= 255)
                {
                    *ttl = (uint8_t)recv_ttl;
                }
            }
#ifdef IPV6_HOPLIMIT
            // IPv6 Hop Limit
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
            {
                int recv_hop;
                memcpy(&recv_hop, WSA_CMSG_DATA(cmsg), sizeof(recv_hop));
                if (recv_hop >= 0 && recv_hop <= 255)
                {
                    *ttl = (uint8_t)recv_hop;
                }
            }
#endif
        }
    }

    return (int)bytes;
#else
    struct msghdr msg;
    struct iovec iov;
    char control[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct timespec))];
    ssize_t n;

    if (ttl)
    {
        *ttl = 0;
    }

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = (size_t)buffer_len;
    msg.msg_name = cliaddr;
    msg.msg_namelen = *len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    n = recvmsg(sockfd, &msg, 0);
    if (unlikely(n < 0))
    {
        return -1;
    }

    *len = msg.msg_namelen;

    // カーネルタイムスタンプを抽出（共通関数を使用）
    bool timestamp_found = false;
    if (t2_sec && t2_frac)
    {
        timestamp_found = extract_kernel_timestamp_linux(&msg, t2_sec, t2_frac);
        if (!timestamp_found)
        {
            get_ntp_timestamp(t2_sec, t2_frac);
        }
    }

    // TTL/Hop Limitを取得（reflector固有の処理）
    if (ttl)
    {
        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            // IPv4 TTL
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
            {
                int recv_ttl;
                memcpy(&recv_ttl, CMSG_DATA(cmsg), sizeof(recv_ttl));
                if (recv_ttl >= 0 && recv_ttl <= 255)
                {
                    *ttl = (uint8_t)recv_ttl;
                }
            }
#ifdef IPV6_HOPLIMIT
            // IPv6 Hop Limit
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
            {
                int recv_hop;
                memcpy(&recv_hop, CMSG_DATA(cmsg), sizeof(recv_hop));
                if (recv_hop >= 0 && recv_hop <= 255)
                {
                    *ttl = (uint8_t)recv_hop;
                }
            }
#endif
        }
    }

    return (int)n;
#endif
}

int main(int argc, char *argv[])
{
    SOCKET sockfd = INVALID_SOCKET;
    struct sockaddr_storage cliaddr;
    uint8_t buffer[STAMP_MAX_PACKET_SIZE];
    socklen_t len;
    uint16_t port = PORT;
    int af_hint = AF_UNSPEC; // デュアルスタック（デフォルト）
    int socket_family = AF_INET;
    int exit_code = 0;

#ifdef _WIN32
    // Windows: ソケット初期化
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    // getopt()によるオプションパース
    int opt;
    while ((opt = getopt(argc, argv, "46d")) != -1)
    {
        switch (opt)
        {
        case '4':
            af_hint = AF_INET;
            break;
        case '6':
            af_hint = AF_INET6;
            break;
        case 'd':
#ifndef _WIN32
            g_debug_mode = true;
#else
            fprintf(stderr, "Warning: Debug mode not supported on Windows\n");
#endif
            break;
        default:
            print_usage(argc > 0 ? argv[0] : "reflector");
            exit_code = 1;
            goto cleanup;
        }
    }

    // 残りの引数の数を確認
    int remaining_args = argc - optind;
    if (remaining_args > 1)
    {
        print_usage(argc > 0 ? argv[0] : "reflector");
        exit_code = 1;
        goto cleanup;
    }

    if (remaining_args > 0 && parse_port(argv[optind], &port) != 0)
    {
        fprintf(stderr, "Invalid port: %s\n", argv[optind]);
        print_usage(argc > 0 ? argv[0] : "reflector");
        exit_code = 1;
        goto cleanup;
    }

#ifndef _WIN32
    if (port < 1024 && geteuid() != 0)
    {
        fprintf(stderr, "Warning: binding to privileged port %u may fail without root privileges.\n", port);
    }
#endif

    // ソケットの初期化
    sockfd = init_reflector_socket(port, af_hint, &socket_family);
    if (SOCKET_ERROR_CHECK(sockfd))
    {
        exit_code = 1;
        goto cleanup;
    }

#ifdef _WIN32
    init_wsa_recvmsg(sockfd, &g_wsa_recvmsg);
    SetConsoleCtrlHandler(stamp_signal_handler, TRUE);
#else
    signal(SIGINT, stamp_signal_handler);
    signal(SIGTERM, stamp_signal_handler);

    if (geteuid() == 0)
    {
        if (add_firewall_rule(port, socket_family) == 0)
        {
            atexit(remove_firewall_rule);
        }
    }

    if (g_debug_mode)
    {
        fprintf(stderr, "[DEBUG] Debug mode enabled\n");
    }
#endif

    // 開始メッセージの表示
    {
        const char *mode_str;
        if (af_hint == AF_UNSPEC)
        {
            mode_str = (socket_family == AF_INET6) ? "dual-stack (IPv4+IPv6)" : "IPv4";
        }
        else
        {
            mode_str = (socket_family == AF_INET6) ? "IPv6" : "IPv4";
        }
        printf("STAMP Reflector listening on port %u (%s)...\n", port, mode_str);
    }
    printf("Press Ctrl+C to stop and show statistics\n");

    // メインループ
    while (g_running)
    {
        uint8_t ttl = 0;
        uint32_t t2_sec = 0, t2_frac = 0;
        int n;
        int send_len;

        len = sizeof(cliaddr);
        n = recv_stamp_packet(sockfd, buffer, sizeof(buffer), &cliaddr, &len, &ttl, &t2_sec, &t2_frac, socket_family);

        if (n < 0)
        {
            if (!g_running)
                break;
#ifdef _WIN32
            // Windows: タイムアウトエラーは無視してループを継続
            if (WSAGetLastError() == WSAETIMEDOUT)
                continue;
#endif
            PRINT_SOCKET_ERROR("recvfrom failed");
            continue;
        }
        if (n == 0)
        {
            continue;
        }

#ifndef _WIN32
        // 受信パケット情報のデバッグ出力（-dオプションで有効化）
        if (g_debug_mode)
        {
            char addr_port_str[INET6_ADDRSTRLEN + 8];
            format_sockaddr_with_port(&cliaddr, addr_port_str, sizeof(addr_port_str));
            DEBUG_LOG("Received %d bytes from %s (family=%d, addrlen=%d, ttl=%d)",
                      n, addr_port_str, cliaddr.ss_family, (int)len, ttl);
        }
#endif

        // パケットサイズが小さい場合はベースサイズに拡張
        send_len = n;
        if (send_len < STAMP_BASE_PACKET_SIZE)
        {
            fprintf(stderr,
                    "Warning: undersized STAMP packet received (%d bytes); will pad to %d bytes.\n",
                    n, STAMP_BASE_PACKET_SIZE);
            memset(buffer + send_len, 0, (size_t)(STAMP_BASE_PACKET_SIZE - send_len));
            send_len = STAMP_BASE_PACKET_SIZE;
        }

        // パケットの反射処理
        if (reflect_packet(sockfd, buffer, send_len, &cliaddr, len, ttl, t2_sec, t2_frac) == 0)
        {
            const struct stamp_reflector_packet *packet =
                (const struct stamp_reflector_packet *)buffer;
            char addr_port_str[INET6_ADDRSTRLEN + 8];
            format_sockaddr_with_port(&cliaddr, addr_port_str, sizeof(addr_port_str));

            const char *ttl_label = (cliaddr.ss_family == AF_INET6) ? "Hop Limit" : "TTL";
            printf("Reflected packet Seq: %" PRIu32 " from %s (%s: %d)\n",
                   (uint32_t)ntohl(packet->sender_seq_num),
                   addr_port_str, ttl_label, ttl);
        }
    }

    // 統計情報表示
    print_statistics();

cleanup:
    // クリーンアップ
    if (!SOCKET_ERROR_CHECK(sockfd))
    {
        CLOSE_SOCKET(sockfd);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return exit_code;
}
