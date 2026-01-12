// RFC 8762 STAMP Sender実装
// 指定されたサーバーに対してSTAMPパケットを送信し、RTTを測定する

#define STAMP_DEFINE_GLOBALS
#include "stamp.h"
#ifdef _WIN32
#include <mswsock.h>
#endif

// 分岐予測ヒント（GNU拡張）
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define PORT STAMP_PORT       // STAMP標準ポート番号
#define SERVER_IP "127.0.0.1" // デフォルトのサーバーIPアドレス（ローカルホスト）
#define SEND_INTERVAL_SEC 1   // 送信間隔（秒）

static bool g_negative_delay_seen = false;

// 統計情報構造体
struct sender_stats
{
    uint32_t sent;
    uint32_t received;
    uint32_t timeouts;
    double min_rtt;
    double max_rtt;
    double sum_rtt;
};

static struct sender_stats g_stats = {0, 0, 0, 1e9, 0, 0};

#ifdef _WIN32
static LPFN_WSARECVMSG g_wsa_recvmsg = NULL;
#endif

/**
 * 統計情報の表示
 */
static void print_statistics(void)
{
    printf("\n--- STAMP Statistics ---\n");
    printf("Packets sent: %u\n", g_stats.sent);
    printf("Packets received: %u\n", g_stats.received);
    printf("Packet loss: %.2f%%\n",
           g_stats.sent > 0 ? (100.0 * (g_stats.sent - g_stats.received) / g_stats.sent) : 0);
    printf("Timeouts: %u\n", g_stats.timeouts);
    if (g_stats.received > 0)
    {
        printf("RTT min/avg/max = %.3f/%.3f/%.3f ms\n",
               g_stats.min_rtt, g_stats.sum_rtt / g_stats.received, g_stats.max_rtt);
    }
    if (g_negative_delay_seen)
    {
        fprintf(stderr, "\nWarning: A negative delay was detected.\n");
        fprintf(stderr, "This typically indicates system clock skew.\n");
        fprintf(stderr, "Please ensure time synchronization is active on your system.\n");
        fprintf(stderr, "Tools: Windows (w32tm), Linux (chronyc/timedatectl), macOS (sntp).\n");
    }
}

/**
 * 使用方法の表示
 * @param prog プログラム名
 */
static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-4|-6] [server_ip|hostname] [port]\n", prog ? prog : "sender");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -4    Force IPv4\n");
    fprintf(stderr, "  -6    Force IPv6\n");
    fprintf(stderr, "  (default: auto-detect from address format)\n");
}

/**
 * ソケットの初期化
 * @return ソケットディスクリプタ、エラー時INVALID_SOCKET
 */
static SOCKET init_socket(const char *host, uint16_t port,
                          struct sockaddr_storage *servaddr, socklen_t *servaddr_len,
                          int af_hint)
{
    SOCKET sockfd = INVALID_SOCKET;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    int last_err = 0;
    struct sockaddr_storage last_addr;
    bool have_last_addr = false;

    if (resolve_address_list(host, port, af_hint, &result) != 0)
    {
        fprintf(stderr, "Failed to resolve address: %s\n", host);
        return INVALID_SOCKET;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        if (rp->ai_family != AF_INET && rp->ai_family != AF_INET6)
        {
            continue;
        }

        sockfd = socket(rp->ai_family, SOCK_DGRAM, 0);
        if (SOCKET_ERROR_CHECK(sockfd))
        {
            last_err = SOCKET_ERRNO;
            continue;
        }

#ifdef _WIN32
        DWORD timeout_ms = (SOCKET_TIMEOUT_SEC * 1000) + (SOCKET_TIMEOUT_USEC / 1000);
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&timeout_ms, sizeof(timeout_ms)) < 0)
        {
            PRINT_SOCKET_ERROR("setsockopt failed");
            CLOSE_SOCKET(sockfd);
            freeaddrinfo(result);
            return INVALID_SOCKET;
        }

        init_wsa_recvmsg(sockfd, &g_wsa_recvmsg);

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
#else
        struct timeval tv;
        tv.tv_sec = SOCKET_TIMEOUT_SEC;
        tv.tv_usec = SOCKET_TIMEOUT_USEC;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0)
        {
            PRINT_SOCKET_ERROR("setsockopt failed");
            CLOSE_SOCKET(sockfd);
            freeaddrinfo(result);
            return INVALID_SOCKET;
        }

        // カーネルタイムスタンプの有効化 (SO_TIMESTAMPNS: ナノ秒精度)
#ifdef SO_TIMESTAMPNS
        {
            int opt = 1;
            (void)setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPNS, &opt, sizeof(opt));
        }
#elif defined(SO_TIMESTAMP)
        {
            int opt = 1;
            (void)setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt));
        }
#endif

#ifdef __linux__
        // SO_BUSY_POLL: ビジーポーリングでレイテンシ削減
#ifdef SO_BUSY_POLL
        {
            int busy_poll = STAMP_BUSY_POLL_USEC;
            (void)setsockopt(sockfd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
        }
#endif

        // SO_TIMESTAMPING: カーネルレベルの送受信タイムスタンプ
#ifdef SO_TIMESTAMPING
        {
            int ts_flags = SOF_TIMESTAMPING_RX_SOFTWARE |
                           SOF_TIMESTAMPING_TX_SOFTWARE |
                           SOF_TIMESTAMPING_SOFTWARE;
            (void)setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &ts_flags, sizeof(ts_flags));
        }
#endif
#endif // __linux__
#endif

        if (connect(sockfd, rp->ai_addr, ADDRLEN_CAST(rp->ai_addrlen)) < 0)
        {
            last_err = SOCKET_ERRNO;
            if (rp->ai_addrlen <= sizeof(last_addr))
            {
                memset(&last_addr, 0, sizeof(last_addr));
                memcpy(&last_addr, rp->ai_addr, rp->ai_addrlen);
                have_last_addr = true;
            }
            CLOSE_SOCKET(sockfd);
            sockfd = INVALID_SOCKET;
            continue;
        }

        memset(servaddr, 0, sizeof(*servaddr));
        memcpy(servaddr, rp->ai_addr, rp->ai_addrlen);
        *servaddr_len = (socklen_t)rp->ai_addrlen;
        freeaddrinfo(result);
        return sockfd;
    }

    freeaddrinfo(result);

    fprintf(stderr, "Failed to connect to any resolved address for %s:%u\n",
            host, (unsigned int)port);
    if (last_err != 0)
    {
        fprintf(stderr, "connect to remote STAMP server failed: error %d\n", last_err);
    }

    if (have_last_addr)
    {
        char addrstr[INET6_ADDRSTRLEN] = {0};
        uint16_t port_tmp = sockaddr_get_port(&last_addr);
        if (sockaddr_to_string(&last_addr, addrstr, sizeof(addrstr)) != NULL)
        {
            fprintf(stderr,
                    "Last attempted address: %s:%u (remote host or network may be unreachable).\n",
                    addrstr, (unsigned int)port_tmp);
        }
    }

    return INVALID_SOCKET;
}

/**
 * STAMPパケットの送信 (RFC 8762 Section 4.2.1)
 * @param sockfd ソケットディスクリプタ
 * @param seq シーケンス番号
 * @param tx_packet 送信パケットのポインタ
 * @return 成功時0、エラー時-1
 */
static int send_stamp_packet(SOCKET sockfd, uint32_t seq,
                             struct stamp_sender_packet *tx_packet)
{
    uint32_t t1_sec, t1_frac;

    // パケットの初期化（RFC 4.2.1 準拠）
    memset(tx_packet, 0, sizeof(*tx_packet));
    tx_packet->seq_num = htonl(seq);
    tx_packet->error_estimate = htons(ERROR_ESTIMATE_DEFAULT);
    // T1: 送信時刻の取得
    if (unlikely(get_ntp_timestamp(&t1_sec, &t1_frac) != 0))
    {
        fprintf(stderr, "Failed to get T1 timestamp\n");
        return -1;
    }
    tx_packet->timestamp_sec = t1_sec;
    tx_packet->timestamp_frac = t1_frac;

    // パケット送信
    if (unlikely(send(sockfd, (const char *)tx_packet, (int)sizeof(*tx_packet), 0) < 0))
    {
        PRINT_SOCKET_ERROR("send failed");
        return -1;
    }

    g_stats.sent++;
    return 0;
}

/**
 * カーネルタイムスタンプ付きでパケットを受信
 * @return 受信バイト数、エラー時-1
 *
 * 注: この関数はホットパスであり、インライン化によりオーバーヘッドを削減する。
 */
static inline __attribute__((always_inline, hot))
int recv_with_timestamp(SOCKET sockfd, uint8_t *buffer, size_t buffer_len,
                        struct sockaddr_storage *servaddr, socklen_t *len,
                        uint32_t *t4_sec, uint32_t *t4_frac)
{
    ssize_t n;

#ifdef _WIN32
    if (g_wsa_recvmsg != NULL)
    {
        WSABUF data_buf;
        WSAMSG msg;
        char control[STAMP_CMSG_BUFSIZE];
        DWORD bytes = 0;

        data_buf.buf = (CHAR *)buffer;
        data_buf.len = (ULONG)buffer_len;
        memset(&msg, 0, sizeof(msg));
        msg.name = (LPSOCKADDR)servaddr;
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
        bool timestamp_found = extract_kernel_timestamp_windows(&msg, t4_sec, t4_frac);

        // カーネルタイムスタンプが取得できなかった場合はユーザースペースタイムスタンプを使用
        if (!timestamp_found)
        {
            get_ntp_timestamp(t4_sec, t4_frac);
        }

        return (int)bytes;
    }
    else
    {
        n = recvfrom(sockfd, (char *)buffer, (int)buffer_len, 0,
                     (struct sockaddr *)servaddr, len);
        if (n > 0)
        {
            get_ntp_timestamp(t4_sec, t4_frac);
        }
        return (int)n;
    }
#else
    struct msghdr msg;
    struct iovec iov;
    char control[STAMP_CMSG_BUFSIZE];

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = buffer_len;
    msg.msg_name = servaddr;
    msg.msg_namelen = *len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    n = recvmsg(sockfd, &msg, 0);
    if (n < 0)
    {
        return -1;
    }

    *len = msg.msg_namelen;

    // カーネルタイムスタンプを抽出（共通関数を使用）
    bool timestamp_found = extract_kernel_timestamp_linux(&msg, t4_sec, t4_frac);

    if (!timestamp_found)
    {
        get_ntp_timestamp(t4_sec, t4_frac);
    }

    return (int)n;
#endif
}

/**
 * STAMPパケットの受信と処理
 * @return 成功時0、エラー時-1
 */
static int receive_and_process_packet(SOCKET sockfd, const struct stamp_sender_packet *tx_packet)
{
    struct stamp_reflector_packet rx_packet;
    struct sockaddr_storage recvaddr;
    socklen_t len = sizeof(recvaddr);
    uint32_t t4_sec = 0, t4_frac = 0;
    uint8_t buffer[STAMP_MAX_PACKET_SIZE];

    // パケット受信（カーネルタイムスタンプ付き）
    int n = recv_with_timestamp(sockfd, buffer, sizeof(buffer), &recvaddr, &len, &t4_sec, &t4_frac);
    if (unlikely(n < 0))
    {
#ifdef _WIN32
        if (SOCKET_ERRNO == WSAETIMEDOUT)
#else
        if (SOCKET_ERRNO == EAGAIN || SOCKET_ERRNO == EWOULDBLOCK)
#endif
        {
            fprintf(stderr, "Timeout waiting for response\n");
            g_stats.timeouts++;
        }
        else
        {
            PRINT_SOCKET_ERROR("recvfrom failed");
        }
        return -1;
    }

    // パケット検証
    if (unlikely(!validate_stamp_packet(buffer, n)))
    {
        fprintf(stderr, "Invalid packet received\n");
        return -1;
    }

    memcpy(&rx_packet, buffer, sizeof(rx_packet));

    // シーケンス番号の確認
    if (unlikely(rx_packet.sender_seq_num != tx_packet->seq_num))
    {
        fprintf(stderr, "Sequence number mismatch: expected %" PRIu32 ", got %" PRIu32 "\n",
                (uint32_t)ntohl(tx_packet->seq_num), (uint32_t)ntohl(rx_packet.sender_seq_num));
        return -1;
    }

    // タイムスタンプの変換と遅延計算
    double t1 = ntp_to_double(tx_packet->timestamp_sec, tx_packet->timestamp_frac);
    double t2 = ntp_to_double(rx_packet.rx_sec, rx_packet.rx_frac);
    double t3 = ntp_to_double(rx_packet.timestamp_sec, rx_packet.timestamp_frac);
    double t4 = ntp_to_double(t4_sec, t4_frac);

    // タイムスタンプの論理的順序を検証
    // 正常な場合: T1 < T2 < T3 < T4
    // ただし、クロックオフセットがある場合 T2, T3 の順序が逆転することがある
    if (t1 > t4)
    {
        fprintf(stderr, "Warning: T1 > T4 detected. Severe clock skew or timestamp error.\n");
        fprintf(stderr, "  T1=%.9f, T2=%.9f, T3=%.9f, T4=%.9f\n", t1, t2, t3, t4);
        fprintf(stderr, "  Difference: %.6f ms\n", (t1 - t4) * 1000.0);
        g_negative_delay_seen = true;
    }

    double forward_delay = (t2 - t1) * 1000.0;
    double backward_delay = (t4 - t3) * 1000.0;
    double rtt = forward_delay + backward_delay;
    double offset = ((t2 - t1) + (t3 - t4)) * 0.5 * 1000.0;

    // オフセット補正した遅延（クロック差を考慮した推定値）
    double adj_forward = forward_delay - offset;
    double adj_backward = backward_delay + offset;

    // 異常値のチェック
    if (forward_delay < 0 || backward_delay < 0)
    {
        g_negative_delay_seen = true;
    }

    // 統計情報の更新
    g_stats.received++;
    g_stats.sum_rtt += rtt;
    if (rtt < g_stats.min_rtt)
        g_stats.min_rtt = rtt;
    if (rtt > g_stats.max_rtt)
        g_stats.max_rtt = rtt;

    // 結果の表示
    printf("%" PRIu32 "\t%.3f\t\t%.3f\t\t%.3f\t%.3f\t\t%.3f\t\t%.3f\n",
           (uint32_t)ntohl(rx_packet.sender_seq_num),
           forward_delay, backward_delay, rtt, offset, adj_forward, adj_backward);

    return 0;
}

int main(int argc, char *argv[])
{
    SOCKET sockfd = INVALID_SOCKET;
    struct sockaddr_storage servaddr;
    socklen_t servaddr_len;
    struct stamp_sender_packet tx_packet;
    uint32_t seq = 0;
    uint16_t port = PORT;
    int af_hint = AF_UNSPEC; // 自動検出（デフォルト）
    int exit_code = 0;

#ifdef _WIN32
    // Windows: ソケット初期化
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // シグナルハンドラの設定
    SetConsoleCtrlHandler(stamp_signal_handler, TRUE);
#else
    // UNIX/Linux: シグナルハンドラの設定
    signal(SIGINT, stamp_signal_handler);
#endif

    // getopt()によるオプションパース
    int opt;
    while ((opt = getopt(argc, argv, "46")) != -1)
    {
        switch (opt)
        {
        case '4':
            af_hint = AF_INET;
            break;
        case '6':
            af_hint = AF_INET6;
            break;
        default:
            print_usage(argc > 0 ? argv[0] : "sender");
            exit_code = 1;
            goto cleanup;
        }
    }

    // 残りの引数の数を確認
    int remaining_args = argc - optind;
    if (remaining_args > 2)
    {
        print_usage(argc > 0 ? argv[0] : "sender");
        exit_code = 1;
        goto cleanup;
    }

    const char *host = (remaining_args > 0) ? argv[optind] : SERVER_IP;
    if (remaining_args > 1 && parse_port(argv[optind + 1], &port) != 0)
    {
        fprintf(stderr, "Invalid port: %s\n", argv[optind + 1]);
        print_usage(argc > 0 ? argv[0] : "sender");
        exit_code = 1;
        goto cleanup;
    }

    // ソケットの初期化
    sockfd = init_socket(host, port, &servaddr, &servaddr_len, af_hint);
    if (SOCKET_ERROR_CHECK(sockfd))
    {
        exit_code = 1;
        goto cleanup;
    }

    // 測定開始メッセージの表示
    {
        char addr_port_str[INET6_ADDRSTRLEN + 8];
        const char *family_str = (servaddr.ss_family == AF_INET6) ? "IPv6" : "IPv4";
        format_sockaddr_with_port(&servaddr, addr_port_str, sizeof(addr_port_str));
        printf("STAMP Sender targeting %s (%s)\n", addr_port_str, family_str);
    }
    printf("Press Ctrl+C to stop and show statistics\n");
    printf("Seq\tFwd(ms)\t\tBwd(ms)\t\tRTT(ms)\tOffset(ms)\t[adj_Fwd]\t[adj_Bwd]\n");
    printf("--------------------------------------------------------------------------------------------\n");

    // メインループ
    while (g_running)
    {
        if (send_stamp_packet(sockfd, seq, &tx_packet) == 0)
        {
            receive_and_process_packet(sockfd, &tx_packet);
        }
        seq++;

#ifdef _WIN32
        // Ctrl+Cで中断できるよう、100ms間隔でスリープしてg_runningをチェック
        {
            int total_ms = SEND_INTERVAL_SEC * 1000;
            int sleep_interval_ms = SLEEP_CHECK_INTERVAL_MS;
            for (int elapsed = 0; elapsed < total_ms && g_running; elapsed += sleep_interval_ms)
            {
                int remaining = total_ms - elapsed;
                int sleep_time = remaining < sleep_interval_ms ? remaining : sleep_interval_ms;
                Sleep((DWORD)sleep_time);
            }
        }
#else
        sleep(SEND_INTERVAL_SEC);
#endif
    }

    // 統計情報の表示
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
