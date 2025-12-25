// RFC 8762 STAMP Sender実装
// 指定されたサーバーに対してSTAMPパケットを送信し、RTTを測定する

#include "stamp.h"

#define PORT STAMP_PORT       // STAMP標準ポート番号
#define SERVER_IP "127.0.0.1" // デフォルトのサーバーIPアドレス（ローカルホスト）
#define SEND_INTERVAL_SEC 1   // 送信間隔（秒）

// エラーメッセージ出力用マクロ
#define PRINT_SOCKET_ERROR(msg) fprintf(stderr, "%s: error %d\n", msg, SOCKET_ERRNO)

// グローバル変数（シグナルハンドラからアクセス）
static volatile int g_running = 1;
static bool g_negative_delay_seen = false;

// 統計情報構造体
struct stats
{
    uint32_t sent;
    uint32_t received;
    uint32_t timeouts;
    double min_rtt;
    double max_rtt;
    double sum_rtt;
};

static struct stats g_stats = {0, 0, 0, 1e9, 0, 0};

/**
 * シグナルハンドラ（Ctrl+C対応）
 */
#ifdef _WIN32
BOOL WINAPI signal_handler(DWORD signal)
{
    if (signal == CTRL_C_EVENT)
    {
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        g_running = 0;
    }
}
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

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [server_ip] [port]\n", prog ? prog : "sender");
}

static int parse_port(const char *arg, uint16_t *port)
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

/**
 * ソケットの初期化とタイムアウト設定 (RFC 8762 Section 3)
 * @param ip サーバーIPアドレス
 * @param port 宛先ポート番号
 * @param servaddr サーバーアドレス構造体のポインタ
 * @return ソケットディスクリプタ、エラー時-1
 */
static int init_socket(const char *ip, uint16_t port, struct sockaddr_in *servaddr)
{
    SOCKET sockfd;

    // UDPソケットの作成
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (SOCKET_ERROR_CHECK(sockfd))
    {
        PRINT_SOCKET_ERROR("socket creation failed");
        return -1;
    }

    // タイムアウト設定
#ifdef _WIN32
    DWORD timeout_ms = (SOCKET_TIMEOUT_SEC * 1000) + (SOCKET_TIMEOUT_USEC / 1000);
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, sizeof(timeout_ms)) < 0)
    {
        PRINT_SOCKET_ERROR("setsockopt failed");
        CLOSE_SOCKET(sockfd);
        return -1;
    }
#else
    struct timeval tv;
    tv.tv_sec = SOCKET_TIMEOUT_SEC;
    tv.tv_usec = SOCKET_TIMEOUT_USEC;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0)
    {
        PRINT_SOCKET_ERROR("setsockopt failed");
        CLOSE_SOCKET(sockfd);
        return -1;
    }
#endif

    // サーバーアドレスの設定
    memset(servaddr, 0, sizeof(*servaddr));
    servaddr->sin_family = AF_INET;
    servaddr->sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &servaddr->sin_addr) <= 0)
    {
        fprintf(stderr, "Invalid address: %s\n", ip);
        CLOSE_SOCKET(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * STAMPパケットの送信 (RFC 8762 Section 4.2.1)
 * @param sockfd ソケットディスクリプタ
 * @param seq シーケンス番号
 * @param servaddr サーバーアドレス
 * @param tx_packet 送信パケットのポインタ
 * @return 成功時0、エラー時-1
 */
static int send_stamp_packet(int sockfd, uint32_t seq, const struct sockaddr_in *servaddr,
                             struct stamp_sender_packet *tx_packet)
{
    uint32_t t1_sec, t1_frac;

    // パケットの初期化（RFC 4.2.1 準拠）
    memset(tx_packet, 0, sizeof(*tx_packet));
    tx_packet->seq_num = htonl(seq);
    tx_packet->error_estimate = htons(0); // MBZ フィールドは既に0で初期化
    // T1: 送信時刻の取得
    if (get_ntp_timestamp(&t1_sec, &t1_frac) != 0)
    {
        fprintf(stderr, "Failed to get T1 timestamp\n");
        return -1;
    }
    tx_packet->timestamp_sec = t1_sec;
    tx_packet->timestamp_frac = t1_frac;

    // パケット送信
    if (sendto(sockfd, (const char *)tx_packet, sizeof(*tx_packet), 0,
               (const struct sockaddr *)servaddr, sizeof(*servaddr)) < 0)
    {
        PRINT_SOCKET_ERROR("sendto failed");
        return -1;
    }

    g_stats.sent++;
    return 0;
}

/**
 * STAMPパケットの受信と処理 (RFC 8762 Section 4.2)
 * @param sockfd ソケットディスクリプタ
 * @param tx_packet 送信パケット
 * @param servaddr サーバーアドレス
 * @return 成功時0、エラー時-1
 */
static int receive_and_process_packet(int sockfd, const struct stamp_sender_packet *tx_packet,
                                      struct sockaddr_in *servaddr)
{
    struct stamp_reflector_packet rx_packet;
    socklen_t len = sizeof(*servaddr);
    uint32_t t4_sec, t4_frac;
    uint8_t buffer[STAMP_MAX_PACKET_SIZE];

    // パケット受信
    int n = recvfrom(sockfd, (char *)buffer, sizeof(buffer), 0,
                     (struct sockaddr *)servaddr, &len);
    if (n < 0)
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

    // T4: 受信時刻の取得
    if (get_ntp_timestamp(&t4_sec, &t4_frac) != 0)
    {
        fprintf(stderr, "Failed to get T4 timestamp\n");
        return -1;
    }

    // パケット検証
    if (!validate_stamp_packet(buffer, n))
    {
        fprintf(stderr, "Invalid packet received\n");
        return -1;
    }
    memcpy(&rx_packet, buffer, sizeof(rx_packet));

    // シーケンス番号の確認
    if (rx_packet.sender_seq_num != tx_packet->seq_num)
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

    double forward_delay = (t2 - t1) * 1000.0;
    double backward_delay = (t4 - t3) * 1000.0;
    double rtt = forward_delay + backward_delay;
    double offset = ((t2 - t1) + (t3 - t4)) * 0.5 * 1000.0;

    // 異常値のチェック
    if (forward_delay < 0 || backward_delay < 0)
    {
        fprintf(stderr, "Warning: Negative delay detected (clock skew?)\n");
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
    printf("%" PRIu32 "\t%.3f\t\t%.3f\t\t%.3f\t\t%.3f\n",
           (uint32_t)ntohl(rx_packet.sender_seq_num), forward_delay, backward_delay, rtt, offset);

    return 0;
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in servaddr;
    struct stamp_sender_packet tx_packet;
    uint32_t seq = 0;
    uint16_t port = PORT;

#ifdef _WIN32
    // Windows: ソケット初期化
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // シグナルハンドラの設定
    SetConsoleCtrlHandler(signal_handler, TRUE);
#else
    // UNIX/Linux: シグナルハンドラの設定
    signal(SIGINT, signal_handler);
#endif

    // コマンドライン引数からIPアドレスを取得（なければデフォルト使用）
    if (argc > 3)
    {
        print_usage(argc > 0 ? argv[0] : "sender");
        return 1;
    }

    const char *ip = (argc > 1) ? argv[1] : SERVER_IP;
    if (argc > 2 && parse_port(argv[2], &port) != 0)
    {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        print_usage(argc > 0 ? argv[0] : "sender");
        return 1;
    }

    // ソケットの初期化
    sockfd = init_socket(ip, port, &servaddr);
    if (sockfd < 0)
    {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // 測定開始メッセージの表示
    printf("STAMP Sender targeting %s:%u\n", ip, port);
    printf("Press Ctrl+C to stop and show statistics\n");
    printf("Seq\tForward(ms)\tBackward(ms)\tRTT(ms)\tOffset(ms)\n");
    printf("----------------------------------------------------------------\n");

    // メインループ
    while (g_running)
    {
        if (send_stamp_packet(sockfd, seq, &servaddr, &tx_packet) == 0)
        {
            receive_and_process_packet(sockfd, &tx_packet, &servaddr);
        }
        seq++;

#ifdef _WIN32
        Sleep(SEND_INTERVAL_SEC * 1000);
#else
        sleep(SEND_INTERVAL_SEC);
#endif
    }

    // 統計情報の表示
    print_statistics();

    // クリーンアップ
    CLOSE_SOCKET(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
