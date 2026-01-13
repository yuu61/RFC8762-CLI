// RFC 8762 STAMP ユニットテスト
#include "../src/stamp.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define EXPECT_TRUE(cond, msg)         \
    do                                 \
    {                                  \
        g_tests_run++;                 \
        if (!(cond))                   \
        {                              \
            printf("FAIL: %s\n", msg); \
            g_tests_failed++;          \
        }                              \
    } while (0)

#define EXPECT_EQ_ULL(actual, expected, msg)                          \
    do                                                                \
    {                                                                 \
        unsigned long long a = (unsigned long long)(actual);          \
        unsigned long long e = (unsigned long long)(expected);        \
        g_tests_run++;                                                \
        if (a != e)                                                   \
        {                                                             \
            printf("FAIL: %s (got %llu expected %llu)\n", msg, a, e); \
            g_tests_failed++;                                         \
        }                                                             \
    } while (0)

#define EXPECT_NEAR_DOUBLE(actual, expected, eps, msg)    \
    do                                                    \
    {                                                     \
        double a = (actual);                              \
        double e = (expected);                            \
        g_tests_run++;                                    \
        if (fabs(a - e) > (eps))                          \
        {                                                 \
            printf("FAIL: %s (got %.9f expected %.9f)\n", \
                   msg, a, e);                            \
            g_tests_failed++;                             \
        }                                                 \
    } while (0)

#define SKIP_TEST(msg)           \
    do                           \
    {                            \
        printf("SKIP: %s\n", msg); \
    } while (0)

#ifdef _WIN32
static int init_winsock(void)
{
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}
#endif

static int ipv6_available(void)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
#ifdef AI_NUMERICHOST
    hints.ai_flags = AI_NUMERICHOST;
#endif

    rc = getaddrinfo("::1", "0", &hints, &result);
    if (rc != 0)
    {
        return 0;
    }
    freeaddrinfo(result);
    return 1;
}

static void test_constants(void)
{
    EXPECT_EQ_ULL(STAMP_PORT, 862, "STAMP_PORT");
    EXPECT_EQ_ULL(STAMP_BASE_PACKET_SIZE, 44, "STAMP_BASE_PACKET_SIZE");
    EXPECT_TRUE(STAMP_MAX_PACKET_SIZE >= STAMP_BASE_PACKET_SIZE,
                "STAMP_MAX_PACKET_SIZE >= STAMP_BASE_PACKET_SIZE");
    EXPECT_EQ_ULL(NTP_OFFSET, 2208988800UL, "NTP_OFFSET");

    // Error Estimate constants (RFC 4656 Section 4.1.2)
    EXPECT_EQ_ULL(ERROR_ESTIMATE_S_BIT, 0x8000, "ERROR_ESTIMATE_S_BIT");
    EXPECT_EQ_ULL(ERROR_ESTIMATE_Z_BIT, 0x4000, "ERROR_ESTIMATE_Z_BIT");
    EXPECT_EQ_ULL(ERROR_ESTIMATE_DEFAULT & ERROR_ESTIMATE_S_BIT, 0x8000,
                  "ERROR_ESTIMATE_DEFAULT has S=1");
    EXPECT_EQ_ULL(ERROR_ESTIMATE_DEFAULT & ERROR_ESTIMATE_Z_BIT, 0,
                  "ERROR_ESTIMATE_DEFAULT has Z=0 (NTP)");
}

static void test_struct_layout(void)
{
    EXPECT_EQ_ULL(sizeof(struct stamp_sender_packet),
                  STAMP_BASE_PACKET_SIZE,
                  "stamp_sender_packet size");
    EXPECT_EQ_ULL(sizeof(struct stamp_reflector_packet),
                  STAMP_BASE_PACKET_SIZE,
                  "stamp_reflector_packet size");

    EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, timestamp_sec), 4,
                  "sender.timestamp_sec offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, timestamp_frac), 8,
                  "sender.timestamp_frac offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, error_estimate), 12,
                  "sender.error_estimate offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, mbz), 14,
                  "sender.mbz offset");

    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, timestamp_sec), 4,
                  "reflector.timestamp_sec offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, timestamp_frac), 8,
                  "reflector.timestamp_frac offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, error_estimate), 12,
                  "reflector.error_estimate offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, rx_sec), 16,
                  "reflector.rx_sec offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, rx_frac), 20,
                  "reflector.rx_frac offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, sender_seq_num), 24,
                  "reflector.sender_seq_num offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, sender_err_est), 36,
                  "reflector.sender_err_est offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, sender_ttl), 40,
                  "reflector.sender_ttl offset");
}

static void test_validate_stamp_packet(void)
{
    uint8_t buffer[STAMP_BASE_PACKET_SIZE + 4];

    memset(buffer, 0, sizeof(buffer));
    EXPECT_TRUE(validate_stamp_packet(buffer, STAMP_BASE_PACKET_SIZE) == 1,
                "validate base size");
    EXPECT_TRUE(validate_stamp_packet(buffer, STAMP_BASE_PACKET_SIZE + 1) == 1,
                "validate larger size");
    EXPECT_TRUE(validate_stamp_packet(buffer, STAMP_BASE_PACKET_SIZE - 1) == 0,
                "validate too small");
    // NULLテストは削除: nonnull属性により未定義動作となるため
}

static void test_ntp_to_double(void)
{
    uint32_t sec = htonl(NTP_OFFSET);
    uint32_t frac = htonl(0);
    double t0 = ntp_to_double(sec, frac);
    EXPECT_NEAR_DOUBLE(t0, 0.0, 1e-9, "ntp_to_double epoch");

    sec = htonl(NTP_OFFSET + 1);
    frac = htonl(0x80000000u);
    t0 = ntp_to_double(sec, frac);
    EXPECT_NEAR_DOUBLE(t0, 1.5, 1e-9, "ntp_to_double 1.5s");
}

static void test_get_ntp_timestamp(void)
{
    uint32_t sec = 0;
    uint32_t frac = 0;
    int rc = get_ntp_timestamp(&sec, &frac);
    EXPECT_TRUE(rc == 0, "get_ntp_timestamp returns 0");

    double t_unix = ntp_to_double(sec, frac);
    time_t now = time(NULL);
    EXPECT_TRUE(fabs(t_unix - (double)now) < 1.0, "ntp timestamp close to wall clock");
    // NULLテストは削除: nonnull属性により未定義動作となるため
}

static void test_byte_order(void)
{
    struct stamp_sender_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    // seq_num byte order
    pkt.seq_num = htonl(12345);
    EXPECT_EQ_ULL(ntohl(pkt.seq_num), 12345, "seq_num byte order");

    // timestamp byte order
    pkt.timestamp_sec = htonl(0x12345678);
    EXPECT_EQ_ULL(ntohl(pkt.timestamp_sec), 0x12345678, "timestamp_sec byte order");

    pkt.timestamp_frac = htonl(0xABCDEF00);
    EXPECT_EQ_ULL(ntohl(pkt.timestamp_frac), 0xABCDEF00, "timestamp_frac byte order");

    // error_estimate byte order
    pkt.error_estimate = htons(0x1234);
    EXPECT_EQ_ULL(ntohs(pkt.error_estimate), 0x1234, "error_estimate byte order");
}

static void test_parse_port(void)
{
    uint16_t port;
    int rc;

    rc = parse_port("862", &port);
    EXPECT_TRUE(rc == 0, "parse_port 862 success");
    EXPECT_EQ_ULL(port, 862, "parse_port 862 value");

    rc = parse_port("1", &port);
    EXPECT_TRUE(rc == 0, "parse_port min port success");
    EXPECT_EQ_ULL(port, 1, "parse_port min port value");

    rc = parse_port("65535", &port);
    EXPECT_TRUE(rc == 0, "parse_port max port success");
    EXPECT_EQ_ULL(port, 65535, "parse_port max port value");

    rc = parse_port("8080", &port);
    EXPECT_TRUE(rc == 0, "parse_port 8080 success");
    EXPECT_EQ_ULL(port, 8080, "parse_port 8080 value");

    rc = parse_port("0862", &port);
    EXPECT_TRUE(rc == 0, "parse_port leading zero success");
    EXPECT_EQ_ULL(port, 862, "parse_port leading zero value");

    EXPECT_TRUE(parse_port("0", &port) != 0, "parse_port 0 rejected");
    EXPECT_TRUE(parse_port("65536", &port) != 0, "parse_port 65536 rejected");
    EXPECT_TRUE(parse_port("100000", &port) != 0, "parse_port overflow rejected");
    EXPECT_TRUE(parse_port("", &port) != 0, "parse_port empty rejected");
    EXPECT_TRUE(parse_port("123abc", &port) != 0, "parse_port trailing chars rejected");
    EXPECT_TRUE(parse_port("abc", &port) != 0, "parse_port non-numeric rejected");
    EXPECT_TRUE(parse_port("-1", &port) != 0, "parse_port negative rejected");
}

// IPv6対応ユーティリティ関数のテスト
static void test_get_sockaddr_len(void)
{
    EXPECT_EQ_ULL(get_sockaddr_len(AF_INET), sizeof(struct sockaddr_in),
                  "get_sockaddr_len AF_INET");
    EXPECT_EQ_ULL(get_sockaddr_len(AF_INET6), sizeof(struct sockaddr_in6),
                  "get_sockaddr_len AF_INET6");

    // 不正なファミリはIPv4サイズにフォールバック
    EXPECT_EQ_ULL(get_sockaddr_len(AF_UNSPEC), sizeof(struct sockaddr_in),
                  "get_sockaddr_len AF_UNSPEC fallback");
    EXPECT_EQ_ULL(get_sockaddr_len(999), sizeof(struct sockaddr_in),
                  "get_sockaddr_len invalid family fallback");
}

static void test_sockaddr_get_port(void)
{
    struct sockaddr_storage ss;

    // IPv4
    memset(&ss, 0, sizeof(ss));
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(862);
    }
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 862, "sockaddr_get_port IPv4");

    // IPv6
    memset(&ss, 0, sizeof(ss));
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(8080);
    }
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 8080, "sockaddr_get_port IPv6");

    // NULL
    EXPECT_EQ_ULL(sockaddr_get_port(NULL), 0, "sockaddr_get_port NULL");

    // 不正なファミリ
    memset(&ss, 0, sizeof(ss));
    ss.ss_family = AF_UNSPEC;
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 0, "sockaddr_get_port AF_UNSPEC");

    memset(&ss, 0, sizeof(ss));
    ss.ss_family = 999;
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 0, "sockaddr_get_port invalid family");
}

static void test_sockaddr_to_string(void)
{
    struct sockaddr_storage ss;
    char buf[INET6_ADDRSTRLEN];
    int ipv6_ok = ipv6_available();

    // IPv4
    memset(&ss, 0, sizeof(ss));
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &sin->sin_addr);
    }
    EXPECT_TRUE(sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
                "sockaddr_to_string IPv4 success");
    EXPECT_TRUE(strcmp(buf, "127.0.0.1") == 0, "sockaddr_to_string IPv4 value");

    // IPv4 別のアドレス
    memset(&ss, 0, sizeof(ss));
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        inet_pton(AF_INET, "192.168.1.1", &sin->sin_addr);
    }
    EXPECT_TRUE(sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
                "sockaddr_to_string IPv4 192.168.1.1 success");
    EXPECT_TRUE(strcmp(buf, "192.168.1.1") == 0, "sockaddr_to_string IPv4 192.168.1.1 value");

    if (ipv6_ok)
    {
        // IPv6 loopback
        memset(&ss, 0, sizeof(ss));
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            sin6->sin6_family = AF_INET6;
            inet_pton(AF_INET6, "::1", &sin6->sin6_addr);
        }
        EXPECT_TRUE(sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
                    "sockaddr_to_string IPv6 loopback success");
        EXPECT_TRUE(strcmp(buf, "::1") == 0, "sockaddr_to_string IPv6 loopback value");

        // IPv6 full address
        memset(&ss, 0, sizeof(ss));
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            sin6->sin6_family = AF_INET6;
            inet_pton(AF_INET6, "2001:db8::1", &sin6->sin6_addr);
        }
        EXPECT_TRUE(sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
                    "sockaddr_to_string IPv6 2001:db8::1 success");
        EXPECT_TRUE(strcmp(buf, "2001:db8::1") == 0, "sockaddr_to_string IPv6 2001:db8::1 value");
    }
    else
    {
        SKIP_TEST("sockaddr_to_string IPv6 not available");
    }

    // NULLテストは削除: nonnull属性により未定義動作となるため

    // buflen = 0
    EXPECT_TRUE(sockaddr_to_string(&ss, buf, 0) == NULL,
                "sockaddr_to_string buflen 0");

    // 不正なファミリ
    memset(&ss, 0, sizeof(ss));
    ss.ss_family = AF_UNSPEC;
    EXPECT_TRUE(sockaddr_to_string(&ss, buf, sizeof(buf)) == NULL,
                "sockaddr_to_string AF_UNSPEC");

    memset(&ss, 0, sizeof(ss));
    ss.ss_family = 999;
    EXPECT_TRUE(sockaddr_to_string(&ss, buf, sizeof(buf)) == NULL,
                "sockaddr_to_string invalid family");
}

// IPv6ソケット通信の実際のテスト
static void test_ipv6_socket_communication(void)
{
    int ipv6_ok = ipv6_available();
    if (!ipv6_ok)
    {
        SKIP_TEST("IPv6 socket communication (IPv6 not available)");
        return;
    }

    // 送信側ソケット作成
    SOCKET send_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (SOCKET_ERROR_CHECK(send_sock))
    {
        SKIP_TEST("IPv6 socket communication (socket creation failed)");
        return;
    }

    // 受信側ソケット作成とバインド
    SOCKET recv_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (SOCKET_ERROR_CHECK(recv_sock))
    {
        CLOSE_SOCKET(send_sock);
        SKIP_TEST("IPv6 socket communication (recv socket creation failed)");
        return;
    }

    // IPv6ループバックアドレスにバインド
    struct sockaddr_in6 recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin6_family = AF_INET6;
    recv_addr.sin6_addr = in6addr_loopback;
    recv_addr.sin6_port = htons(0); // OSに自動割り当てさせる

    if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0)
    {
        CLOSE_SOCKET(send_sock);
        CLOSE_SOCKET(recv_sock);
        SKIP_TEST("IPv6 socket communication (bind failed)");
        return;
    }

    // バインドされたポート番号を取得
    socklen_t addr_len = sizeof(recv_addr);
    if (getsockname(recv_sock, (struct sockaddr *)&recv_addr, &addr_len) < 0)
    {
        CLOSE_SOCKET(send_sock);
        CLOSE_SOCKET(recv_sock);
        SKIP_TEST("IPv6 socket communication (getsockname failed)");
        return;
    }

    uint16_t test_port = ntohs(recv_addr.sin6_port);

    // 送信先アドレス設定
    struct sockaddr_in6 dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    dest_addr.sin6_addr = in6addr_loopback;
    dest_addr.sin6_port = htons(test_port);

    // テストデータ送信
    const char test_msg[] = "IPv6 test message";
    ssize_t send_result = sendto(send_sock, test_msg, strlen(test_msg), 0,
                                 (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    EXPECT_TRUE(send_result > 0, "IPv6 sendto success");

    if (send_result > 0)
    {
        // 受信テスト (タイムアウト設定)
#ifdef _WIN32
        DWORD timeout_ms = 1000;
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, sizeof(timeout_ms));
#else
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

        char recv_buf[256];
        struct sockaddr_in6 from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t recv_result = recvfrom(recv_sock, recv_buf, sizeof(recv_buf) - 1, 0,
                                       (struct sockaddr *)&from_addr, &from_len);

        EXPECT_TRUE(recv_result > 0, "IPv6 recvfrom success");
        if (recv_result > 0)
        {
            recv_buf[recv_result] = '\0';
            EXPECT_TRUE(strcmp(recv_buf, test_msg) == 0, "IPv6 message content match");
            EXPECT_EQ_ULL(from_addr.sin6_family, AF_INET6, "IPv6 from_addr family");
        }
    }

    CLOSE_SOCKET(send_sock);
    CLOSE_SOCKET(recv_sock);
}

static void test_resolve_address(void)
{
    struct sockaddr_storage ss;
    socklen_t len;
    int ipv6_ok = ipv6_available();

    // IPv4 loopback
    len = 0;
    EXPECT_TRUE(resolve_address("127.0.0.1", 862, AF_INET, &ss, &len) == 0,
                "resolve_address IPv4 loopback");
    EXPECT_EQ_ULL(ss.ss_family, AF_INET, "resolve_address IPv4 family");
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 862, "resolve_address IPv4 port");
    EXPECT_EQ_ULL(len, sizeof(struct sockaddr_in), "resolve_address IPv4 len");

    if (ipv6_ok)
    {
        // IPv6 loopback
        len = 0;
        EXPECT_TRUE(resolve_address("::1", 862, AF_INET6, &ss, &len) == 0,
                    "resolve_address IPv6 loopback");
        EXPECT_EQ_ULL(ss.ss_family, AF_INET6, "resolve_address IPv6 family");
        EXPECT_EQ_ULL(sockaddr_get_port(&ss), 862, "resolve_address IPv6 port");
        EXPECT_EQ_ULL(len, sizeof(struct sockaddr_in6), "resolve_address IPv6 len");
    }
    else
    {
        SKIP_TEST("resolve_address IPv6 loopback");
    }

    // AF_UNSPEC (自動検出) - IPv4アドレス
    len = 0;
    EXPECT_TRUE(resolve_address("127.0.0.1", 8080, AF_UNSPEC, &ss, &len) == 0,
                "resolve_address AF_UNSPEC with IPv4");
    EXPECT_EQ_ULL(ss.ss_family, AF_INET, "resolve_address AF_UNSPEC IPv4 family");
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 8080, "resolve_address AF_UNSPEC IPv4 port");

    // AF_UNSPEC (自動検出) - IPv6アドレス
    if (ipv6_ok)
    {
        len = 0;
        EXPECT_TRUE(resolve_address("::1", 8080, AF_UNSPEC, &ss, &len) == 0,
                    "resolve_address AF_UNSPEC with IPv6");
        EXPECT_EQ_ULL(ss.ss_family, AF_INET6, "resolve_address AF_UNSPEC IPv6 family");
        EXPECT_EQ_ULL(sockaddr_get_port(&ss), 8080, "resolve_address AF_UNSPEC IPv6 port");
    }
    else
    {
        SKIP_TEST("resolve_address AF_UNSPEC IPv6");
    }

    // ホスト名解決 (localhost)
    len = 0;
    EXPECT_TRUE(resolve_address("localhost", 862, AF_INET, &ss, &len) == 0,
                "resolve_address localhost IPv4");
    EXPECT_EQ_ULL(ss.ss_family, AF_INET, "resolve_address localhost family");
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 862, "resolve_address localhost port");

    // 異なるポート番号
    len = 0;
    EXPECT_TRUE(resolve_address("127.0.0.1", 65535, AF_INET, &ss, &len) == 0,
                "resolve_address max port");
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 65535, "resolve_address max port value");

    len = 0;
    EXPECT_TRUE(resolve_address("127.0.0.1", 1, AF_INET, &ss, &len) == 0,
                "resolve_address min port");
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 1, "resolve_address min port value");

    // Invalid address
    EXPECT_TRUE(resolve_address("invalid.invalid", 862, AF_INET, &ss, &len) != 0,
                "resolve_address invalid hostname");

    // NULLテストは削除: nonnull属性により未定義動作となるため

    // ファミリ不一致
    EXPECT_TRUE(resolve_address("127.0.0.1", 862, AF_INET6, &ss, &len) != 0,
                "resolve_address IPv4 addr with AF_INET6");
    if (ipv6_ok)
    {
        EXPECT_TRUE(resolve_address("::1", 862, AF_INET, &ss, &len) != 0,
                    "resolve_address IPv6 addr with AF_INET");
    }
    else
    {
        SKIP_TEST("resolve_address IPv6 addr with AF_INET");
    }
}

// Windows用 stamp_getopt() のユニットテスト
#ifdef _WIN32
// getoptの状態をリセットするヘルパー関数
static void reset_getopt_state(void)
{
    stamp_optind = 1;
    stamp_optarg = NULL;
    stamp_optopt = 0;
}

static void test_stamp_getopt(void)
{
    int opt;

    // テスト1: 基本的なオプション "-4"
    {
        char *argv[] = {"prog", "-4", NULL};
        int argc = 2;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == '4', "getopt: -4 returns '4'");
        EXPECT_EQ_ULL(stamp_optind, 2, "getopt: -4 advances optind to 2");

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == -1, "getopt: returns -1 after all options");
    }

    // テスト2: 複数オプション "-4 -6"
    {
        char *argv[] = {"prog", "-4", "-6", NULL};
        int argc = 3;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == '4', "getopt: first -4");
        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == '6', "getopt: then -6");
        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == -1, "getopt: -1 after all");
    }

    // テスト3: 引数付きオプション "-p 8080"
    {
        char *argv[] = {"prog", "-p", "8080", NULL};
        int argc = 3;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "p:");
        EXPECT_TRUE(opt == 'p', "getopt: -p returns 'p'");
        EXPECT_TRUE(stamp_optarg != NULL && strcmp(stamp_optarg, "8080") == 0,
                    "getopt: -p optarg is 8080");
        EXPECT_EQ_ULL(stamp_optind, 3, "getopt: -p 8080 advances optind to 3");
    }

    // テスト4: 引数がオプションに連結 "-p8080"
    {
        char *argv[] = {"prog", "-p8080", NULL};
        int argc = 2;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "p:");
        EXPECT_TRUE(opt == 'p', "getopt: -p8080 returns 'p'");
        EXPECT_TRUE(stamp_optarg != NULL && strcmp(stamp_optarg, "8080") == 0,
                    "getopt: -p8080 optarg is 8080");
    }

    // テスト5: "--" 終端マーカー
    {
        char *argv[] = {"prog", "-4", "--", "-6", NULL};
        int argc = 4;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == '4', "getopt: -4 before --");
        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == -1, "getopt: -- terminates options");
        EXPECT_EQ_ULL(stamp_optind, 3, "getopt: -- leaves optind at 3");
    }

    // テスト6: 無効なオプション
    {
        char *argv[] = {"prog", "-x", NULL};
        int argc = 2;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == '?', "getopt: -x returns '?'");
        EXPECT_TRUE(stamp_optopt == 'x', "getopt: optopt is 'x'");
    }

    // テスト7: 必要な引数がない
    {
        char *argv[] = {"prog", "-p", NULL};
        int argc = 2;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "p:");
        EXPECT_TRUE(opt == '?', "getopt: -p without arg returns '?'");
        EXPECT_TRUE(stamp_optopt == 'p', "getopt: optopt is 'p'");
    }

    // テスト8: 余分な文字を拒否 "-4extra"
    {
        char *argv[] = {"prog", "-4extra", NULL};
        int argc = 2;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == '?', "getopt: -4extra returns '?'");
        EXPECT_TRUE(stamp_optopt == '4', "getopt: optopt is '4'");
    }

    // テスト9: オプションなしの引数
    {
        char *argv[] = {"prog", "arg1", "arg2", NULL};
        int argc = 3;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == -1, "getopt: non-option returns -1");
        EXPECT_EQ_ULL(stamp_optind, 1, "getopt: optind stays at 1");
    }

    // テスト10: 空の引数リスト
    {
        char *argv[] = {"prog", NULL};
        int argc = 1;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == -1, "getopt: no args returns -1");
    }

    // テスト11: "-" のみ（オプションではない）
    {
        char *argv[] = {"prog", "-", NULL};
        int argc = 2;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == -1, "getopt: single dash returns -1");
    }

    // テスト12: オプションと位置引数の混在
    {
        char *argv[] = {"prog", "-4", "192.168.1.1", "8080", NULL};
        int argc = 4;
        reset_getopt_state();

        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == '4', "getopt: -4 with trailing args");
        opt = stamp_getopt(argc, argv, "46");
        EXPECT_TRUE(opt == -1, "getopt: stops at non-option");
        EXPECT_EQ_ULL(stamp_optind, 2, "getopt: optind at first non-option");
    }
}
#endif

// =============================================================================
// Phase 1: NTP変換マクロのテスト
// =============================================================================

static void test_nsec_to_ntp_frac(void)
{
    // 境界値テスト: 0
    EXPECT_EQ_ULL(NSEC_TO_NTP_FRAC(0), 0, "NSEC_TO_NTP_FRAC(0)");

    // 0.5秒 = 500,000,000 ナノ秒 → NTP小数部 0x80000000
    uint32_t half_sec = NSEC_TO_NTP_FRAC(500000000);
    EXPECT_TRUE(half_sec >= 0x7FFFFFFF && half_sec <= 0x80000001,
                "NSEC_TO_NTP_FRAC(500000000) ≈ 0x80000000");

    // 最大値（1秒未満）= 999,999,999 ナノ秒
    uint32_t max_nsec = NSEC_TO_NTP_FRAC(999999999);
    EXPECT_TRUE(max_nsec >= 0xFFFFFFFC, "NSEC_TO_NTP_FRAC(999999999) near max");

    // 精度テスト: 1ナノ秒 ≈ 4.29 NTP単位
    uint32_t one_nsec = NSEC_TO_NTP_FRAC(1);
    EXPECT_TRUE(one_nsec >= 4 && one_nsec <= 5, "NSEC_TO_NTP_FRAC(1) ≈ 4-5");

    // 1ミリ秒 = 1,000,000 ナノ秒 ≈ 4,294,967 NTP単位
    uint32_t one_ms = NSEC_TO_NTP_FRAC(1000000);
    EXPECT_TRUE(one_ms >= 4294960 && one_ms <= 4294975,
                "NSEC_TO_NTP_FRAC(1000000) ≈ 4294967");

    // 0.25秒 = 250,000,000 ナノ秒 → 0x40000000
    uint32_t quarter_sec = NSEC_TO_NTP_FRAC(250000000);
    EXPECT_TRUE(quarter_sec >= 0x3FFFFFFF && quarter_sec <= 0x40000001,
                "NSEC_TO_NTP_FRAC(250000000) ≈ 0x40000000");
}

static void test_usec_to_ntp_frac(void)
{
    // 境界値テスト: 0
    EXPECT_EQ_ULL(USEC_TO_NTP_FRAC(0), 0, "USEC_TO_NTP_FRAC(0)");

    // 0.5秒 = 500,000 マイクロ秒 → NTP小数部 0x80000000
    uint32_t half_sec = USEC_TO_NTP_FRAC(500000);
    EXPECT_TRUE(half_sec >= 0x7FFFFFFF && half_sec <= 0x80000001,
                "USEC_TO_NTP_FRAC(500000) ≈ 0x80000000");

    // 最大値（1秒未満）= 999,999 マイクロ秒
    uint32_t max_usec = USEC_TO_NTP_FRAC(999999);
    EXPECT_TRUE(max_usec >= 0xFFFFEF00, "USEC_TO_NTP_FRAC(999999) near max");

    // 1マイクロ秒 ≈ 4295 NTP単位
    uint32_t one_usec = USEC_TO_NTP_FRAC(1);
    EXPECT_TRUE(one_usec >= 4294 && one_usec <= 4296,
                "USEC_TO_NTP_FRAC(1) ≈ 4295");

    // 0.25秒 = 250,000 マイクロ秒 → 0x40000000
    uint32_t quarter_sec = USEC_TO_NTP_FRAC(250000);
    EXPECT_TRUE(quarter_sec >= 0x3FFFFFFF && quarter_sec <= 0x40000001,
                "USEC_TO_NTP_FRAC(250000) ≈ 0x40000000");
}

#ifdef _WIN32
static void test_windows_100ns_to_ntp_frac(void)
{
    // 0
    EXPECT_EQ_ULL(WINDOWS_100NS_TO_NTP_FRAC(0), 0,
                  "WINDOWS_100NS_TO_NTP_FRAC(0)");

    // 0.5秒 = 5,000,000 (100ナノ秒単位)
    uint32_t half_sec = WINDOWS_100NS_TO_NTP_FRAC(5000000);
    EXPECT_TRUE(half_sec >= 0x7FFFFFFF && half_sec <= 0x80000001,
                "WINDOWS_100NS_TO_NTP_FRAC(5000000) ≈ 0x80000000");

    // 1秒未満最大 = 9,999,999 (100ナノ秒単位) = 0.9999999秒
    // 0.9999999秒 * 2^32 / 1秒 ≈ 4,294,962,867 ≈ 0xFFFFFB73
    uint32_t max_val = WINDOWS_100NS_TO_NTP_FRAC(9999999);
    EXPECT_TRUE(max_val >= 0xFFFFF000,
                "WINDOWS_100NS_TO_NTP_FRAC(9999999) near max");

    // 0.25秒 = 2,500,000 (100ナノ秒単位)
    uint32_t quarter_sec = WINDOWS_100NS_TO_NTP_FRAC(2500000);
    EXPECT_TRUE(quarter_sec >= 0x3FFFFFFF && quarter_sec <= 0x40000001,
                "WINDOWS_100NS_TO_NTP_FRAC(2500000) ≈ 0x40000000");
}
#endif

// =============================================================================
// Phase 2: timespec/timeval変換テスト (UNIX/Linux)
// =============================================================================

#ifndef _WIN32
static void test_timespec_to_ntp(void)
{
    uint32_t sec, frac;

    // Unix epoch (1970-01-01 00:00:00.0)
    struct timespec ts_epoch = {0, 0};
    timespec_to_ntp(&ts_epoch, &sec, &frac);
    EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET, "timespec_to_ntp epoch sec");
    EXPECT_EQ_ULL(ntohl(frac), 0, "timespec_to_ntp epoch frac");

    // 1.5秒後
    struct timespec ts_1_5 = {1, 500000000};
    timespec_to_ntp(&ts_1_5, &sec, &frac);
    EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET + 1, "timespec_to_ntp 1.5s sec");
    uint32_t frac_host = ntohl(frac);
    EXPECT_TRUE(frac_host >= 0x7FFFFFFF && frac_host <= 0x80000001,
                "timespec_to_ntp 1.5s frac ≈ 0x80000000");

    // 境界値: tv_nsec = 999999999
    struct timespec ts_max_frac = {100, 999999999};
    timespec_to_ntp(&ts_max_frac, &sec, &frac);
    EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET + 100, "timespec_to_ntp max_frac sec");
    EXPECT_TRUE(ntohl(frac) >= 0xFFFFFFFC, "timespec_to_ntp max_frac frac near max");

    // 大きな秒数
    struct timespec ts_large = {1000000, 0};
    timespec_to_ntp(&ts_large, &sec, &frac);
    EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET + 1000000, "timespec_to_ntp large sec");
}

static void test_timeval_to_ntp(void)
{
    uint32_t sec, frac;

    // Unix epoch
    struct timeval tv_epoch = {0, 0};
    timeval_to_ntp(&tv_epoch, &sec, &frac);
    EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET, "timeval_to_ntp epoch sec");
    EXPECT_EQ_ULL(ntohl(frac), 0, "timeval_to_ntp epoch frac");

    // 1.5秒後
    struct timeval tv_1_5 = {1, 500000};
    timeval_to_ntp(&tv_1_5, &sec, &frac);
    EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET + 1, "timeval_to_ntp 1.5s sec");
    uint32_t frac_host = ntohl(frac);
    EXPECT_TRUE(frac_host >= 0x7FFFFFFF && frac_host <= 0x80000001,
                "timeval_to_ntp 1.5s frac ≈ 0x80000000");

    // 境界値: tv_usec = 999999
    struct timeval tv_max_frac = {100, 999999};
    timeval_to_ntp(&tv_max_frac, &sec, &frac);
    EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET + 100, "timeval_to_ntp max_frac sec");
    EXPECT_TRUE(ntohl(frac) >= 0xFFFFEF00, "timeval_to_ntp max_frac frac near max");
}
#endif

// =============================================================================
// Phase 3: sockaddrユーティリティ追加テスト
// =============================================================================

static void test_sockaddr_to_string_safe(void)
{
    struct sockaddr_storage ss;
    char buf[INET6_ADDRSTRLEN];

    // 正常ケース（IPv4）
    memset(&ss, 0, sizeof(ss));
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        inet_pton(AF_INET, "10.0.0.1", &sin->sin_addr);
    }
    EXPECT_TRUE(strcmp(sockaddr_to_string_safe(&ss, buf, sizeof(buf)),
                       "10.0.0.1") == 0,
                "sockaddr_to_string_safe valid IPv4");

    // NULLバッファ
    EXPECT_TRUE(strcmp(sockaddr_to_string_safe(&ss, NULL, 0), "<unknown>") == 0,
                "sockaddr_to_string_safe NULL buffer");

    // バッファサイズ0
    EXPECT_TRUE(strcmp(sockaddr_to_string_safe(&ss, buf, 0), "<unknown>") == 0,
                "sockaddr_to_string_safe buflen 0");

    // 不正なファミリ
    memset(&ss, 0, sizeof(ss));
    ss.ss_family = 999;
    const char *result = sockaddr_to_string_safe(&ss, buf, sizeof(buf));
    EXPECT_TRUE(strcmp(result, "<unknown>") == 0,
                "sockaddr_to_string_safe invalid family");
}

static void test_format_sockaddr_with_port(void)
{
    struct sockaddr_storage ss;
    char buf[INET6_ADDRSTRLEN + 8];
    int ipv6_ok = ipv6_available();

    // IPv4 形式: "192.168.1.1:862"
    memset(&ss, 0, sizeof(ss));
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(862);
        inet_pton(AF_INET, "192.168.1.1", &sin->sin_addr);
    }
    const char *ipv4_result = format_sockaddr_with_port(&ss, buf, sizeof(buf));
    EXPECT_TRUE(strcmp(ipv4_result, "192.168.1.1:862") == 0,
                "format_sockaddr_with_port IPv4");

    // 別のポート番号
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_port = htons(8080);
    }
    ipv4_result = format_sockaddr_with_port(&ss, buf, sizeof(buf));
    EXPECT_TRUE(strcmp(ipv4_result, "192.168.1.1:8080") == 0,
                "format_sockaddr_with_port IPv4 port 8080");

    // IPv6 形式: "[::1]:8080"
    if (ipv6_ok)
    {
        memset(&ss, 0, sizeof(ss));
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(8080);
            inet_pton(AF_INET6, "::1", &sin6->sin6_addr);
        }
        const char *ipv6_result = format_sockaddr_with_port(&ss, buf, sizeof(buf));
        EXPECT_TRUE(strcmp(ipv6_result, "[::1]:8080") == 0,
                    "format_sockaddr_with_port IPv6 bracket format");
    }
    else
    {
        SKIP_TEST("format_sockaddr_with_port IPv6 not available");
    }

    // NULLバッファ
    EXPECT_TRUE(strcmp(format_sockaddr_with_port(&ss, NULL, 0), "") == 0,
                "format_sockaddr_with_port NULL buffer");

    // バッファサイズ0
    EXPECT_TRUE(strcmp(format_sockaddr_with_port(&ss, buf, 0), "") == 0,
                "format_sockaddr_with_port buflen 0");
}

// =============================================================================
// Phase 4: resolve_address_list テスト
// =============================================================================

static void test_resolve_address_list(void)
{
    struct addrinfo *result = NULL;
    int ipv6_ok = ipv6_available();

    // 正常ケース: 127.0.0.1
    EXPECT_TRUE(resolve_address_list("127.0.0.1", 862, AF_INET, &result) == 0,
                "resolve_address_list 127.0.0.1");
    if (result)
        freeaddrinfo(result);
    result = NULL;

    // AF_UNSPEC
    EXPECT_TRUE(resolve_address_list("localhost", 8080, AF_UNSPEC, &result) == 0,
                "resolve_address_list localhost AF_UNSPEC");
    if (result)
        freeaddrinfo(result);
    result = NULL;

    // IPv6（利用可能な場合）
    if (ipv6_ok)
    {
        EXPECT_TRUE(resolve_address_list("::1", 862, AF_INET6, &result) == 0,
                    "resolve_address_list ::1");
        if (result)
            freeaddrinfo(result);
        result = NULL;
    }
    else
    {
        SKIP_TEST("resolve_address_list IPv6");
    }

    // 無効なホスト名
    EXPECT_TRUE(resolve_address_list("invalid.invalid.invalid", 862,
                                     AF_INET, &result) != 0,
                "resolve_address_list invalid hostname");

    // NULLホスト
    EXPECT_TRUE(resolve_address_list(NULL, 862, AF_INET, &result) != 0,
                "resolve_address_list NULL host");

    // NULLポインタ（結果）
    EXPECT_TRUE(resolve_address_list("127.0.0.1", 862, AF_INET, NULL) != 0,
                "resolve_address_list NULL result");

    // ホスト名長さ制限テスト (MAX_HOSTNAME_LEN = 253)
    char long_hostname[260];
    memset(long_hostname, 'a', 254);
    long_hostname[254] = '\0';
    EXPECT_TRUE(resolve_address_list(long_hostname, 862, AF_INET, &result) != 0,
                "resolve_address_list hostname too long");
}

// =============================================================================
// Phase 5: validate_stamp_packet 拡張テスト
// =============================================================================

static void test_validate_stamp_packet_extended(void)
{
    uint8_t buffer[STAMP_MAX_PACKET_SIZE + 16];
    memset(buffer, 0, sizeof(buffer));

    // ちょうど最小サイズ
    EXPECT_TRUE(validate_stamp_packet(buffer, STAMP_BASE_PACKET_SIZE) == 1,
                "validate exact STAMP_BASE_PACKET_SIZE");

    // 最小サイズ - 1
    EXPECT_TRUE(validate_stamp_packet(buffer, STAMP_BASE_PACKET_SIZE - 1) == 0,
                "validate STAMP_BASE_PACKET_SIZE - 1");

    // 最大サイズ
    EXPECT_TRUE(validate_stamp_packet(buffer, STAMP_MAX_PACKET_SIZE) == 1,
                "validate STAMP_MAX_PACKET_SIZE");

    // 中間サイズ
    EXPECT_TRUE(validate_stamp_packet(buffer, 100) == 1,
                "validate medium size (100)");
    EXPECT_TRUE(validate_stamp_packet(buffer, 1000) == 1,
                "validate size 1000");

    // サイズ0
    EXPECT_TRUE(validate_stamp_packet(buffer, 0) == 0,
                "validate size 0");

    // 負のサイズ（int境界）
    EXPECT_TRUE(validate_stamp_packet(buffer, -1) == 0,
                "validate negative size");

    // サイズ1（最小より小さい）
    EXPECT_TRUE(validate_stamp_packet(buffer, 1) == 0,
                "validate size 1");
}

// =============================================================================
// Phase 6: RTT計算ロジックテスト
// =============================================================================

// RTT計算ユーティリティ（テスト用）
static void calculate_delays(double t1, double t2, double t3, double t4,
                             double *forward, double *backward,
                             double *rtt, double *offset)
{
    *forward = (t2 - t1) * 1000.0;
    *backward = (t4 - t3) * 1000.0;
    *rtt = *forward + *backward;
    *offset = ((t2 - t1) + (t3 - t4)) * 0.5 * 1000.0;
}

static void test_rtt_calculation(void)
{
    double fwd, bwd, rtt, offset;

    // ケース1: 対称遅延（クロック同期済み）
    // T1=0, T2=0.001, T3=0.002, T4=0.003
    calculate_delays(0.0, 0.001, 0.002, 0.003, &fwd, &bwd, &rtt, &offset);
    EXPECT_NEAR_DOUBLE(fwd, 1.0, 0.001, "RTT symmetric forward 1ms");
    EXPECT_NEAR_DOUBLE(bwd, 1.0, 0.001, "RTT symmetric backward 1ms");
    EXPECT_NEAR_DOUBLE(rtt, 2.0, 0.001, "RTT symmetric total 2ms");
    EXPECT_NEAR_DOUBLE(offset, 0.0, 0.001, "RTT symmetric offset 0ms");

    // ケース2: 非対称遅延
    // T1=0, T2=0.002, T3=0.003, T4=0.004
    calculate_delays(0.0, 0.002, 0.003, 0.004, &fwd, &bwd, &rtt, &offset);
    EXPECT_NEAR_DOUBLE(fwd, 2.0, 0.001, "RTT asymmetric forward 2ms");
    EXPECT_NEAR_DOUBLE(bwd, 1.0, 0.001, "RTT asymmetric backward 1ms");
    EXPECT_NEAR_DOUBLE(rtt, 3.0, 0.001, "RTT asymmetric total 3ms");

    // ケース3: クロックオフセットあり
    // T1=0, T2=0.002, T3=0.003, T4=0.002
    calculate_delays(0.0, 0.002, 0.003, 0.002, &fwd, &bwd, &rtt, &offset);
    EXPECT_NEAR_DOUBLE(rtt, 1.0, 0.001, "RTT with offset total 1ms");
    EXPECT_NEAR_DOUBLE(offset, 1.5, 0.001, "RTT clock offset 1.5ms");

    // ケース4: ゼロ遅延（ローカルホスト理想ケース）
    calculate_delays(1.0, 1.0, 1.0, 1.0, &fwd, &bwd, &rtt, &offset);
    EXPECT_NEAR_DOUBLE(rtt, 0.0, 0.001, "RTT zero delay");
    EXPECT_NEAR_DOUBLE(offset, 0.0, 0.001, "RTT zero offset");

    // ケース5: 大きな遅延
    calculate_delays(0.0, 0.1, 0.15, 0.25, &fwd, &bwd, &rtt, &offset);
    EXPECT_NEAR_DOUBLE(fwd, 100.0, 0.1, "RTT large forward 100ms");
    EXPECT_NEAR_DOUBLE(bwd, 100.0, 0.1, "RTT large backward 100ms");
    EXPECT_NEAR_DOUBLE(rtt, 200.0, 0.1, "RTT large total 200ms");
}

static void test_negative_delay_detection(void)
{
    double fwd, bwd, rtt, offset;

    // T1 > T4 異常ケース（重大なクロックスキュー）
    double t1 = 1.0;
    double t4 = 0.5;
    EXPECT_TRUE(t1 > t4, "T1 > T4 anomaly detected");

    // 負の往路遅延
    // T1=1.0, T2=0.5 (Reflectorの時計が遅れている)
    calculate_delays(1.0, 0.5, 0.6, 1.1, &fwd, &bwd, &rtt, &offset);
    EXPECT_TRUE(fwd < 0, "Negative forward delay detected");

    // 負の復路遅延
    // T3=1.0, T4=0.9
    calculate_delays(0.0, 0.1, 1.0, 0.9, &fwd, &bwd, &rtt, &offset);
    EXPECT_TRUE(bwd < 0, "Negative backward delay detected");
}

// =============================================================================
// Phase 7: 統計計算テスト
// =============================================================================

// 統計計算用構造体（sender.cと同じ構造）
struct test_stats
{
    uint32_t sent;
    uint32_t received;
    uint32_t timeouts;
    double min_rtt;
    double max_rtt;
    double sum_rtt;
};

static void test_statistics_calculation(void)
{
    struct test_stats stats = {0, 0, 0, 1e9, 0, 0};

    // RTTサンプルを追加
    double rtts[] = {1.0, 2.0, 3.0, 4.0, 5.0};
    int count = (int)(sizeof(rtts) / sizeof(rtts[0]));

    for (int i = 0; i < count; i++)
    {
        stats.sent++;
        stats.received++;
        stats.sum_rtt += rtts[i];
        if (rtts[i] < stats.min_rtt)
            stats.min_rtt = rtts[i];
        if (rtts[i] > stats.max_rtt)
            stats.max_rtt = rtts[i];
    }

    EXPECT_EQ_ULL(stats.sent, 5, "stats sent count");
    EXPECT_EQ_ULL(stats.received, 5, "stats received count");
    EXPECT_NEAR_DOUBLE(stats.min_rtt, 1.0, 0.001, "stats min RTT");
    EXPECT_NEAR_DOUBLE(stats.max_rtt, 5.0, 0.001, "stats max RTT");
    EXPECT_NEAR_DOUBLE(stats.sum_rtt / stats.received, 3.0, 0.001,
                       "stats avg RTT");

    // タイムアウトのカウント
    stats.timeouts = 3;
    EXPECT_EQ_ULL(stats.timeouts, 3, "stats timeouts count");

    // 単一サンプル
    struct test_stats single = {1, 1, 0, 1e9, 0, 0};
    single.sum_rtt = 2.5;
    single.min_rtt = 2.5;
    single.max_rtt = 2.5;
    EXPECT_NEAR_DOUBLE(single.min_rtt, single.max_rtt, 0.001,
                       "single sample min == max");
}

static void test_packet_loss_calculation(void)
{
    // 0% ロス
    {
        uint32_t sent = 100, received = 100;
        double loss = (sent > 0) ? (100.0 * (double)(sent - received) / (double)sent) : 0;
        EXPECT_NEAR_DOUBLE(loss, 0.0, 0.001, "packet loss 0%");
    }

    // 5% ロス
    {
        uint32_t sent = 100, received = 95;
        double loss = (sent > 0) ? (100.0 * (double)(sent - received) / (double)sent) : 0;
        EXPECT_NEAR_DOUBLE(loss, 5.0, 0.001, "packet loss 5%");
    }

    // 50% ロス
    {
        uint32_t sent = 100, received = 50;
        double loss = (sent > 0) ? (100.0 * (double)(sent - received) / (double)sent) : 0;
        EXPECT_NEAR_DOUBLE(loss, 50.0, 0.001, "packet loss 50%");
    }

    // 100% ロス
    {
        uint32_t sent = 100, received = 0;
        double loss = (sent > 0) ? (100.0 * (double)(sent - received) / (double)sent) : 0;
        EXPECT_NEAR_DOUBLE(loss, 100.0, 0.001, "packet loss 100%");
    }

    // 送信0の場合
    {
        uint32_t sent = 0, received = 0;
        double loss = (sent > 0) ? (100.0 * (double)(sent - received) / (double)sent) : 0;
        EXPECT_NEAR_DOUBLE(loss, 0.0, 0.001, "packet loss sent=0");
    }
}

// =============================================================================
// Phase 8: パケット構築テスト
// =============================================================================

static void test_sender_packet_fields(void)
{
    struct stamp_sender_packet pkt;

    // パケット初期化
    memset(&pkt, 0, sizeof(pkt));
    pkt.seq_num = htonl(12345);
    pkt.error_estimate = htons(ERROR_ESTIMATE_DEFAULT);

    // フィールド検証
    EXPECT_EQ_ULL(ntohl(pkt.seq_num), 12345, "sender packet seq_num");
    EXPECT_EQ_ULL(ntohs(pkt.error_estimate), ERROR_ESTIMATE_DEFAULT,
                  "sender packet error_estimate");

    // MBZフィールドがゼロであること
    int mbz_ok = 1;
    for (size_t i = 0; i < sizeof(pkt.mbz); i++)
    {
        if (pkt.mbz[i] != 0)
        {
            mbz_ok = 0;
            break;
        }
    }
    EXPECT_TRUE(mbz_ok, "sender packet MBZ all zeros");

    // タイムスタンプフィールド
    pkt.timestamp_sec = htonl(0xDEADBEEF);
    pkt.timestamp_frac = htonl(0xCAFEBABE);
    EXPECT_EQ_ULL(ntohl(pkt.timestamp_sec), 0xDEADBEEF,
                  "sender packet timestamp_sec");
    EXPECT_EQ_ULL(ntohl(pkt.timestamp_frac), 0xCAFEBABE,
                  "sender packet timestamp_frac");

    // シーケンス番号の境界値
    pkt.seq_num = htonl(0);
    EXPECT_EQ_ULL(ntohl(pkt.seq_num), 0, "sender packet seq_num 0");

    pkt.seq_num = htonl(0xFFFFFFFF);
    EXPECT_EQ_ULL(ntohl(pkt.seq_num), 0xFFFFFFFF, "sender packet seq_num max");
}

static void test_reflector_packet_fields(void)
{
    struct stamp_sender_packet sender;
    struct stamp_reflector_packet reflector;

    // 送信者パケットを設定
    memset(&sender, 0, sizeof(sender));
    sender.seq_num = htonl(42);
    sender.timestamp_sec = htonl(0x12345678);
    sender.timestamp_frac = htonl(0xABCDEF00);
    sender.error_estimate = htons(0x8001);

    // Reflectorパケットに情報をコピー（reflect_packet()のロジック）
    memset(&reflector, 0, sizeof(reflector));
    reflector.seq_num = sender.seq_num; // Stateless mode
    reflector.sender_seq_num = sender.seq_num;
    reflector.sender_ts_sec = sender.timestamp_sec;
    reflector.sender_ts_frac = sender.timestamp_frac;
    reflector.sender_err_est = sender.error_estimate;
    reflector.sender_ttl = 64;
    reflector.error_estimate = htons(ERROR_ESTIMATE_DEFAULT);

    // 検証
    EXPECT_EQ_ULL(ntohl(reflector.seq_num), 42,
                  "reflector packet seq_num (stateless)");
    EXPECT_EQ_ULL(ntohl(reflector.sender_seq_num), 42,
                  "reflector packet sender_seq_num");
    EXPECT_EQ_ULL(ntohl(reflector.sender_ts_sec), 0x12345678,
                  "reflector packet sender_ts_sec");
    EXPECT_EQ_ULL(ntohl(reflector.sender_ts_frac), 0xABCDEF00,
                  "reflector packet sender_ts_frac");
    EXPECT_EQ_ULL(ntohs(reflector.sender_err_est), 0x8001,
                  "reflector packet sender_err_est");
    EXPECT_EQ_ULL(reflector.sender_ttl, 64, "reflector packet sender_ttl");

    // MBZフィールド検証
    EXPECT_EQ_ULL(reflector.mbz_1, 0, "reflector packet mbz_1");
    EXPECT_EQ_ULL(reflector.mbz_2, 0, "reflector packet mbz_2");
    int mbz3_ok = 1;
    for (size_t i = 0; i < sizeof(reflector.mbz_3); i++)
    {
        if (reflector.mbz_3[i] != 0)
        {
            mbz3_ok = 0;
            break;
        }
    }
    EXPECT_TRUE(mbz3_ok, "reflector packet mbz_3 all zeros");

    // TTL/Hop Limit境界値
    reflector.sender_ttl = 0;
    EXPECT_EQ_ULL(reflector.sender_ttl, 0, "reflector sender_ttl 0");

    reflector.sender_ttl = 255;
    EXPECT_EQ_ULL(reflector.sender_ttl, 255, "reflector sender_ttl 255");
}

// =============================================================================
// Phase 9: Error Estimate フィールドテスト
// =============================================================================

static void test_error_estimate_fields(void)
{
    // デフォルト値の検証
    uint16_t ee = ERROR_ESTIMATE_DEFAULT;

    // S bit (synchronized) = 1
    EXPECT_TRUE((ee & ERROR_ESTIMATE_S_BIT) != 0,
                "ERROR_ESTIMATE_DEFAULT S bit set");

    // Z bit (timestamp format) = 0 (NTP)
    EXPECT_TRUE((ee & ERROR_ESTIMATE_Z_BIT) == 0,
                "ERROR_ESTIMATE_DEFAULT Z bit clear (NTP format)");

    // Scale (bits 8-13) の抽出
    uint8_t scale = (uint8_t)((ee & ERROR_ESTIMATE_SCALE_MASK) >> 8);
    EXPECT_EQ_ULL(scale, 0, "ERROR_ESTIMATE_DEFAULT scale = 0");

    // Multiplier (bits 0-7) の抽出
    uint8_t mult = (uint8_t)(ee & ERROR_ESTIMATE_MULT_MASK);
    EXPECT_EQ_ULL(mult, 1, "ERROR_ESTIMATE_DEFAULT multiplier = 1");

    // カスタム Error Estimate の構築テスト
    // S=1, Z=0, Scale=5, Mult=10
    uint16_t custom_ee = ERROR_ESTIMATE_S_BIT | (5 << 8) | 10;
    EXPECT_TRUE((custom_ee & ERROR_ESTIMATE_S_BIT) != 0, "custom S bit");
    EXPECT_EQ_ULL((custom_ee & ERROR_ESTIMATE_SCALE_MASK) >> 8, 5, "custom scale");
    EXPECT_EQ_ULL(custom_ee & ERROR_ESTIMATE_MULT_MASK, 10, "custom multiplier");

    // Z=1 (PTP format) のテスト
    uint16_t ptp_ee = ERROR_ESTIMATE_S_BIT | ERROR_ESTIMATE_Z_BIT | 1;
    EXPECT_TRUE((ptp_ee & ERROR_ESTIMATE_Z_BIT) != 0,
                "PTP format Z bit set");

    // S=0 (unsynchronized) のテスト
    uint16_t unsync_ee = 1; // S=0, Z=0, Scale=0, Mult=1
    EXPECT_TRUE((unsync_ee & ERROR_ESTIMATE_S_BIT) == 0,
                "Unsynchronized S bit clear");
}

int main(void)
{
#ifdef _WIN32
    if (init_winsock() != 0)
    {
        printf("FAIL: WSAStartup\n");
        return 1;
    }
#endif

    test_constants();
    test_struct_layout();
    test_validate_stamp_packet();
    test_ntp_to_double();
    test_get_ntp_timestamp();
    test_byte_order();
    test_parse_port();
    // IPv6対応テスト
    test_get_sockaddr_len();
    test_sockaddr_get_port();
    test_sockaddr_to_string();
    test_resolve_address();
    // IPv6通信テスト
    test_ipv6_socket_communication();
    // Windows getoptテスト
#ifdef _WIN32
    test_stamp_getopt();
#endif

    // ===== 新規追加テスト =====
    // Phase 1: NTP変換マクロ
    test_nsec_to_ntp_frac();
    test_usec_to_ntp_frac();
#ifdef _WIN32
    test_windows_100ns_to_ntp_frac();
#endif

    // Phase 2: timespec/timeval変換 (UNIX)
#ifndef _WIN32
    test_timespec_to_ntp();
    test_timeval_to_ntp();
#endif

    // Phase 3: sockaddrユーティリティ追加
    test_sockaddr_to_string_safe();
    test_format_sockaddr_with_port();

    // Phase 4: resolve_address_list
    test_resolve_address_list();

    // Phase 5: validate_stamp_packet拡張
    test_validate_stamp_packet_extended();

    // Phase 6: RTT計算
    test_rtt_calculation();
    test_negative_delay_detection();

    // Phase 7: 統計計算
    test_statistics_calculation();
    test_packet_loss_calculation();

    // Phase 8: パケット構築
    test_sender_packet_fields();
    test_reflector_packet_fields();

    // Phase 9: Error Estimate
    test_error_estimate_fields();

    if (g_tests_failed == 0)
    {
        printf("PASS: %d tests\n", g_tests_run);
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    printf("FAIL: %d of %d tests\n", g_tests_failed, g_tests_run);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
}
