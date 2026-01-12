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
