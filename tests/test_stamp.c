// Basic unit tests for RFC 8762 STAMP structures and helpers.
// stamp.hを最初にインクルードして_POSIX_C_SOURCEを有効にする
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
    EXPECT_TRUE(validate_stamp_packet(NULL, STAMP_BASE_PACKET_SIZE) == 0,
                "validate null");
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

    rc = get_ntp_timestamp(NULL, &frac);
    EXPECT_TRUE(rc != 0, "get_ntp_timestamp rejects null sec");
    rc = get_ntp_timestamp(&sec, NULL);
    EXPECT_TRUE(rc != 0, "get_ntp_timestamp rejects null frac");
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

// IPv6対応ユーティリティ関数のテスト
static void test_get_sockaddr_len(void)
{
    EXPECT_EQ_ULL(get_sockaddr_len(AF_INET), sizeof(struct sockaddr_in),
                  "get_sockaddr_len AF_INET");
    EXPECT_EQ_ULL(get_sockaddr_len(AF_INET6), sizeof(struct sockaddr_in6),
                  "get_sockaddr_len AF_INET6");
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
}

static void test_sockaddr_to_string(void)
{
    struct sockaddr_storage ss;
    char buf[INET6_ADDRSTRLEN];

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

    // IPv6
    memset(&ss, 0, sizeof(ss));
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, "::1", &sin6->sin6_addr);
    }
    EXPECT_TRUE(sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
                "sockaddr_to_string IPv6 success");
    EXPECT_TRUE(strcmp(buf, "::1") == 0, "sockaddr_to_string IPv6 value");

    // NULL cases
    EXPECT_TRUE(sockaddr_to_string(NULL, buf, sizeof(buf)) == NULL,
                "sockaddr_to_string NULL addr");
    EXPECT_TRUE(sockaddr_to_string(&ss, NULL, sizeof(buf)) == NULL,
                "sockaddr_to_string NULL buf");
}

static void test_resolve_address(void)
{
    struct sockaddr_storage ss;
    socklen_t len;

    // IPv4 loopback
    EXPECT_TRUE(resolve_address("127.0.0.1", 862, AF_INET, &ss, &len) == 0,
                "resolve_address IPv4 loopback");
    EXPECT_EQ_ULL(ss.ss_family, AF_INET, "resolve_address IPv4 family");
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 862, "resolve_address IPv4 port");

    // IPv6 loopback
    EXPECT_TRUE(resolve_address("::1", 862, AF_INET6, &ss, &len) == 0,
                "resolve_address IPv6 loopback");
    EXPECT_EQ_ULL(ss.ss_family, AF_INET6, "resolve_address IPv6 family");
    EXPECT_EQ_ULL(sockaddr_get_port(&ss), 862, "resolve_address IPv6 port");

    // Invalid address
    EXPECT_TRUE(resolve_address("invalid.address.example", 862, AF_INET, &ss, &len) != 0,
                "resolve_address invalid hostname");

    // NULL cases
    EXPECT_TRUE(resolve_address(NULL, 862, AF_INET, &ss, &len) != 0,
                "resolve_address NULL host");
    EXPECT_TRUE(resolve_address("127.0.0.1", 862, AF_INET, NULL, &len) != 0,
                "resolve_address NULL out_addr");
}

int main(void)
{
    test_constants();
    test_struct_layout();
    test_validate_stamp_packet();
    test_ntp_to_double();
    test_get_ntp_timestamp();
    test_byte_order();
    // IPv6対応テスト
    test_get_sockaddr_len();
    test_sockaddr_get_port();
    test_sockaddr_to_string();
    test_resolve_address();

    if (g_tests_failed == 0)
    {
        printf("PASS: %d tests\n", g_tests_run);
        return 0;
    }

    printf("FAIL: %d of %d tests\n", g_tests_failed, g_tests_run);
    return 1;
}
