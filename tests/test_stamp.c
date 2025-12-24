// Basic unit tests for RFC 8762 STAMP structures and helpers.
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/stamp.h"

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
    EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, error_estimate), 12,
                  "sender.error_estimate offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, mbz), 14,
                  "sender.mbz offset");

    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, timestamp_sec), 4,
                  "reflector.timestamp_sec offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, error_estimate), 12,
                  "reflector.error_estimate offset");
    EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, rx_sec), 16,
                  "reflector.rx_sec offset");
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
    EXPECT_TRUE(fabs(t_unix - (double)now) < 5.0, "ntp timestamp close to wall clock");

    rc = get_ntp_timestamp(NULL, &frac);
    EXPECT_TRUE(rc != 0, "get_ntp_timestamp rejects null sec");
    rc = get_ntp_timestamp(&sec, NULL);
    EXPECT_TRUE(rc != 0, "get_ntp_timestamp rejects null frac");
}

int main(void)
{
    test_constants();
    test_struct_layout();
    test_validate_stamp_packet();
    test_ntp_to_double();
    test_get_ntp_timestamp();

    if (g_tests_failed == 0)
    {
        printf("PASS: %d tests\n", g_tests_run);
        return 0;
    }

    printf("FAIL: %d of %d tests\n", g_tests_failed, g_tests_run);
    return 1;
}
