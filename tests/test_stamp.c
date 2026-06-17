// RFC 8762 STAMP ユニットテスト
//
// Test organization:
//   ~93-200:    Protocol constants, struct layout, basic utility
//   ~200-630:   Network utilities (sockaddr, resolve, IPv6)
//   ~630-795:   Windows getopt
//   ~800-950:   NTP/PTP conversion macros
//   ~950-1150:  Extended utilities and address tests
//   ~1150-1320: RTT calculation and statistics
//   ~1320-1550: Packet construction and HW timestamp
//   ~1550-1700: Error estimate and PTP timestamp
//   ~1700-1900: PHC, one-way delay, jitter
//   ~3370-3780: E2E integration (loopback sender↔reflector)
#include "../src/stamp.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif

static int g_tests_run = 0;
static int g_tests_failed = 0;
static int g_tests_skipped = 0;
static int g_ipv6_ok = 0;

#define EXPECT_TRUE(cond, msg)                                                 \
	do {                                                                   \
		g_tests_run++;                                                 \
		if (!(cond)) {                                                 \
			printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
			g_tests_failed++;                                      \
		}                                                              \
	} while (0)

#define EXPECT_EQ_ULL(actual, expected, msg)                           \
	do {                                                           \
		unsigned long long a = (unsigned long long)(actual);   \
		unsigned long long e = (unsigned long long)(expected); \
		g_tests_run++;                                         \
		if (a != e) {                                          \
			printf("FAIL: %s (got %llu expected %llu) "    \
			       "(%s:%d)\n",                            \
			       msg,                                    \
			       a,                                      \
			       e,                                      \
			       __FILE__,                               \
			       __LINE__);                              \
			g_tests_failed++;                              \
		}                                                      \
	} while (0)

#define EXPECT_NEAR_DOUBLE(actual, expected, eps, msg)              \
	do {                                                        \
		double a = (actual);                                \
		double e = (expected);                              \
		g_tests_run++;                                      \
		if (fabs(a - e) > (eps)) {                          \
			printf("FAIL: %s (got %.9f expected %.9f) " \
			       "(%s:%d)\n",                         \
			       msg,                                 \
			       a,                                   \
			       e,                                   \
			       __FILE__,                            \
			       __LINE__);                           \
			g_tests_failed++;                           \
		}                                                   \
	} while (0)

#define SKIP_TEST(msg)                     \
	do {                               \
		g_tests_skipped++;         \
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
	if (rc != 0) {
		return 0;
	}
	freeaddrinfo(result);
	return 1;
}

static void test_protocol_constants(void)
{
	EXPECT_EQ_ULL(STAMP_PORT, 862, "STAMP_PORT");
	EXPECT_EQ_ULL(STAMP_BASE_PACKET_SIZE, 44, "STAMP_BASE_PACKET_SIZE");
	EXPECT_TRUE(STAMP_MAX_PACKET_SIZE >= STAMP_BASE_PACKET_SIZE,
		    "STAMP_MAX_PACKET_SIZE >= STAMP_BASE_PACKET_SIZE");
	EXPECT_EQ_ULL(NTP_OFFSET, 2208988800UL, "NTP_OFFSET");

	// Error Estimate constants (RFC 4656 Section 4.1.2)
	EXPECT_EQ_ULL(ERROR_ESTIMATE_S_BIT, 0x8000, "ERROR_ESTIMATE_S_BIT");
	EXPECT_EQ_ULL(ERROR_ESTIMATE_Z_BIT, 0x4000, "ERROR_ESTIMATE_Z_BIT");
	EXPECT_EQ_ULL(ERROR_ESTIMATE_DEFAULT,
		      0x0001,
		      "ERROR_ESTIMATE_DEFAULT raw value");
}

static void test_struct_layout(void)
{
	EXPECT_EQ_ULL(sizeof(struct stamp_sender_packet),
		      STAMP_BASE_PACKET_SIZE,
		      "stamp_sender_packet size");
	EXPECT_EQ_ULL(sizeof(struct stamp_reflector_packet),
		      STAMP_BASE_PACKET_SIZE,
		      "stamp_reflector_packet size");

	EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, timestamp_sec),
		      4,
		      "sender.timestamp_sec offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, timestamp_frac),
		      8,
		      "sender.timestamp_frac offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, error_estimate),
		      12,
		      "sender.error_estimate offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_sender_packet, mbz),
		      14,
		      "sender.mbz offset");

	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, timestamp_sec),
		      4,
		      "reflector.timestamp_sec offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, timestamp_frac),
		      8,
		      "reflector.timestamp_frac offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, error_estimate),
		      12,
		      "reflector.error_estimate offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, rx_sec),
		      16,
		      "reflector.rx_sec offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, rx_frac),
		      20,
		      "reflector.rx_frac offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, sender_seq_num),
		      24,
		      "reflector.sender_seq_num offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, sender_err_est),
		      36,
		      "reflector.sender_err_est offset");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, sender_ttl),
		      40,
		      "reflector.sender_ttl offset");
}

/**
 * テストバッファに有効な Error Estimate を設定するヘルパー
 * offset 12-13 に ERROR_ESTIMATE_DEFAULT (0x0001) を書き込む
 */
static void set_valid_error_estimate(uint8_t *buf, size_t len)
{
	if (len >= 14) {
		buf[12] = (uint8_t)(ERROR_ESTIMATE_DEFAULT >> 8);
		buf[13] = (uint8_t)(ERROR_ESTIMATE_DEFAULT & 0xFF);
	}
}

static void test_stamp_validate_packet(void)
{
	uint8_t buffer[STAMP_BASE_PACKET_SIZE + 4];

	memset(buffer, 0, sizeof(buffer));
	set_valid_error_estimate(buffer, sizeof(buffer));
	EXPECT_TRUE(stamp_validate_packet(buffer, STAMP_BASE_PACKET_SIZE) == 1,
		    "validate base size");
	EXPECT_TRUE(stamp_validate_packet(buffer, STAMP_BASE_PACKET_SIZE + 1) ==
			    1,
		    "validate larger size");
	EXPECT_TRUE(stamp_validate_packet(buffer, STAMP_BASE_PACKET_SIZE - 1) ==
			    0,
		    "validate too small");
	// NULLテストは削除: nonnull属性により未定義動作となるため
}

static void test_stamp_ntp_to_double(void)
{
	uint32_t sec = htonl(NTP_OFFSET);
	uint32_t frac = htonl(0);
	double t0 = stamp_ntp_to_double(sec, frac);
	EXPECT_NEAR_DOUBLE(t0, 0.0, 1e-9, "stamp_ntp_to_double epoch");

	sec = htonl(NTP_OFFSET + 1);
	frac = htonl(0x80000000U);
	t0 = stamp_ntp_to_double(sec, frac);
	EXPECT_NEAR_DOUBLE(t0, 1.5, 1e-9, "stamp_ntp_to_double 1.5s");
}

static void test_stamp_get_ntp_timestamp(void)
{
	uint32_t sec = 0;
	uint32_t frac = 0;
	time_t before = time(NULL);
	int rc = stamp_get_ntp_timestamp(&sec, &frac);
	time_t after = time(NULL);
	EXPECT_TRUE(rc == 0, "stamp_get_ntp_timestamp returns 0");

	double t_unix = stamp_ntp_to_double(sec, frac);
	EXPECT_TRUE(t_unix >= (double)before && t_unix <= (double)(after + 1),
		    "ntp timestamp within [before, after+1] window");
	// NULLテストは削除: nonnull属性により未定義動作となるため
}

static void test_byte_order(void)
{
	struct stamp_sender_packet pkt;
	memset(&pkt, 0, sizeof(pkt));

	// seq_num: verify actual big-endian byte layout
	pkt.seq_num = htonl(0x01020304);
	{
		const uint8_t *bytes = (const uint8_t *)&pkt.seq_num;
		EXPECT_EQ_ULL(bytes[0], 0x01, "seq_num MSB");
		EXPECT_EQ_ULL(bytes[1], 0x02, "seq_num byte 1");
		EXPECT_EQ_ULL(bytes[2], 0x03, "seq_num byte 2");
		EXPECT_EQ_ULL(bytes[3], 0x04, "seq_num LSB");
	}

	// timestamp_sec: verify actual big-endian byte layout
	pkt.timestamp_sec = htonl(0x12345678);
	{
		const uint8_t *b = (const uint8_t *)&pkt.timestamp_sec;
		EXPECT_EQ_ULL(b[0], 0x12, "timestamp_sec byte[0]");
		EXPECT_EQ_ULL(b[1], 0x34, "timestamp_sec byte[1]");
		EXPECT_EQ_ULL(b[2], 0x56, "timestamp_sec byte[2]");
		EXPECT_EQ_ULL(b[3], 0x78, "timestamp_sec byte[3]");
	}

	// timestamp_frac: verify actual big-endian byte layout
	pkt.timestamp_frac = htonl(0xABCDEF00);
	{
		const uint8_t *b = (const uint8_t *)&pkt.timestamp_frac;
		EXPECT_EQ_ULL(b[0], 0xAB, "timestamp_frac byte[0]");
		EXPECT_EQ_ULL(b[1], 0xCD, "timestamp_frac byte[1]");
		EXPECT_EQ_ULL(b[2], 0xEF, "timestamp_frac byte[2]");
		EXPECT_EQ_ULL(b[3], 0x00, "timestamp_frac byte[3]");
	}

	// error_estimate: verify actual big-endian byte layout (16-bit)
	pkt.error_estimate = htons(0xABCD);
	{
		const uint8_t *bytes = (const uint8_t *)&pkt.error_estimate;
		EXPECT_EQ_ULL(bytes[0], 0xAB, "error_estimate MSB");
		EXPECT_EQ_ULL(bytes[1], 0xCD, "error_estimate LSB");
	}
}

static void test_stamp_parse_port(void)
{
	uint16_t port = 0;
	int rc;

	rc = stamp_parse_port("862", &port);
	EXPECT_TRUE(rc == 0, "stamp_parse_port 862 success");
	EXPECT_EQ_ULL(port, 862, "stamp_parse_port 862 value");

	rc = stamp_parse_port("1", &port);
	EXPECT_TRUE(rc == 0, "stamp_parse_port min port success");
	EXPECT_EQ_ULL(port, 1, "stamp_parse_port min port value");

	rc = stamp_parse_port("65535", &port);
	EXPECT_TRUE(rc == 0, "stamp_parse_port max port success");
	EXPECT_EQ_ULL(port, 65535, "stamp_parse_port max port value");

	rc = stamp_parse_port("8080", &port);
	EXPECT_TRUE(rc == 0, "stamp_parse_port 8080 success");
	EXPECT_EQ_ULL(port, 8080, "stamp_parse_port 8080 value");

	rc = stamp_parse_port("0862", &port);
	EXPECT_TRUE(rc == 0, "stamp_parse_port leading zero success");
	EXPECT_EQ_ULL(port, 862, "stamp_parse_port leading zero value");

	EXPECT_TRUE(stamp_parse_port("0", &port) != 0,
		    "stamp_parse_port 0 rejected");
	EXPECT_TRUE(stamp_parse_port("65536", &port) != 0,
		    "stamp_parse_port 65536 rejected");
	EXPECT_TRUE(stamp_parse_port("100000", &port) != 0,
		    "stamp_parse_port overflow rejected");
	EXPECT_TRUE(stamp_parse_port("", &port) != 0,
		    "stamp_parse_port empty rejected");
	EXPECT_TRUE(stamp_parse_port("123abc", &port) != 0,
		    "stamp_parse_port trailing chars rejected");
	EXPECT_TRUE(stamp_parse_port("abc", &port) != 0,
		    "stamp_parse_port non-numeric rejected");
	EXPECT_TRUE(stamp_parse_port("-1", &port) != 0,
		    "stamp_parse_port negative rejected");
}

// IPv6対応ユーティリティ関数のテスト
static void test_stamp_get_sockaddr_len(void)
{
	EXPECT_EQ_ULL(stamp_get_sockaddr_len(AF_INET),
		      sizeof(struct sockaddr_in),
		      "stamp_get_sockaddr_len AF_INET");
	EXPECT_EQ_ULL(stamp_get_sockaddr_len(AF_INET6),
		      sizeof(struct sockaddr_in6),
		      "stamp_get_sockaddr_len AF_INET6");

	// 不正なファミリはIPv4サイズにフォールバック
	EXPECT_EQ_ULL(stamp_get_sockaddr_len(AF_UNSPEC),
		      sizeof(struct sockaddr_in),
		      "stamp_get_sockaddr_len AF_UNSPEC fallback");
	EXPECT_EQ_ULL(stamp_get_sockaddr_len(999),
		      sizeof(struct sockaddr_in),
		      "stamp_get_sockaddr_len invalid family fallback");
}

static void test_stamp_sockaddr_get_port(void)
{
	struct sockaddr_storage ss;

	// IPv4
	memset(&ss, 0, sizeof(ss));
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(862);
	}
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      862,
		      "stamp_sockaddr_get_port IPv4");

	// IPv6
	memset(&ss, 0, sizeof(ss));
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(8080);
	}
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      8080,
		      "stamp_sockaddr_get_port IPv6");

	// NULL
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(NULL),
		      0,
		      "stamp_sockaddr_get_port NULL");

	// 不正なファミリ
	memset(&ss, 0, sizeof(ss));
	ss.ss_family = AF_UNSPEC;
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      0,
		      "stamp_sockaddr_get_port AF_UNSPEC");

	memset(&ss, 0, sizeof(ss));
	ss.ss_family = 999;
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      0,
		      "stamp_sockaddr_get_port invalid family");
}

static void test_stamp_sockaddr_to_string(void)
{
	struct sockaddr_storage ss;
	char buf[INET6_ADDRSTRLEN];
	int ipv6_ok = g_ipv6_ok;

	// IPv4
	memset(&ss, 0, sizeof(ss));
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &sin->sin_addr);
	}
	EXPECT_TRUE(stamp_sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
		    "stamp_sockaddr_to_string IPv4 success");
	EXPECT_TRUE(strcmp(buf, "127.0.0.1") == 0,
		    "stamp_sockaddr_to_string IPv4 value");

	// IPv4 別のアドレス
	memset(&ss, 0, sizeof(ss));
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		inet_pton(AF_INET, "192.168.1.1", &sin->sin_addr);
	}
	EXPECT_TRUE(stamp_sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
		    "stamp_sockaddr_to_string IPv4 192.168.1.1 success");
	EXPECT_TRUE(strcmp(buf, "192.168.1.1") == 0,
		    "stamp_sockaddr_to_string IPv4 192.168.1.1 value");

	if (ipv6_ok) {
		// IPv6 loopback
		memset(&ss, 0, sizeof(ss));
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			inet_pton(AF_INET6, "::1", &sin6->sin6_addr);
		}
		EXPECT_TRUE(stamp_sockaddr_to_string(&ss, buf, sizeof(buf)) !=
				    NULL,
			    "stamp_sockaddr_to_string IPv6 loopback success");
		EXPECT_TRUE(strcmp(buf, "::1") == 0,
			    "stamp_sockaddr_to_string IPv6 loopback value");

		// IPv6 full address
		memset(&ss, 0, sizeof(ss));
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			inet_pton(AF_INET6, "2001:db8::1", &sin6->sin6_addr);
		}
		EXPECT_TRUE(
			stamp_sockaddr_to_string(&ss, buf, sizeof(buf)) != NULL,
			"stamp_sockaddr_to_string IPv6 2001:db8::1 success");
		EXPECT_TRUE(strcmp(buf, "2001:db8::1") == 0,
			    "stamp_sockaddr_to_string IPv6 2001:db8::1 value");
	} else {
		SKIP_TEST("stamp_sockaddr_to_string IPv6 not available");
	}

	// NULLテストは削除: nonnull属性により未定義動作となるため

	// buflen = 0
	EXPECT_TRUE(stamp_sockaddr_to_string(&ss, buf, 0) == NULL,
		    "stamp_sockaddr_to_string buflen 0");

	// 不正なファミリ
	memset(&ss, 0, sizeof(ss));
	ss.ss_family = AF_UNSPEC;
	EXPECT_TRUE(stamp_sockaddr_to_string(&ss, buf, sizeof(buf)) == NULL,
		    "stamp_sockaddr_to_string AF_UNSPEC");

	memset(&ss, 0, sizeof(ss));
	ss.ss_family = 999;
	EXPECT_TRUE(stamp_sockaddr_to_string(&ss, buf, sizeof(buf)) == NULL,
		    "stamp_sockaddr_to_string invalid family");
}

// NOTE: Integration test - performs real UDP I/O on loopback.
static void test_ipv6_socket_communication(void)
{
	int ipv6_ok = g_ipv6_ok;
	if (!ipv6_ok) {
		SKIP_TEST("IPv6 socket communication (IPv6 not available)");
		return;
	}

	// 送信側ソケット作成
	SOCKET send_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(send_sock)) {
		SKIP_TEST("IPv6 socket communication (socket creation failed)");
		return;
	}

	// 受信側ソケット作成とバインド
	SOCKET recv_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(recv_sock)) {
		CLOSE_SOCKET(send_sock);
		SKIP_TEST("IPv6 socket communication (recv socket creation "
			  "failed)");
		return;
	}

	// IPv6ループバックアドレスにバインド
	struct sockaddr_in6 recv_addr;
	memset(&recv_addr, 0, sizeof(recv_addr));
	recv_addr.sin6_family = AF_INET6;
	recv_addr.sin6_addr = in6addr_loopback;
	recv_addr.sin6_port = htons(0); // OSに自動割り当てさせる

	if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) <
	    0) {
		CLOSE_SOCKET(send_sock);
		CLOSE_SOCKET(recv_sock);
		SKIP_TEST("IPv6 socket communication (bind failed)");
		return;
	}

	// バインドされたポート番号を取得
	socklen_t addr_len = sizeof(recv_addr);
	if (getsockname(recv_sock, (struct sockaddr *)&recv_addr, &addr_len) <
	    0) {
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
	ssize_t send_result = sendto(send_sock,
				     test_msg,
				     strlen(test_msg),
				     0,
				     (struct sockaddr *)&dest_addr,
				     sizeof(dest_addr));

	EXPECT_TRUE(send_result > 0, "IPv6 sendto success");

	if (send_result > 0) {
		// 受信テスト (タイムアウト設定)
#ifdef _WIN32
		DWORD timeout_ms = 1000;
		setsockopt(recv_sock,
			   SOL_SOCKET,
			   SO_RCVTIMEO,
			   (const char *)&timeout_ms,
			   sizeof(timeout_ms));
#else
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

		char recv_buf[256];
		struct sockaddr_in6 from_addr;
		socklen_t from_len = sizeof(from_addr);
		ssize_t recv_result = recvfrom(recv_sock,
					       recv_buf,
					       sizeof(recv_buf) - 1,
					       0,
					       (struct sockaddr *)&from_addr,
					       &from_len);

		EXPECT_TRUE(recv_result > 0, "IPv6 recvfrom success");
		if (recv_result > 0) {
			// NOLINTNEXTLINE(clang-analyzer-security.ArrayBound)
			recv_buf[recv_result] = '\0';
			EXPECT_TRUE(strcmp(recv_buf, test_msg) == 0,
				    "IPv6 message content match");
			EXPECT_EQ_ULL(from_addr.sin6_family,
				      AF_INET6,
				      "IPv6 from_addr family");
		}
	}

	CLOSE_SOCKET(send_sock);
	CLOSE_SOCKET(recv_sock);
}

#ifndef _WIN32
static void sleep_ms_for_test(long ms)
{
	struct timespec req;
	req.tv_sec = ms / 1000;
	req.tv_nsec = (ms % 1000) * 1000000L;
	(void)nanosleep(&req, NULL);
}

static int set_recv_timeout_ms(SOCKET sock, int timeout_ms)
{
	struct timeval tv;
	if (timeout_ms < 0) {
		return -1;
	}
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000L);
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int pick_free_udp_port_ipv4(uint16_t *out_port)
{
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(sock)) {
		return -1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(0);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		CLOSE_SOCKET(sock);
		return -1;
	}

	socklen_t len = (socklen_t)sizeof(addr);
	if (getsockname(sock, (struct sockaddr *)&addr, &len) < 0) {
		CLOSE_SOCKET(sock);
		return -1;
	}

	*out_port = ntohs(addr.sin_port);
	CLOSE_SOCKET(sock);
	return 0;
}

static int start_reflector_subprocess(uint16_t port, pid_t *out_pid)
{
	if (out_pid == NULL) {
		return -1;
	}
	char port_str[6];
	if (snprintf(port_str, sizeof(port_str), "%u", (unsigned)port) <= 0) {
		return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			(void)dup2(devnull, STDOUT_FILENO);
			(void)dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO) {
				(void)close(devnull);
			}
		}
		char *const argv[] = {"./reflector", "-4", port_str, NULL};
		execv("./reflector", argv);
		_exit(127);
	}

	*out_pid = pid;
	return 0;
}

static void stop_reflector_subprocess(pid_t pid)
{
	if (pid <= 0) {
		return;
	}

	int status = 0;
	pid_t rc = waitpid(pid, &status, WNOHANG);
	if (rc == pid) {
		return;
	}

	(void)kill(pid, SIGINT);
	for (int i = 0; i < 20; i++) {
		rc = waitpid(pid, &status, WNOHANG);
		if (rc == pid) {
			return;
		}
		sleep_ms_for_test(25);
	}

	(void)kill(pid, SIGTERM);
	for (int i = 0; i < 20; i++) {
		rc = waitpid(pid, &status, WNOHANG);
		if (rc == pid) {
			return;
		}
		sleep_ms_for_test(25);
	}

	(void)kill(pid, SIGKILL);
	(void)waitpid(pid, &status, 0);
}

static void build_sender_like_payload(uint8_t *buf,
				      size_t len,
				      uint32_t seq,
				      uint16_t error_estimate)
{
	memset(buf, 0, len);
	if (len >= sizeof(uint32_t)) {
		uint32_t seq_nbo = htonl(seq);
		memcpy(buf, &seq_nbo, sizeof(seq_nbo));
	}
	if (len >= 14) {
		buf[12] = (uint8_t)(error_estimate >> 8);
		buf[13] = (uint8_t)(error_estimate & 0xFF);
	}
}

static int exchange_udp_ipv4(SOCKET sock,
			     const struct sockaddr_in *dest,
			     const uint8_t *tx_buf,
			     size_t tx_len,
			     uint8_t *rx_buf,
			     size_t rx_buf_len)
{
	ssize_t send_rc = sendto(sock,
				 tx_buf,
				 tx_len,
				 0,
				 (const struct sockaddr *)dest,
				 sizeof(*dest));
	if (send_rc < 0 || (size_t)send_rc != tx_len) {
		return -3;
	}

	struct sockaddr_in from;
	socklen_t from_len = (socklen_t)sizeof(from);
	ssize_t recv_rc = recvfrom(sock,
				   rx_buf,
				   rx_buf_len,
				   0,
				   (struct sockaddr *)&from,
				   &from_len);
	if (recv_rc < 0) {
		return IS_WOULDBLOCK(errno) ? -2 : -1;
	}
	return (int)recv_rc;
}

static void test_reflector_loopback_filtering_and_padding(void)
{
#ifndef IP_RECVTTL
	SKIP_TEST("reflector loopback filtering/padding (IP_RECVTTL unavailable)");
	return;
#else
	uint16_t port = 0;
	pid_t reflector_pid = -1;
	SOCKET sock = INVALID_SOCKET;
	bool started = false;

	if (pick_free_udp_port_ipv4(&port) != 0 || port == 0) {
		SKIP_TEST("reflector loopback filtering/padding (port allocation failed)");
		return;
	}

	if (start_reflector_subprocess(port, &reflector_pid) != 0) {
		SKIP_TEST("reflector loopback filtering/padding (failed to start reflector)");
		return;
	}
	started = true;
	sleep_ms_for_test(150);

	int status = 0;
	pid_t wait_rc = waitpid(reflector_pid, &status, WNOHANG);
	if (wait_rc == reflector_pid) {
		EXPECT_TRUE(0, "reflector subprocess exited early");
		goto cleanup;
	}

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(sock)) {
		SKIP_TEST("reflector loopback filtering/padding (client socket failed)");
		goto cleanup;
	}
	if (set_recv_timeout_ms(sock, 300) != 0) {
		SKIP_TEST("reflector loopback filtering/padding (set timeout failed)");
		goto cleanup;
	}

	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dest.sin_port = htons(port);

	uint8_t rx_buf[STAMP_MAX_PACKET_SIZE];

	// 13B (too short) -> no response
	{
		uint8_t tx[13];
		build_sender_like_payload(tx, sizeof(tx), 1, ERROR_ESTIMATE_DEFAULT);
		int n = exchange_udp_ipv4(sock,
					  &dest,
					  tx,
					  sizeof(tx),
					  rx_buf,
					  sizeof(rx_buf));
		EXPECT_TRUE(n == -2, "reflector drops payload < 14 bytes");
	}

	// 44B, multiplier==0 -> no response
	{
		uint8_t tx[STAMP_BASE_PACKET_SIZE];
		build_sender_like_payload(tx, sizeof(tx), 2, 0x0000);
		int n = exchange_udp_ipv4(sock,
					  &dest,
					  tx,
					  sizeof(tx),
					  rx_buf,
					  sizeof(rx_buf));
		EXPECT_TRUE(n == -2, "reflector drops payload with EE multiplier==0");
	}

	// 14B valid -> padded 44B response
	{
		uint8_t tx[14];
		build_sender_like_payload(tx, sizeof(tx), 3, ERROR_ESTIMATE_DEFAULT);
		int n = exchange_udp_ipv4(sock,
					  &dest,
					  tx,
					  sizeof(tx),
					  rx_buf,
					  sizeof(rx_buf));
		EXPECT_EQ_ULL((unsigned)n,
			      STAMP_BASE_PACKET_SIZE,
			      "reflector pads valid 14B payload to 44B");
		if (n == STAMP_BASE_PACKET_SIZE) {
			const struct stamp_reflector_packet *rp =
				(const struct stamp_reflector_packet *)rx_buf;
			EXPECT_EQ_ULL(ntohl(rp->sender_seq_num), 3, "reflector 14B sender_seq copied");
			EXPECT_EQ_ULL(ntohs(rp->sender_err_est),
				      ERROR_ESTIMATE_DEFAULT,
				      "reflector 14B sender_err_est copied");
			EXPECT_TRUE(rp->sender_ttl > 0, "reflector 14B sender_ttl copied");
		}
	}

	// 43B valid -> padded 44B response
	{
		uint8_t tx[43];
		build_sender_like_payload(tx, sizeof(tx), 4, ERROR_ESTIMATE_DEFAULT);
		int n = exchange_udp_ipv4(sock,
					  &dest,
					  tx,
					  sizeof(tx),
					  rx_buf,
					  sizeof(rx_buf));
		EXPECT_EQ_ULL((unsigned)n,
			      STAMP_BASE_PACKET_SIZE,
			      "reflector pads valid 43B payload to 44B");
		if (n == STAMP_BASE_PACKET_SIZE) {
			const struct stamp_reflector_packet *rp =
				(const struct stamp_reflector_packet *)rx_buf;
			EXPECT_EQ_ULL(ntohl(rp->sender_seq_num), 4, "reflector 43B sender_seq copied");
			EXPECT_TRUE(rp->sender_ttl > 0, "reflector 43B sender_ttl copied");
		}
	}

	// 44B valid -> 44B response with sender_ttl copied (>0)
	{
		uint8_t tx[STAMP_BASE_PACKET_SIZE];
		build_sender_like_payload(tx, sizeof(tx), 5, ERROR_ESTIMATE_DEFAULT);
		int n = exchange_udp_ipv4(sock,
					  &dest,
					  tx,
					  sizeof(tx),
					  rx_buf,
					  sizeof(rx_buf));
		EXPECT_EQ_ULL((unsigned)n,
			      STAMP_BASE_PACKET_SIZE,
			      "reflector reflects valid 44B payload");
		if (n == STAMP_BASE_PACKET_SIZE) {
			const struct stamp_reflector_packet *rp =
				(const struct stamp_reflector_packet *)rx_buf;
			EXPECT_EQ_ULL(ntohl(rp->sender_seq_num), 5, "reflector 44B sender_seq copied");
			EXPECT_EQ_ULL(ntohs(rp->sender_err_est),
				      ERROR_ESTIMATE_DEFAULT,
				      "reflector 44B sender_err_est copied");
			EXPECT_TRUE(rp->sender_ttl > 0, "reflector 44B sender_ttl copied");
		}
	}

cleanup:
	if (!SOCKET_ERROR_CHECK(sock)) {
		CLOSE_SOCKET(sock);
	}
	if (started) {
		stop_reflector_subprocess(reflector_pid);
	}
#endif
}
#endif

static void test_stamp_resolve_address(void)
{
	struct sockaddr_storage ss = {0};
	socklen_t len;
	int ipv6_ok = g_ipv6_ok;

	// IPv4 loopback
	len = 0;
	EXPECT_TRUE(
		stamp_resolve_address("127.0.0.1", 862, AF_INET, &ss, &len) ==
			0,
		"stamp_resolve_address IPv4 loopback");
	EXPECT_EQ_ULL(ss.ss_family,
		      AF_INET,
		      "stamp_resolve_address IPv4 family");
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      862,
		      "stamp_resolve_address IPv4 port");
	EXPECT_EQ_ULL(len,
		      sizeof(struct sockaddr_in),
		      "stamp_resolve_address IPv4 len");

	if (ipv6_ok) {
		// IPv6 loopback
		len = 0;
		EXPECT_TRUE(stamp_resolve_address("::1",
						  862,
						  AF_INET6,
						  &ss,
						  &len) == 0,
			    "stamp_resolve_address IPv6 loopback");
		EXPECT_EQ_ULL(ss.ss_family,
			      AF_INET6,
			      "stamp_resolve_address IPv6 family");
		EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
			      862,
			      "stamp_resolve_address IPv6 port");
		EXPECT_EQ_ULL(len,
			      sizeof(struct sockaddr_in6),
			      "stamp_resolve_address IPv6 len");
	} else {
		SKIP_TEST("stamp_resolve_address IPv6 loopback");
	}

	// AF_UNSPEC (自動検出) - IPv4アドレス
	len = 0;
	EXPECT_TRUE(stamp_resolve_address("127.0.0.1",
					  8080,
					  AF_UNSPEC,
					  &ss,
					  &len) == 0,
		    "stamp_resolve_address AF_UNSPEC with IPv4");
	EXPECT_EQ_ULL(ss.ss_family,
		      AF_INET,
		      "stamp_resolve_address AF_UNSPEC IPv4 family");
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      8080,
		      "stamp_resolve_address AF_UNSPEC IPv4 port");

	// AF_UNSPEC (自動検出) - IPv6アドレス
	if (ipv6_ok) {
		len = 0;
		EXPECT_TRUE(stamp_resolve_address("::1",
						  8080,
						  AF_UNSPEC,
						  &ss,
						  &len) == 0,
			    "stamp_resolve_address AF_UNSPEC with IPv6");
		EXPECT_EQ_ULL(ss.ss_family,
			      AF_INET6,
			      "stamp_resolve_address AF_UNSPEC IPv6 family");
		EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
			      8080,
			      "stamp_resolve_address AF_UNSPEC IPv6 port");
	} else {
		SKIP_TEST("stamp_resolve_address AF_UNSPEC IPv6");
	}

	// ホスト名解決 (localhost)
	len = 0;
	EXPECT_TRUE(
		stamp_resolve_address("localhost", 862, AF_INET, &ss, &len) ==
			0,
		"stamp_resolve_address localhost IPv4");
	EXPECT_EQ_ULL(ss.ss_family,
		      AF_INET,
		      "stamp_resolve_address localhost family");
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      862,
		      "stamp_resolve_address localhost port");

	// 異なるポート番号
	len = 0;
	EXPECT_TRUE(
		stamp_resolve_address("127.0.0.1", 65535, AF_INET, &ss, &len) ==
			0,
		"stamp_resolve_address max port");
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      65535,
		      "stamp_resolve_address max port value");

	len = 0;
	EXPECT_TRUE(stamp_resolve_address("127.0.0.1", 1, AF_INET, &ss, &len) ==
			    0,
		    "stamp_resolve_address min port");
	EXPECT_EQ_ULL(stamp_sockaddr_get_port(&ss),
		      1,
		      "stamp_resolve_address min port value");

	// Invalid address
	EXPECT_TRUE(stamp_resolve_address("invalid.invalid",
					  862,
					  AF_INET,
					  &ss,
					  &len) != 0,
		    "stamp_resolve_address invalid hostname");

	// NULLテストは削除: nonnull属性により未定義動作となるため

	// ファミリ不一致
	EXPECT_TRUE(
		stamp_resolve_address("127.0.0.1", 862, AF_INET6, &ss, &len) !=
			0,
		"stamp_resolve_address IPv4 addr with AF_INET6");
	if (ipv6_ok) {
		EXPECT_TRUE(
			stamp_resolve_address("::1", 862, AF_INET, &ss, &len) !=
				0,
			"stamp_resolve_address IPv6 addr with AF_INET");
	} else {
		SKIP_TEST("stamp_resolve_address IPv6 addr with AF_INET");
	}
}

// Windows用 stamp_getopt() のユニットテスト
#ifdef _WIN32
// getoptの状態をリセットするヘルパー関数
static void reset_getopt_state(void)
{
	g_stamp_optind = 1;
	g_stamp_optarg = NULL;
	g_stamp_optopt = 0;
}

static void test_stamp_getopt_basic(void)
{
	int opt;

	// テスト1: 基本的なオプション "-4"
	{
		char *argv[] = {"prog", "-4", NULL};
		int argc = 2;
		reset_getopt_state();

		opt = stamp_getopt(argc, argv, "46");
		EXPECT_TRUE(opt == '4', "getopt: -4 returns '4'");
		EXPECT_EQ_ULL(g_stamp_optind,
			      2,
			      "getopt: -4 advances optind to 2");

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
}

static void test_stamp_getopt_arguments(void)
{
	int opt;

	// テスト3: 引数付きオプション "-p 8080"
	{
		char *argv[] = {"prog", "-p", "8080", NULL};
		int argc = 3;
		reset_getopt_state();

		opt = stamp_getopt(argc, argv, "p:");
		EXPECT_TRUE(opt == 'p', "getopt: -p returns 'p'");
		EXPECT_TRUE(g_stamp_optarg != NULL &&
				    strcmp(g_stamp_optarg, "8080") == 0,
			    "getopt: -p optarg is 8080");
		EXPECT_EQ_ULL(g_stamp_optind,
			      3,
			      "getopt: -p 8080 advances optind to 3");
	}

	// テスト4: 引数がオプションに連結 "-p8080"
	{
		char *argv[] = {"prog", "-p8080", NULL};
		int argc = 2;
		reset_getopt_state();

		opt = stamp_getopt(argc, argv, "p:");
		EXPECT_TRUE(opt == 'p', "getopt: -p8080 returns 'p'");
		EXPECT_TRUE(g_stamp_optarg != NULL &&
				    strcmp(g_stamp_optarg, "8080") == 0,
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
		EXPECT_EQ_ULL(g_stamp_optind,
			      3,
			      "getopt: -- leaves optind at 3");
	}
}

static void test_stamp_getopt_errors(void)
{
	int opt;

	// テスト6: 無効なオプション
	{
		char *argv[] = {"prog", "-x", NULL};
		int argc = 2;
		reset_getopt_state();

		opt = stamp_getopt(argc, argv, "46");
		EXPECT_TRUE(opt == '?', "getopt: -x returns '?'");
		EXPECT_TRUE(g_stamp_optopt == 'x', "getopt: optopt is 'x'");
	}

	// テスト7: 必要な引数がない
	{
		char *argv[] = {"prog", "-p", NULL};
		int argc = 2;
		reset_getopt_state();

		opt = stamp_getopt(argc, argv, "p:");
		EXPECT_TRUE(opt == '?', "getopt: -p without arg returns '?'");
		EXPECT_TRUE(g_stamp_optopt == 'p', "getopt: optopt is 'p'");
	}

	// テスト8: 余分な文字を拒否 "-4extra"
	{
		char *argv[] = {"prog", "-4extra", NULL};
		int argc = 2;
		reset_getopt_state();

		opt = stamp_getopt(argc, argv, "46");
		EXPECT_TRUE(opt == '?', "getopt: -4extra returns '?'");
		EXPECT_TRUE(g_stamp_optopt == '4', "getopt: optopt is '4'");
	}
}

static void test_stamp_getopt_mixed(void)
{
	int opt;

	// テスト9: オプションなしの引数
	{
		char *argv[] = {"prog", "arg1", "arg2", NULL};
		int argc = 3;
		reset_getopt_state();

		opt = stamp_getopt(argc, argv, "46");
		EXPECT_TRUE(opt == -1, "getopt: non-option returns -1");
		EXPECT_EQ_ULL(g_stamp_optind, 1, "getopt: optind stays at 1");
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
		EXPECT_EQ_ULL(g_stamp_optind,
			      2,
			      "getopt: optind at first non-option");
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
	EXPECT_TRUE(max_nsec >= 0xFFFFFFFC,
		    "NSEC_TO_NTP_FRAC(999999999) near max");

	// 精度テスト: 1ナノ秒 ≈ 4.29 NTP単位
	uint32_t one_nsec = NSEC_TO_NTP_FRAC(1);
	EXPECT_TRUE(one_nsec >= 4 && one_nsec <= 5,
		    "NSEC_TO_NTP_FRAC(1) ≈ 4-5");

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
	EXPECT_TRUE(max_usec >= 0xFFFFEF00,
		    "USEC_TO_NTP_FRAC(999999) near max");

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
	EXPECT_EQ_ULL(WINDOWS_100NS_TO_NTP_FRAC(0),
		      0,
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
static void test_stamp_timespec_to_ntp(void)
{
	uint32_t sec;
	uint32_t frac;

	// Unix epoch (1970-01-01 00:00:00.0)
	struct timespec ts_epoch = {0, 0};
	stamp_timespec_to_ntp(&ts_epoch, &sec, &frac);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET,
		      "stamp_timespec_to_ntp epoch sec");
	EXPECT_EQ_ULL(ntohl(frac), 0, "stamp_timespec_to_ntp epoch frac");

	// 1.5秒後
	struct timespec ts_1_5 = {1, 500000000};
	stamp_timespec_to_ntp(&ts_1_5, &sec, &frac);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET + 1,
		      "stamp_timespec_to_ntp 1.5s sec");
	uint32_t frac_host = ntohl(frac);
	EXPECT_TRUE(frac_host >= 0x7FFFFFFF && frac_host <= 0x80000001,
		    "stamp_timespec_to_ntp 1.5s frac ≈ 0x80000000");

	// 境界値: tv_nsec = 999999999
	struct timespec ts_max_frac = {100, 999999999};
	stamp_timespec_to_ntp(&ts_max_frac, &sec, &frac);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET + 100,
		      "stamp_timespec_to_ntp max_frac sec");
	EXPECT_TRUE(ntohl(frac) >= 0xFFFFFFFC,
		    "stamp_timespec_to_ntp max_frac frac near max");

	// 大きな秒数
	struct timespec ts_large = {1000000, 0};
	stamp_timespec_to_ntp(&ts_large, &sec, &frac);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET + 1000000,
		      "stamp_timespec_to_ntp large sec");
}

static void test_stamp_timeval_to_ntp(void)
{
	uint32_t sec;
	uint32_t frac;

	// Unix epoch
	struct timeval tv_epoch = {0, 0};
	stamp_timeval_to_ntp(&tv_epoch, &sec, &frac);
	EXPECT_EQ_ULL(ntohl(sec), NTP_OFFSET, "stamp_timeval_to_ntp epoch sec");
	EXPECT_EQ_ULL(ntohl(frac), 0, "stamp_timeval_to_ntp epoch frac");

	// 1.5秒後
	struct timeval tv_1_5 = {1, 500000};
	stamp_timeval_to_ntp(&tv_1_5, &sec, &frac);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET + 1,
		      "stamp_timeval_to_ntp 1.5s sec");
	uint32_t frac_host = ntohl(frac);
	EXPECT_TRUE(frac_host >= 0x7FFFFFFF && frac_host <= 0x80000001,
		    "stamp_timeval_to_ntp 1.5s frac ≈ 0x80000000");

	// 境界値: tv_usec = 999999
	struct timeval tv_max_frac = {100, 999999};
	stamp_timeval_to_ntp(&tv_max_frac, &sec, &frac);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET + 100,
		      "stamp_timeval_to_ntp max_frac sec");
	EXPECT_TRUE(ntohl(frac) >= 0xFFFFEF00,
		    "stamp_timeval_to_ntp max_frac frac near max");
}
#endif

// =============================================================================
// Phase 3: sockaddrユーティリティ追加テスト
// =============================================================================

static void test_stamp_sockaddr_to_string_safe(void)
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
	EXPECT_TRUE(strcmp(stamp_sockaddr_to_string_safe(&ss, buf, sizeof(buf)),
			   "10.0.0.1") == 0,
		    "stamp_sockaddr_to_string_safe valid IPv4");

	// NULLバッファ
	EXPECT_TRUE(strcmp(stamp_sockaddr_to_string_safe(&ss, NULL, 0),
			   "<unknown>") == 0,
		    "stamp_sockaddr_to_string_safe NULL buffer");

	// バッファサイズ0
	EXPECT_TRUE(strcmp(stamp_sockaddr_to_string_safe(&ss, buf, 0),
			   "<unknown>") == 0,
		    "stamp_sockaddr_to_string_safe buflen 0");

	// 不正なファミリ
	memset(&ss, 0, sizeof(ss));
	ss.ss_family = 999;
	const char *result =
		stamp_sockaddr_to_string_safe(&ss, buf, sizeof(buf));
	EXPECT_TRUE(strcmp(result, "<unknown>") == 0,
		    "stamp_sockaddr_to_string_safe invalid family");
}

static void test_stamp_format_sockaddr_with_port(void)
{
	struct sockaddr_storage ss;
	char buf[INET6_ADDRSTRLEN + 8];
	int ipv6_ok = g_ipv6_ok;

	// IPv4 形式: "192.168.1.1:862"
	memset(&ss, 0, sizeof(ss));
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(862);
		inet_pton(AF_INET, "192.168.1.1", &sin->sin_addr);
	}
	const char *ipv4_result =
		stamp_format_sockaddr_with_port(&ss, buf, sizeof(buf));
	EXPECT_TRUE(strcmp(ipv4_result, "192.168.1.1:862") == 0,
		    "stamp_format_sockaddr_with_port IPv4");

	// 別のポート番号
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_port = htons(8080);
	}
	ipv4_result = stamp_format_sockaddr_with_port(&ss, buf, sizeof(buf));
	EXPECT_TRUE(strcmp(ipv4_result, "192.168.1.1:8080") == 0,
		    "stamp_format_sockaddr_with_port IPv4 port 8080");

	// IPv6 形式: "[::1]:8080"
	if (ipv6_ok) {
		memset(&ss, 0, sizeof(ss));
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(8080);
			inet_pton(AF_INET6, "::1", &sin6->sin6_addr);
		}
		const char *ipv6_result =
			stamp_format_sockaddr_with_port(&ss, buf, sizeof(buf));
		EXPECT_TRUE(
			strcmp(ipv6_result, "[::1]:8080") == 0,
			"stamp_format_sockaddr_with_port IPv6 bracket format");
	} else {
		SKIP_TEST("stamp_format_sockaddr_with_port IPv6 not available");
	}

	// NULLバッファ
	EXPECT_TRUE(strcmp(stamp_format_sockaddr_with_port(&ss, NULL, 0), "") ==
			    0,
		    "stamp_format_sockaddr_with_port NULL buffer");

	// バッファサイズ0
	EXPECT_TRUE(strcmp(stamp_format_sockaddr_with_port(&ss, buf, 0), "") ==
			    0,
		    "stamp_format_sockaddr_with_port buflen 0");
}

// =============================================================================
// Phase 4: stamp_resolve_address_list テスト
// =============================================================================

static void test_stamp_resolve_address_list(void)
{
	struct addrinfo *result = NULL;
	int ipv6_ok = g_ipv6_ok;

	// 正常ケース: 127.0.0.1
	EXPECT_TRUE(stamp_resolve_address_list("127.0.0.1",
					       862,
					       AF_INET,
					       &result) == 0,
		    "stamp_resolve_address_list 127.0.0.1");
	if (result) {
		freeaddrinfo(result);
	}
	result = NULL;

	// AF_UNSPEC
	EXPECT_TRUE(stamp_resolve_address_list("localhost",
					       8080,
					       AF_UNSPEC,
					       &result) == 0,
		    "stamp_resolve_address_list localhost AF_UNSPEC");
	if (result) {
		freeaddrinfo(result);
	}
	result = NULL;

	// IPv6（利用可能な場合）
	if (ipv6_ok) {
		EXPECT_TRUE(stamp_resolve_address_list("::1",
						       862,
						       AF_INET6,
						       &result) == 0,
			    "stamp_resolve_address_list ::1");
		if (result) {
			freeaddrinfo(result);
		}
		result = NULL;
	} else {
		SKIP_TEST("stamp_resolve_address_list IPv6");
	}

	// 無効なホスト名
	EXPECT_TRUE(stamp_resolve_address_list("invalid.invalid.invalid",
					       862,
					       AF_INET,
					       &result) != 0,
		    "stamp_resolve_address_list invalid hostname");

	// NULLホスト
	EXPECT_TRUE(stamp_resolve_address_list(NULL, 862, AF_INET, &result) !=
			    0,
		    "stamp_resolve_address_list NULL host");

	// NULLポインタ（結果）
	EXPECT_TRUE(
		stamp_resolve_address_list("127.0.0.1", 862, AF_INET, NULL) !=
			0,
		"stamp_resolve_address_list NULL result");

	// ホスト名長さ制限テスト (MAX_HOSTNAME_LEN = 253)
	char long_hostname[260];
	memset(long_hostname, 'a', 254);
	long_hostname[254] = '\0';
	EXPECT_TRUE(stamp_resolve_address_list(long_hostname,
					       862,
					       AF_INET,
					       &result) != 0,
		    "stamp_resolve_address_list hostname too long");
}

// =============================================================================
// Phase 5: stamp_validate_packet 拡張テスト
// =============================================================================

static void test_stamp_validate_packet_boundary_sizes(void)
{
	uint8_t buffer[STAMP_MAX_PACKET_SIZE + 16];
	memset(buffer, 0, sizeof(buffer));
	set_valid_error_estimate(buffer, sizeof(buffer));

	// ちょうど最小サイズ
	EXPECT_TRUE(stamp_validate_packet(buffer, STAMP_BASE_PACKET_SIZE) == 1,
		    "validate exact STAMP_BASE_PACKET_SIZE");

	// 最小サイズ - 1
	EXPECT_TRUE(stamp_validate_packet(buffer, STAMP_BASE_PACKET_SIZE - 1) ==
			    0,
		    "validate STAMP_BASE_PACKET_SIZE - 1");

	// 最大サイズ
	EXPECT_TRUE(stamp_validate_packet(buffer, STAMP_MAX_PACKET_SIZE) == 1,
		    "validate STAMP_MAX_PACKET_SIZE");

	// 中間サイズ
	EXPECT_TRUE(stamp_validate_packet(buffer, 100) == 1,
		    "validate medium size (100)");
	EXPECT_TRUE(stamp_validate_packet(buffer, 1000) == 1,
		    "validate size 1000");

	// サイズ0
	EXPECT_TRUE(stamp_validate_packet(buffer, 0) == 0, "validate size 0");

	// 負のサイズ（int境界）
	EXPECT_TRUE(stamp_validate_packet(buffer, -1) == 0,
		    "validate negative size");

	// サイズ1（最小より小さい）
	EXPECT_TRUE(stamp_validate_packet(buffer, 1) == 0, "validate size 1");
}

static void test_stamp_validate_test_payload_for_reflector(void)
{
	uint8_t buffer[STAMP_MAX_PACKET_SIZE + 16];
	memset(buffer, 0, sizeof(buffer));

	// 14バイト未満は拒否（TWAMP/OWAMP unauth minimum data segment未満）
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(buffer, 13) == 0,
		    "reflector validate rejects size 13");

	// 14バイト以上44バイト未満は Error Estimate が妥当なら許容（RFC 8762 4.6）
	buffer[12] = 0x00;
	buffer[13] = 0x01; // multiplier=1
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(buffer, 14) == 1,
		    "reflector validate accepts size 14 with valid EE");
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(buffer, 43) == 1,
		    "reflector validate accepts size 43 with valid EE");

	// multiplier==0 は拒否
	buffer[12] = 0x00;
	buffer[13] = 0x00;
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(buffer, 14) == 0,
		    "reflector validate rejects multiplier==0 at size 14");
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(buffer, 44) == 0,
		    "reflector validate rejects multiplier==0 at size 44");

	// base STAMP サイズ以上は既存 validate と同様に受理可能
	buffer[12] = 0x40; // Z=1
	buffer[13] = 0x01; // multiplier=1
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(buffer, 44) == 1,
		    "reflector validate accepts size 44 with valid PTP EE");

	// 上限超過は拒否
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(
			    buffer,
			    STAMP_MAX_PACKET_SIZE + 1) == 0,
		    "reflector validate rejects oversized payload");
}

static void test_stamp_check_reflector_input(void)
{
	uint8_t buffer[STAMP_BASE_PACKET_SIZE];
	enum stamp_reflector_input_check_result rc;
	memset(buffer, 0, sizeof(buffer));
	set_valid_error_estimate(buffer, sizeof(buffer));

	rc = stamp_check_reflector_input(buffer, 13, 64);
	EXPECT_EQ_ULL(rc,
		      STAMP_REFLECTOR_INPUT_INVALID_PAYLOAD,
		      "reflector input check invalid payload (<14)");

	rc = stamp_check_reflector_input(buffer, STAMP_BASE_PACKET_SIZE, 0);
	EXPECT_EQ_ULL(rc,
		      STAMP_REFLECTOR_INPUT_MISSING_TTL,
		      "reflector input check missing ttl");

	rc = stamp_check_reflector_input(buffer, STAMP_BASE_PACKET_SIZE, 64);
	EXPECT_EQ_ULL(rc,
		      STAMP_REFLECTOR_INPUT_OK,
		      "reflector input check ok");

	// invalid payload が TTL 判定より優先されること
	memset(buffer, 0, sizeof(buffer)); // multiplier=0
	rc = stamp_check_reflector_input(buffer, STAMP_BASE_PACKET_SIZE, 0);
	EXPECT_EQ_ULL(rc,
		      STAMP_REFLECTOR_INPUT_INVALID_PAYLOAD,
		      "reflector input check prioritizes invalid payload");
}

// =============================================================================
// Phase 6: RTT計算ロジックテスト
// =============================================================================

static void test_rtt_calculation(void)
{
	double fwd;
	double bwd;
	double rtt;
	double offset;

	// ケース1: 対称遅延（クロック同期済み）
	// T1=0, T2=0.001, T3=0.002, T4=0.003
	fwd = stamp_forward_delay(0.0, 0.001);
	bwd = stamp_backward_delay(0.002, 0.003);
	rtt = stamp_rtt(fwd, bwd);
	offset = stamp_clock_offset(0.0, 0.001, 0.002, 0.003);
	EXPECT_NEAR_DOUBLE(fwd, 1.0, 0.001, "RTT symmetric forward 1ms");
	EXPECT_NEAR_DOUBLE(bwd, 1.0, 0.001, "RTT symmetric backward 1ms");
	EXPECT_NEAR_DOUBLE(rtt, 2.0, 0.001, "RTT symmetric total 2ms");
	EXPECT_NEAR_DOUBLE(offset, 0.0, 0.001, "RTT symmetric offset 0ms");

	// ケース2: 非対称遅延
	// T1=0, T2=0.002, T3=0.003, T4=0.004
	fwd = stamp_forward_delay(0.0, 0.002);
	bwd = stamp_backward_delay(0.003, 0.004);
	rtt = stamp_rtt(fwd, bwd);
	EXPECT_NEAR_DOUBLE(fwd, 2.0, 0.001, "RTT asymmetric forward 2ms");
	EXPECT_NEAR_DOUBLE(bwd, 1.0, 0.001, "RTT asymmetric backward 1ms");
	EXPECT_NEAR_DOUBLE(rtt, 3.0, 0.001, "RTT asymmetric total 3ms");

	// ケース3: クロックオフセットあり
	// T1=0, T2=0.002, T3=0.003, T4=0.002（fwdは同値だが異なるテストケース）
	fwd = stamp_forward_delay(0.0, 0.002); // cppcheck-suppress redundantAssignment
	bwd = stamp_backward_delay(0.003, 0.002);
	rtt = stamp_rtt(fwd, bwd);
	offset = stamp_clock_offset(0.0, 0.002, 0.003, 0.002);
	EXPECT_NEAR_DOUBLE(rtt, 1.0, 0.001, "RTT with offset total 1ms");
	EXPECT_NEAR_DOUBLE(offset, 1.5, 0.001, "RTT clock offset 1.5ms");

	// ケース4: ゼロ遅延（ローカルホスト理想ケース）
	fwd = stamp_forward_delay(1.0, 1.0);
	bwd = stamp_backward_delay(1.0, 1.0);
	rtt = stamp_rtt(fwd, bwd);
	offset = stamp_clock_offset(1.0, 1.0, 1.0, 1.0);
	EXPECT_NEAR_DOUBLE(rtt, 0.0, 0.001, "RTT zero delay");
	EXPECT_NEAR_DOUBLE(offset, 0.0, 0.001, "RTT zero offset");

	// ケース5: 大きな遅延
	fwd = stamp_forward_delay(0.0, 0.1);
	bwd = stamp_backward_delay(0.15, 0.25);
	rtt = stamp_rtt(fwd, bwd);
	EXPECT_NEAR_DOUBLE(fwd, 100.0, 0.1, "RTT large forward 100ms");
	EXPECT_NEAR_DOUBLE(bwd, 100.0, 0.1, "RTT large backward 100ms");
	EXPECT_NEAR_DOUBLE(rtt, 200.0, 0.1, "RTT large total 200ms");
}

static void test_negative_delay_detection(void)
{
	// 負の往路遅延
	// T1=1.0, T2=0.5 (Reflectorの時計が遅れている)
	double fwd = stamp_forward_delay(1.0, 0.5);
	EXPECT_TRUE(fwd < 0, "Negative forward delay detected");

	// 負の復路遅延
	// T3=1.0, T4=0.9
	double bwd = stamp_backward_delay(1.0, 0.9);
	EXPECT_TRUE(bwd < 0, "Negative backward delay detected");
}

// =============================================================================
// Phase 7: 統計計算テスト
// =============================================================================

static void test_statistics_calculation(void)
{
	// stamp_jitter: 値 {1,2,3,4,5}, sum=15, sum_sq=55, count=5
	// avg=3, var=55/5-9=2, std=sqrt(2)≈1.414
	double jitter = stamp_jitter(15.0, 55.0, 5);
	EXPECT_NEAR_DOUBLE(jitter,
			   1.414,
			   0.01,
			   "stamp_jitter with known values");

	// 単一サンプル: jitter=0
	double single_jitter = stamp_jitter(2.5, 6.25, 1);
	EXPECT_NEAR_DOUBLE(single_jitter,
			   0.0,
			   0.001,
			   "stamp_jitter single sample");
}

static void test_packet_loss_calculation(void)
{
	// 0% ロス
	EXPECT_NEAR_DOUBLE(stamp_packet_loss(100, 100),
			   0.0,
			   0.001,
			   "packet loss 0%");

	// 5% ロス
	EXPECT_NEAR_DOUBLE(stamp_packet_loss(100, 95),
			   5.0,
			   0.001,
			   "packet loss 5%");

	// 50% ロス
	EXPECT_NEAR_DOUBLE(stamp_packet_loss(100, 50),
			   50.0,
			   0.001,
			   "packet loss 50%");

	// 100% ロス
	EXPECT_NEAR_DOUBLE(stamp_packet_loss(100, 0),
			   100.0,
			   0.001,
			   "packet loss 100%");

	// 送信0の場合（ゼロ除算防止）
	EXPECT_NEAR_DOUBLE(stamp_packet_loss(0, 0),
			   0.0,
			   0.001,
			   "packet loss sent=0");
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

	// フィールド検証: バイトレベルで big-endian を確認
	{
		const uint8_t *b = (const uint8_t *)&pkt.seq_num;
		EXPECT_EQ_ULL(b[0], 0x00, "sender seq_num byte[0]");
		EXPECT_EQ_ULL(b[1], 0x00, "sender seq_num byte[1]");
		EXPECT_EQ_ULL(b[2],
			      0x30,
			      "sender seq_num byte[2]"); // 12345 = 0x3039
		EXPECT_EQ_ULL(b[3], 0x39, "sender seq_num byte[3]");
	}
	{
		const uint8_t *b = (const uint8_t *)&pkt.error_estimate;
		EXPECT_EQ_ULL(
			b[0],
			0x00,
			"sender error_estimate byte[0]"); // 0x0001 big-endian
		EXPECT_EQ_ULL(b[1], 0x01, "sender error_estimate byte[1]");
	}

	// MBZフィールドがゼロであること
	{
		int mbz_ok = 1;
		size_t mbz_fail_idx = 0;
		for (size_t i = 0; i < sizeof(pkt.mbz); i++) {
			if (pkt.mbz[i] != 0) {
				mbz_ok = 0;
				mbz_fail_idx = i;
				break;
			}
		}
		if (!mbz_ok) {
			char msg[80];
			snprintf(msg,
				 sizeof(msg),
				 "sender packet MBZ byte[%zu]=0x%02x",
				 mbz_fail_idx,
				 pkt.mbz[mbz_fail_idx]);
			EXPECT_TRUE(0, msg);
		} else {
			EXPECT_TRUE(1, "sender packet MBZ all zeros");
		}
	}

	// タイムスタンプフィールド: バイトレベル検証
	pkt.timestamp_sec = htonl(0xDEADBEEF);
	{
		const uint8_t *b = (const uint8_t *)&pkt.timestamp_sec;
		EXPECT_EQ_ULL(b[0], 0xDE, "sender timestamp_sec byte[0]");
		EXPECT_EQ_ULL(b[1], 0xAD, "sender timestamp_sec byte[1]");
		EXPECT_EQ_ULL(b[2], 0xBE, "sender timestamp_sec byte[2]");
		EXPECT_EQ_ULL(b[3], 0xEF, "sender timestamp_sec byte[3]");
	}
	pkt.timestamp_frac = htonl(0xCAFEBABE);
	{
		const uint8_t *b = (const uint8_t *)&pkt.timestamp_frac;
		EXPECT_EQ_ULL(b[0], 0xCA, "sender timestamp_frac byte[0]");
		EXPECT_EQ_ULL(b[1], 0xFE, "sender timestamp_frac byte[1]");
		EXPECT_EQ_ULL(b[2], 0xBA, "sender timestamp_frac byte[2]");
		EXPECT_EQ_ULL(b[3], 0xBE, "sender timestamp_frac byte[3]");
	}

	// シーケンス番号の境界値: バイトレベル検証
	pkt.seq_num = htonl(0);
	{
		const uint8_t *b = (const uint8_t *)&pkt.seq_num;
		EXPECT_TRUE(b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0,
			    "sender seq_num 0 all zeros");
	}
	pkt.seq_num = htonl(0xFFFFFFFF);
	{
		const uint8_t *b = (const uint8_t *)&pkt.seq_num;
		EXPECT_TRUE(b[0] == 0xFF && b[1] == 0xFF && b[2] == 0xFF &&
				    b[3] == 0xFF,
			    "sender seq_num max all FF");
	}
}

static void test_reflector_packet_fields(void)
{
	struct stamp_sender_packet sender;
	struct stamp_reflector_packet reflector;
	const uint8_t *b; // 各フィールドのバイト検証で再利用

	// 送信者パケットを設定
	memset(&sender, 0, sizeof(sender));
	sender.seq_num = htonl(42);
	sender.timestamp_sec = htonl(0x12345678);
	sender.timestamp_frac = htonl(0xABCDEF00);
	sender.error_estimate = htons(ERROR_ESTIMATE_DEFAULT);

	// production の反射パケット構築ロジック (reflect_packet が呼ぶ本体) を
	// 実際に呼び出して検証する。旧実装はこのコピー処理をテスト内で手書きして
	// おり、自分で代入した値を読み返すだけのトートロジーになっていた。
	memset(&reflector, 0, sizeof(reflector));
	memcpy(&reflector, &sender, sizeof(sender));
	// reflector 自身の Error Estimate は sender の値(DEFAULT=0x0001)とは
	// 別値(PTP=0x4001)を渡す。両フィールドは offset 12 で重なるため、別値に
	// しないと memcpy 残骸と区別できず production の上書きを検証できない。
	stamp_build_reflector_packet((uint8_t *)&reflector,
				     STAMP_BASE_PACKET_SIZE,
				     64,		// sender_ttl
				     htonl(0x11223344), // rx_sec (T2)
				     htonl(0x55667788), // rx_frac (T2)
				     htons(ERROR_ESTIMATE_PTP_DEFAULT));

	// 検証: バイトレベルで big-endian を確認
	// seq_num = htonl(42) = 0x0000002A big-endian
	{
		b = (const uint8_t *)&reflector.seq_num;
		EXPECT_EQ_ULL(b[0], 0x00, "reflector seq_num byte[0]");
		EXPECT_EQ_ULL(b[1], 0x00, "reflector seq_num byte[1]");
		EXPECT_EQ_ULL(b[2], 0x00, "reflector seq_num byte[2]");
		EXPECT_EQ_ULL(b[3], 0x2A, "reflector seq_num byte[3]");
	}
	{
		b = (const uint8_t *)&reflector.sender_seq_num;
		EXPECT_EQ_ULL(b[0], 0x00, "reflector sender_seq_num byte[0]");
		EXPECT_EQ_ULL(b[3], 0x2A, "reflector sender_seq_num byte[3]");
	}
	// sender_ts_sec = htonl(0x12345678)
	{
		b = (const uint8_t *)&reflector.sender_ts_sec;
		EXPECT_EQ_ULL(b[0], 0x12, "reflector sender_ts_sec byte[0]");
		EXPECT_EQ_ULL(b[1], 0x34, "reflector sender_ts_sec byte[1]");
		EXPECT_EQ_ULL(b[2], 0x56, "reflector sender_ts_sec byte[2]");
		EXPECT_EQ_ULL(b[3], 0x78, "reflector sender_ts_sec byte[3]");
	}
	// sender_ts_frac = htonl(0xABCDEF00)
	{
		b = (const uint8_t *)&reflector.sender_ts_frac;
		EXPECT_EQ_ULL(b[0], 0xAB, "reflector sender_ts_frac byte[0]");
		EXPECT_EQ_ULL(b[1], 0xCD, "reflector sender_ts_frac byte[1]");
		EXPECT_EQ_ULL(b[2], 0xEF, "reflector sender_ts_frac byte[2]");
		EXPECT_EQ_ULL(b[3], 0x00, "reflector sender_ts_frac byte[3]");
	}
	// sender_err_est = htons(ERROR_ESTIMATE_DEFAULT)
	{
		b = (const uint8_t *)&reflector.sender_err_est;
		EXPECT_EQ_ULL(b[0], 0x00, "reflector sender_err_est byte[0]");
		EXPECT_EQ_ULL(b[1], 0x01, "reflector sender_err_est byte[1]");
	}
	EXPECT_EQ_ULL(reflector.sender_ttl, 64, "reflector packet sender_ttl");

	// Reflector が設定する受信タイムスタンプ T2 と Error Estimate
	// (production stamp_build_reflector_packet の出力を検証)
	{
		b = (const uint8_t *)&reflector.rx_sec;
		EXPECT_EQ_ULL(b[0], 0x11, "reflector rx_sec byte[0]");
		EXPECT_EQ_ULL(b[3], 0x44, "reflector rx_sec byte[3]");
	}
	{
		// ERROR_ESTIMATE_PTP_DEFAULT = 0x4001 → big-endian {0x40, 0x01}。
		// byte[0]=0x40 は memcpy 残骸(0x00)と異なるため、production が
		// error_estimate を上書きしたことを実証する。
		b = (const uint8_t *)&reflector.error_estimate;
		EXPECT_EQ_ULL(b[0], 0x40, "reflector error_estimate byte[0]");
		EXPECT_EQ_ULL(b[1], 0x01, "reflector error_estimate byte[1]");
	}

	// MBZフィールド検証
	EXPECT_EQ_ULL(reflector.mbz_1, 0, "reflector packet mbz_1");
	EXPECT_EQ_ULL(reflector.mbz_2, 0, "reflector packet mbz_2");
	{
		int mbz3_ok = 1;
		size_t mbz3_fail_idx = 0;
		for (size_t i = 0; i < sizeof(reflector.mbz_3); i++) {
			if (reflector.mbz_3[i] != 0) {
				mbz3_ok = 0;
				mbz3_fail_idx = i;
				break;
			}
		}
		if (!mbz3_ok) {
			char msg[80];
			snprintf(msg,
				 sizeof(msg),
				 "reflector packet mbz_3 byte[%zu]=0x%02x",
				 mbz3_fail_idx,
				 reflector.mbz_3[mbz3_fail_idx]);
			EXPECT_TRUE(0, msg);
		} else {
			EXPECT_TRUE(1, "reflector packet mbz_3 all zeros");
		}
	}

	// TTL/Hop Limit: verify struct layout instead of assign-and-check
	EXPECT_EQ_ULL(sizeof(reflector.sender_ttl), 1, "sender_ttl is 1 byte");
	EXPECT_EQ_ULL(offsetof(struct stamp_reflector_packet, sender_ttl),
		      40,
		      "sender_ttl at offset 40");
}

/**
 * Sender TTL=255 設定テスト (RFC 4656 Section 4.1.2 SHOULD)
 */
static void test_sender_ttl_setting(void)
{
	/* IPv4: IP_TTL=255 を設定して getsockopt で検証 */
	{
		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (SOCKET_ERROR_CHECK(s)) {
			SKIP_TEST("sender TTL IPv4 socket creation failed");
		} else {
			int ttl = IP_TTL_MAX;
			int rc = setsockopt(s,
					    IPPROTO_IP,
					    IP_TTL,
					    (const char *)&ttl,
					    sizeof(ttl));
			EXPECT_TRUE(rc == 0, "setsockopt IP_TTL=255");

			int got = 0;
			socklen_t len = sizeof(got);
			rc = getsockopt(s,
					IPPROTO_IP,
					IP_TTL,
					(char *)&got,
					&len);
			EXPECT_TRUE(rc == 0, "getsockopt IP_TTL");
			EXPECT_EQ_ULL((unsigned)got,
				      255,
				      "IP_TTL value is 255");
			CLOSE_SOCKET(s);
		}
	}

	/* IPv6: IPV6_UNICAST_HOPS=255 を設定して getsockopt で検証 */
	{
		SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (SOCKET_ERROR_CHECK(s)) {
			SKIP_TEST("sender TTL IPv6 socket creation failed");
		} else {
			int hops = IP_TTL_MAX;
			int rc = setsockopt(s,
					    IPPROTO_IPV6,
					    IPV6_UNICAST_HOPS,
					    (const char *)&hops,
					    sizeof(hops));
			EXPECT_TRUE(rc == 0, "setsockopt IPV6_UNICAST_HOPS=255");

			int got = 0;
			socklen_t len = sizeof(got);
			rc = getsockopt(s,
					IPPROTO_IPV6,
					IPV6_UNICAST_HOPS,
					(char *)&got,
					&len);
			EXPECT_TRUE(rc == 0, "getsockopt IPV6_UNICAST_HOPS");
			EXPECT_EQ_ULL((unsigned)got,
				      255,
				      "IPV6_UNICAST_HOPS value is 255");
			CLOSE_SOCKET(s);
		}
	}
}

// =============================================================================
// Phase 10: HW タイムスタンプ優先選択テスト (Linux)
// =============================================================================

#ifdef __linux__
/**
 * msghdr + 制御メッセージの構築ヘルパー
 * HWタイムスタンプテストのボイラープレートを削減
 */
static void build_mock_msghdr_timestamping(struct msghdr *msg,
					   struct iovec *iov,
					   char *data,
					   char *control,
					   size_t control_size,
					   int cmsg_type,
					   const void *cmsg_data,
					   size_t cmsg_data_len)
{
	memset(control, 0, control_size);
	memset(msg, 0, sizeof(*msg));
	*data = 0;
	iov->iov_base = data;
	iov->iov_len = 1;
	msg->msg_iov = iov;
	msg->msg_iovlen = 1;
	msg->msg_control = control;
	msg->msg_controllen = control_size;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = cmsg_type;
	cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
	memcpy(CMSG_DATA(cmsg), cmsg_data, cmsg_data_len);
	msg->msg_controllen = (size_t)((char *)cmsg + cmsg->cmsg_len - control);
}

/**
 * ts[2] (raw HW) と ts[0] (SW) の両方が非ゼロの場合、ts[2]
 * が選択されることを検証
 */
static void test_stamp_extract_kernel_timestamp_linux_hw_priority(void)
{
	struct timespec ts[3] = {
		{1000, 111111111}, // ts[0] (software)
		{0, 0},		   // ts[1] (legacy)
		{1000, 222222222}, // ts[2] (raw HW)
	};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPING,
				       ts,
				       sizeof(ts));

	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	EXPECT_TRUE(result, "HW priority: timestamp extracted");

	// ts[2] の値 (sec=1000, nsec=222222222)
	// を独立計算した定数リテラルで検証 sec: 1000 + NTP_OFFSET(2208988800) =
	// 2208989800 frac: (222222222 * 4294967296 + 500000000) / 1000000000 =
	// 954437176
	EXPECT_EQ_ULL(ntohl(ntp_sec),
		      2208989800U,
		      "HW priority: sec matches ts[2]");
	EXPECT_EQ_ULL(ntohl(ntp_frac),
		      954437176U,
		      "HW priority: frac matches ts[2]");
}

/**
 * ts[2] がゼロで ts[0] のみ非ゼロの場合、ts[0] にフォールバックすることを検証
 */
static void test_stamp_extract_kernel_timestamp_linux_sw_fallback(void)
{
	struct timespec ts[3] = {
		{2000, 333333333}, // ts[0] (software)
		{0, 0},		   // ts[1] (legacy)
		{0, 0},		   // ts[2] (raw HW): ゼロ (HW 非対応)
	};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPING,
				       ts,
				       sizeof(ts));

	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	EXPECT_TRUE(result, "SW fallback: timestamp extracted");

	// ts[0] の値 (sec=2000, nsec=333333333)
	// を独立計算した定数リテラルで検証 sec: 2000 + NTP_OFFSET(2208988800) =
	// 2208990800 frac: (333333333 * 4294967296 + 500000000) / 1000000000 =
	// 1431655764
	EXPECT_EQ_ULL(ntohl(ntp_sec),
		      2208990800U,
		      "SW fallback: sec matches ts[0]");
	EXPECT_EQ_ULL(ntohl(ntp_frac),
		      1431655764U,
		      "SW fallback: frac matches ts[0]");
}

/**
 * HW優先 + PTPモード: fracフィールドがナノ秒直値であることを検証
 */
static void test_stamp_extract_kernel_timestamp_linux_ptp_hw(void)
{
	struct timespec ts[3] = {
		{1000, 111111111}, // ts[0] (software)
		{0, 0},		   // ts[1] (legacy)
		{1000, 222222222}, // ts[2] (raw HW)
	};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPING,
				       ts,
				       sizeof(ts));

	uint32_t ptp_sec = 0;
	uint32_t ptp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ptp_sec,
							   &ptp_frac,
							   true);
	EXPECT_TRUE(result, "PTP HW: timestamp extracted");

	EXPECT_EQ_ULL(ntohl(ptp_sec), 2208989800U, "PTP HW: sec matches ts[2]");
	// PTPモードではfracはナノ秒直値
	EXPECT_EQ_ULL(ntohl(ptp_frac),
		      222222222U,
		      "PTP HW: frac is raw nanoseconds");
}

/**
 * SWフォールバック + PTPモード
 */
static void test_stamp_extract_kernel_timestamp_linux_ptp_sw(void)
{
	struct timespec ts[3] = {
		{2000, 333333333}, // ts[0] (software)
		{0, 0},		   // ts[1] (legacy)
		{0, 0},		   // ts[2] (raw HW): ゼロ
	};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPING,
				       ts,
				       sizeof(ts));

	uint32_t ptp_sec = 0;
	uint32_t ptp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ptp_sec,
							   &ptp_frac,
							   true);
	EXPECT_TRUE(result, "PTP SW: timestamp extracted");

	EXPECT_EQ_ULL(ntohl(ptp_sec), 2208990800U, "PTP SW: sec matches ts[0]");
	EXPECT_EQ_ULL(ntohl(ptp_frac),
		      333333333U,
		      "PTP SW: frac is raw nanoseconds");
}

/**
 * SCM_TIMESTAMPNS パステスト
 */
static void test_stamp_extract_kernel_timestamp_linux_timestampns(void)
{
	struct timespec ts = {3000, 444444444};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPNS,
				       &ts,
				       sizeof(ts));

	// NTPモード
	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	EXPECT_TRUE(result, "TIMESTAMPNS NTP: timestamp extracted");
	// sec: 3000 + NTP_OFFSET(2208988800) = 2208991800
	// frac: (444444444 * 4294967296 + 500000000) / 1000000000 = 1908874352
	EXPECT_EQ_ULL(ntohl(ntp_sec), 2208991800U, "TIMESTAMPNS NTP: sec");
	EXPECT_EQ_ULL(ntohl(ntp_frac), 1908874352U, "TIMESTAMPNS NTP: frac");

	// PTPモード
	uint32_t ptp_sec = 0;
	uint32_t ptp_frac = 0;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPNS,
				       &ts,
				       sizeof(ts));
	result = stamp_extract_kernel_timestamp_linux(&msg,
						      &ptp_sec,
						      &ptp_frac,
						      true);
	EXPECT_TRUE(result, "TIMESTAMPNS PTP: timestamp extracted");
	EXPECT_EQ_ULL(ntohl(ptp_sec), 2208991800U, "TIMESTAMPNS PTP: sec");
	EXPECT_EQ_ULL(ntohl(ptp_frac),
		      444444444U,
		      "TIMESTAMPNS PTP: frac is raw nsec");
}

/**
 * SCM_TIMESTAMP パステスト (timeval)
 */
static void test_stamp_extract_kernel_timestamp_linux_timestamp(void)
{
	struct timeval tv = {4000, 555555};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMP,
				       &tv,
				       sizeof(tv));

	// NTPモード: stamp_timeval_to_ntp() 経由
	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	EXPECT_TRUE(result, "TIMESTAMP NTP: timestamp extracted");
	// sec: 4000 + NTP_OFFSET(2208988800) = 2208992800
	// frac: (555555 * 4294967296 + 500000) / 1000000 = 2386090556
	EXPECT_EQ_ULL(ntohl(ntp_sec), 2208992800U, "TIMESTAMP NTP: sec");
	EXPECT_EQ_ULL(ntohl(ntp_frac), 2386090556U, "TIMESTAMP NTP: frac");

	// PTPモード: timeval→nsec変換
	uint32_t ptp_sec = 0;
	uint32_t ptp_frac = 0;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMP,
				       &tv,
				       sizeof(tv));
	result = stamp_extract_kernel_timestamp_linux(&msg,
						      &ptp_sec,
						      &ptp_frac,
						      true);
	EXPECT_TRUE(result, "TIMESTAMP PTP: timestamp extracted");
	EXPECT_EQ_ULL(ntohl(ptp_sec), 2208992800U, "TIMESTAMP PTP: sec");
	// timeval usec -> nsec: 555555 * 1000 = 555555000
	EXPECT_EQ_ULL(ntohl(ptp_frac),
		      555555000U,
		      "TIMESTAMP PTP: frac = usec * 1000");
}
#endif // __linux__

// =============================================================================
// Phase 9: Error Estimate フィールドテスト
// =============================================================================

static void test_error_estimate_fields(void)
{
	// Raw 値検証（独立リテラル）
	EXPECT_EQ_ULL(ERROR_ESTIMATE_DEFAULT, 0x0001, "EE_DEFAULT raw value");

	// ビットフィールド分解テスト: リテラル 0x0001 を分解
	EXPECT_TRUE((0x0001 & 0x8000) == 0, "EE_DEFAULT S bit clear");
	EXPECT_TRUE((0x0001 & 0x4000) == 0, "EE_DEFAULT Z bit clear");
	EXPECT_EQ_ULL((0x0001 >> 8) & 0x3F, 0, "EE_DEFAULT scale=0");
	EXPECT_EQ_ULL(0x0001 & 0xFF, 1, "EE_DEFAULT mult=1");

	// カスタム Error Estimate の構築テスト
	// S=1, Z=0, Scale=5, Mult=10 → 0x850A
	uint16_t custom_ee = ERROR_ESTIMATE_S_BIT | (5 << 8) | 10;
	EXPECT_EQ_ULL(custom_ee, 0x850A, "custom EE raw value");
	// 分解は独立リテラル 0x850A に対して実施
	EXPECT_EQ_ULL((0x850A >> 8) & 0x3F, 5, "custom scale from literal");
	EXPECT_EQ_ULL(0x850A & 0xFF, 10, "custom mult from literal");

	// Z=1 (PTP format) のテスト
	uint16_t ptp_ee = ERROR_ESTIMATE_S_BIT | ERROR_ESTIMATE_Z_BIT | 1;
	EXPECT_TRUE((ptp_ee & ERROR_ESTIMATE_Z_BIT) != 0,
		    "PTP format Z bit set");

	// S=0 (unsynchronized) のテスト
	uint16_t unsync_ee = 1; // S=0, Z=0, Scale=0, Mult=1
	EXPECT_TRUE((unsync_ee & ERROR_ESTIMATE_S_BIT) == 0,
		    "Unsynchronized S bit clear");
}

// =============================================================================
// Phase 11: PTP タイムスタンプ変換テスト
// =============================================================================

static void test_stamp_ptp_to_double(void)
{
	// エポック: NTP_OFFSET 秒, 0 ナノ秒 → UNIX 0.0
	uint32_t sec = htonl(NTP_OFFSET);
	uint32_t nsec = htonl(0);
	double t0 = stamp_ptp_to_double(sec, nsec);
	EXPECT_NEAR_DOUBLE(t0, 0.0, 1e-9, "stamp_ptp_to_double epoch");

	// 1.5秒: NTP_OFFSET+1, 500000000 ナノ秒
	sec = htonl(NTP_OFFSET + 1);
	nsec = htonl(500000000);
	double t1 = stamp_ptp_to_double(sec, nsec);
	EXPECT_NEAR_DOUBLE(t1, 1.5, 1e-9, "stamp_ptp_to_double 1.5s");

	// 境界値: 999999999 ナノ秒 (ほぼ1秒)
	sec = htonl(NTP_OFFSET + 10);
	nsec = htonl(999999999);
	double t2 = stamp_ptp_to_double(sec, nsec);
	EXPECT_NEAR_DOUBLE(t2, 11.0, 1e-6, "stamp_ptp_to_double max nsec");

	// 0ナノ秒
	sec = htonl(NTP_OFFSET + 100);
	nsec = htonl(0);
	double t3 = stamp_ptp_to_double(sec, nsec);
	EXPECT_NEAR_DOUBLE(t3, 100.0, 1e-9, "stamp_ptp_to_double zero nsec");
}

#ifndef _WIN32
static void test_stamp_timespec_to_ptp(void)
{
	uint32_t sec;
	uint32_t nsec;

	// Unix epoch → NTP_OFFSET, 0
	struct timespec ts_epoch = {0, 0};
	stamp_timespec_to_ptp(&ts_epoch, &sec, &nsec);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET,
		      "stamp_timespec_to_ptp epoch sec");
	EXPECT_EQ_ULL(ntohl(nsec), 0, "stamp_timespec_to_ptp epoch nsec");

	// 1.5秒
	struct timespec ts_1_5 = {1, 500000000};
	stamp_timespec_to_ptp(&ts_1_5, &sec, &nsec);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET + 1,
		      "stamp_timespec_to_ptp 1.5s sec");
	EXPECT_EQ_ULL(ntohl(nsec),
		      500000000,
		      "stamp_timespec_to_ptp 1.5s nsec");

	// 境界値: tv_nsec = 999999999
	struct timespec ts_max = {100, 999999999};
	stamp_timespec_to_ptp(&ts_max, &sec, &nsec);
	EXPECT_EQ_ULL(ntohl(sec),
		      NTP_OFFSET + 100,
		      "stamp_timespec_to_ptp max sec");
	EXPECT_EQ_ULL(ntohl(nsec), 999999999, "stamp_timespec_to_ptp max nsec");
}
#endif

static void test_ntp_ptp_cross_conversion(void)
{
	// NTP → ナノ秒 → NTP ラウンドトリップ
	// 0.5秒 = NTP小数部 0x80000000
	uint32_t ntp_frac_half = 0x80000000U;
	uint32_t nsec = stamp_ntp_frac_to_nsec(ntp_frac_half);
	EXPECT_TRUE(nsec >= 499999999 && nsec <= 500000001,
		    "stamp_ntp_frac_to_nsec(0x80000000) ≈ 500000000");

	uint32_t ntp_back = stamp_nsec_to_ntp_frac(nsec);
	// ラウンドトリップで誤差1以内
	EXPECT_TRUE(ntp_back >= 0x7FFFFFFE && ntp_back <= 0x80000002,
		    "nsec_to_ntp_frac round-trip 0.5s");

	// 0ナノ秒
	EXPECT_EQ_ULL(stamp_ntp_frac_to_nsec(0),
		      0,
		      "stamp_ntp_frac_to_nsec(0)");
	EXPECT_EQ_ULL(stamp_nsec_to_ntp_frac(0),
		      0,
		      "stamp_nsec_to_ntp_frac(0)");

	// 最大値 (丸めにより 1000000000 になり得る)
	uint32_t nsec_max = stamp_ntp_frac_to_nsec(0xFFFFFFFF);
	EXPECT_TRUE(
		nsec_max >= 999999999 && nsec_max <= 1000000000,
		"stamp_ntp_frac_to_nsec(0xFFFFFFFF) ≈ 999999999-1000000000");

	// 1ナノ秒
	uint32_t ntp_1ns = stamp_nsec_to_ntp_frac(1);
	EXPECT_TRUE(ntp_1ns >= 4 && ntp_1ns <= 5,
		    "stamp_nsec_to_ntp_frac(1) ≈ 4-5");
}

static void test_stamp_timestamp_to_double_dispatch(void)
{
	// Z=0 (NTP) → stamp_ntp_to_double
	uint32_t sec = htonl(NTP_OFFSET + 1);
	uint32_t frac = htonl(0x80000000U); // 0.5秒 in NTP
	double ntp_result =
		stamp_timestamp_to_double(sec, frac, ERROR_ESTIMATE_DEFAULT);
	EXPECT_NEAR_DOUBLE(ntp_result,
			   1.5,
			   1e-9,
			   "stamp_timestamp_to_double Z=0 (NTP)");

	// Z=1 (PTP) → stamp_ptp_to_double
	uint32_t nsec = htonl(500000000); // 0.5秒 in PTP
	double ptp_result =
		stamp_timestamp_to_double(sec,
					  nsec,
					  ERROR_ESTIMATE_PTP_DEFAULT);
	EXPECT_NEAR_DOUBLE(ptp_result,
			   1.5,
			   1e-9,
			   "stamp_timestamp_to_double Z=1 (PTP)");

	// NTP と PTP で同じ 0.5 秒を表すが、小数部エンコードが異なる
	EXPECT_NEAR_DOUBLE(ntp_result,
			   ptp_result,
			   1e-6,
			   "NTP and PTP 0.5s agree");
}

static void test_error_estimate_ptp_default(void)
{
	// Raw 値検証（独立リテラル）
	EXPECT_EQ_ULL(ERROR_ESTIMATE_PTP_DEFAULT,
		      0x4001,
		      "EE_PTP_DEFAULT raw value");

	// ビット分解は独立リテラル 0x4001 に対して実施
	EXPECT_TRUE((0x4001 & 0x8000) == 0, "PTP default S bit clear");
	EXPECT_TRUE((0x4001 & 0x4000) != 0, "PTP default Z bit");
	EXPECT_EQ_ULL((0x4001 >> 8) & 0x3F, 0, "PTP default scale = 0");
	EXPECT_EQ_ULL(0x4001 & 0xFF, 1, "PTP default multiplier = 1");
}

static void test_stamp_get_ptp_timestamp(void)
{
	uint32_t sec = 0;
	uint32_t nsec = 0;
	time_t before = time(NULL);
	int rc = stamp_get_ptp_timestamp(&sec, &nsec);
	time_t after = time(NULL);
	EXPECT_TRUE(rc == 0, "stamp_get_ptp_timestamp returns 0");

	// ナノ秒部分は 0-999999999 の範囲
	uint32_t nsec_host = ntohl(nsec);
	EXPECT_TRUE(nsec_host <= PTP_NSEC_MAX, "PTP nsec within valid range");

	// PTP → double で壁時計ウィンドウ内
	double t_ptp = stamp_ptp_to_double(sec, nsec);
	EXPECT_TRUE(t_ptp >= (double)(before - 1) &&
			    t_ptp <= (double)(after + 1),
		    "PTP timestamp within [before-1, after+1] window");
}

// =============================================================================
// Phase 12: PHC マクロテスト
// =============================================================================

#ifdef __linux__
static void test_phc_clockid_macros(void)
{
	// FD_TO_CLOCKID → CLOCKID_TO_FD ラウンドトリップ
	for (int fd = 3; fd < 10; fd++) {
		clockid_t clk = FD_TO_CLOCKID(fd);
		unsigned int fd_back = CLOCKID_TO_FD(clk);
		char msg[64];
		snprintf(msg,
			 sizeof(msg),
			 "FD_TO_CLOCKID/CLOCKID_TO_FD round-trip fd=%d",
			 fd);
		EXPECT_EQ_ULL(fd_back, (unsigned int)fd, msg);
	}
}

static void test_phc_timestamp_with_realtime(void)
{
	// CLOCK_REALTIME を使って出力形式を検証
	uint32_t sec = 0;
	uint32_t frac = 0;

	// NTP モード
	time_t before = time(NULL);
	int rc = stamp_get_phc_timestamp(CLOCK_REALTIME, &sec, &frac, false);
	time_t after = time(NULL);
	EXPECT_TRUE(rc == 0, "stamp_get_phc_timestamp NTP mode success");
	if (rc == 0) {
		double t_ntp = stamp_ntp_to_double(sec, frac);
		EXPECT_TRUE(t_ntp >= (double)(before - 1) &&
				    t_ntp <= (double)(after + 1),
			    "PHC NTP timestamp within [before-1, after+1]");
	}

	// PTP モード
	before = time(NULL);
	rc = stamp_get_phc_timestamp(CLOCK_REALTIME, &sec, &frac, true);
	after = time(NULL);
	EXPECT_TRUE(rc == 0, "stamp_get_phc_timestamp PTP mode success");
	if (rc == 0) {
		double t_ptp = stamp_ptp_to_double(sec, frac);
		EXPECT_TRUE(t_ptp >= (double)(before - 1) &&
				    t_ptp <= (double)(after + 1),
			    "PHC PTP timestamp within [before-1, after+1]");

		uint32_t nsec_host = ntohl(frac);
		EXPECT_TRUE(nsec_host <= PTP_NSEC_MAX,
			    "PHC PTP nsec within valid range");
	}
}

static void test_hwts_caps_phc_index(void)
{
	// phc_index の初期値テスト
	struct stamp_hwts_caps caps;
	caps.rx_hw = true;
	caps.tx_hw = true;
	caps.phc_index = 42;

	// ソケット作成して stamp_detect_hwts_caps
	// を呼ぶ（ダミーインターフェース）
	SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!SOCKET_ERROR_CHECK(sockfd)) {
		// stamp_detect_hwts_caps は ifname=NULL で -1 を返し、caps
		// を初期化
		int rc = stamp_detect_hwts_caps(sockfd, NULL, &caps);
		EXPECT_TRUE(rc == -1, "stamp_detect_hwts_caps NULL ifname");
		EXPECT_TRUE(caps.phc_index == -1,
			    "phc_index initialized to -1");
		EXPECT_TRUE(caps.rx_hw == false, "rx_hw initialized to false");
		EXPECT_TRUE(caps.tx_hw == false, "tx_hw initialized to false");
		CLOSE_SOCKET(sockfd);
	} else {
		SKIP_TEST("test_hwts_caps_phc_index (socket creation failed)");
	}
}
#endif // __linux__

// =============================================================================
// Phase 13: One-way delay 統計テスト
// =============================================================================

// stamp_ntp_to_double / stamp_ptp_to_double のエッジケーステスト
static void test_stamp_ntp_to_double_edge_cases(void)
{
	// sec=0 (NTPエポック 1900年): unsigned underflow → 大きな負値
	uint32_t sec = htonl(0);
	uint32_t frac = htonl(0);
	double t = stamp_ntp_to_double(sec, frac);
	// (0 - NTP_OFFSET) は unsigned underflow により大きい正値にラップ
	// ただしdoubleにキャストされるため、2^32 - NTP_OFFSET の正値
	EXPECT_TRUE(t != 0.0, "stamp_ntp_to_double sec=0 is not zero");

	// sec=NTP_OFFSET (UNIXエポック) → 0.0
	sec = htonl(NTP_OFFSET);
	frac = htonl(0);
	t = stamp_ntp_to_double(sec, frac);
	EXPECT_NEAR_DOUBLE(t,
			   0.0,
			   1e-9,
			   "stamp_ntp_to_double sec=NTP_OFFSET is 0.0");

	// max frac (0xFFFFFFFF) → ほぼ+1.0
	sec = htonl(NTP_OFFSET + 1);
	frac = htonl(0xFFFFFFFF);
	t = stamp_ntp_to_double(sec, frac);
	EXPECT_NEAR_DOUBLE(t, 2.0, 1e-6, "stamp_ntp_to_double max frac ≈ +1.0");
}

static void test_stamp_ptp_to_double_edge_cases(void)
{
	// nsec=1000000000 (範囲外: 1秒分) → 結果は sec+1.0
	uint32_t sec = htonl(NTP_OFFSET + 5);
	uint32_t nsec = htonl(1000000000);
	double t = stamp_ptp_to_double(sec, nsec);
	EXPECT_NEAR_DOUBLE(t,
			   6.0,
			   1e-6,
			   "stamp_ptp_to_double nsec=1e9 → sec+1.0");

	// nsec=2000000000 (大幅範囲外)
	nsec = htonl(2000000000U);
	t = stamp_ptp_to_double(sec, nsec);
	EXPECT_NEAR_DOUBLE(t,
			   7.0,
			   1e-6,
			   "stamp_ptp_to_double nsec=2e9 → sec+2.0");

	// nsec=0 → 整数部のみ
	sec = htonl(NTP_OFFSET + 100);
	nsec = htonl(0);
	t = stamp_ptp_to_double(sec, nsec);
	EXPECT_NEAR_DOUBLE(t,
			   100.0,
			   1e-9,
			   "stamp_ptp_to_double nsec=0 → integer only");
}

static void test_jitter_calculation(void)
{
	// 分散・標準偏差の計算検証
	// 値: 1, 2, 3, 4, 5 → 平均3, 分散2, std=sqrt(2)≈1.414
	const double values[] = {1.0, 2.0, 3.0, 4.0, 5.0};
	int count = 5;
	double sum = 0;
	double sum_sq = 0;

	for (int i = 0; i < count; i++) {
		sum += values[i];
		sum_sq += values[i] * values[i];
	}

	double jitter = stamp_jitter(sum, sum_sq, (uint32_t)count);
	EXPECT_NEAR_DOUBLE(sum / count, 3.0, 0.001, "jitter avg");
	EXPECT_NEAR_DOUBLE(jitter, 1.414, 0.01, "jitter stddev");

	// 定数列 → jitter = 0
	const double const_values[] = {5.0, 5.0, 5.0};
	int const_count = 3;
	sum = 0;
	sum_sq = 0;
	for (int i = 0; i < const_count; i++) {
		sum += const_values[i];
		sum_sq += const_values[i] * const_values[i];
	}
	double jitter_const = stamp_jitter(sum, sum_sq, (uint32_t)const_count);
	EXPECT_NEAR_DOUBLE(jitter_const,
			   0.0,
			   0.001,
			   "jitter constant values = 0");

	// count=0 エッジケース
	EXPECT_NEAR_DOUBLE(stamp_jitter(0.0, 0.0, 0),
			   0.0,
			   0.001,
			   "jitter count=0");
}

/**
 * 7a. stamp_jitter エッジケーステスト
 */
static void test_stamp_jitter_edge_cases(void)
{
	// count=0 → 0.0
	EXPECT_NEAR_DOUBLE(stamp_jitter(10.0, 100.0, 0),
			   0.0,
			   1e-9,
			   "jitter count=0");
	// 負分散ガード: sum=10, sum_sq=19, count=5
	// var = 19/5 - (10/5)^2 = 3.8 - 4.0 = -0.2 → should return 0.0
	EXPECT_NEAR_DOUBLE(stamp_jitter(10.0, 19.0, 5),
			   0.0,
			   1e-9,
			   "jitter negative variance");
	// count=1: var = sum_sq/1 - (sum/1)^2 = 0 → 0.0
	EXPECT_NEAR_DOUBLE(stamp_jitter(5.0, 25.0, 1),
			   0.0,
			   1e-9,
			   "jitter single sample");
}

/**
 * 7b. stamp_packet_loss エッジケーステスト
 */
static void test_stamp_packet_loss_edge_cases(void)
{
	EXPECT_NEAR_DOUBLE(stamp_packet_loss(1, 0),
			   100.0,
			   0.001,
			   "packet_loss 100%");
	EXPECT_NEAR_DOUBLE(stamp_packet_loss(1, 1),
			   0.0,
			   0.001,
			   "packet_loss 0%");
}

/**
 * 7c. stamp_format_sockaddr_with_port NULL addr テスト
 */
static void test_stamp_format_sockaddr_with_port_null_addr(void)
{
	char buf[64];
	const char *result =
		stamp_format_sockaddr_with_port(NULL, buf, sizeof(buf));
	EXPECT_TRUE(result == buf, "format_sockaddr NULL addr returns buf");
	EXPECT_TRUE(buf[0] == '\0', "format_sockaddr NULL addr empty string");
}

/**
 * 7d. stamp_sockaddr_to_string_safe 切り詰めテスト
 */
static void test_stamp_sockaddr_to_string_safe_truncation(void)
{
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	ss.ss_family = 255; // 無効なファミリ → stamp_sockaddr_to_string が失敗
	// buflen=5: "<unk" + '\0' に切り詰め
	char buf[5];
	const char *result =
		stamp_sockaddr_to_string_safe(&ss, buf, sizeof(buf));
	EXPECT_TRUE(result == buf, "truncation returns buf");
	EXPECT_TRUE(buf[4] == '\0', "truncation null terminated");
	EXPECT_TRUE(strlen(buf) == 4, "truncation length 4");
}

/**
 * 7k. stamp_nsec_to_ntp_frac 境界値テスト
 */
static void test_stamp_nsec_to_ntp_frac_boundary(void)
{
	// 2^32 - 1 = 4294967295: (2^32-1) * 2^32 = 2^64 - 2^32 (no overflow)
	// product = 18446744069414584320, result wraps to uint32_t
	// (18446744069414584320 + 500000000) / 1000000000 = 18446744069
	// (uint32_t)18446744069 = 1266874885
	uint32_t result = stamp_nsec_to_ntp_frac(4294967295ULL);
	EXPECT_EQ_ULL(result,
		      1266874885U,
		      "stamp_nsec_to_ntp_frac(2^32-1) no overflow wraps");
}

// =============================================================================
// Step 6: 新規テスト関数
// =============================================================================

#ifndef _WIN32
/**
 * テスト間で共有するグローバル状態を既定値(実行中=1)に戻す
 * setup/teardown ヘルパー。各テストを順序非依存・自己完結にする。
 */
static void reset_global_state(void)
{
	__atomic_store_n(&g_running, 1, __ATOMIC_SEQ_CST);
}

/**
 * 6a. シグナルハンドラテスト (Linux/POSIX)
 */
static void test_signal_handler(void)
{
	// setup: グローバル状態を既知の値(実行中)へ
	reset_global_state();

	// SIGINT: g_running=1 → stamp_signal_handler(SIGINT) → g_running==0
	__atomic_store_n(&g_running, 1, __ATOMIC_SEQ_CST);
	stamp_signal_handler(SIGINT);
	EXPECT_TRUE(__atomic_load_n(&g_running, __ATOMIC_SEQ_CST) == 0,
		    "signal handler SIGINT sets g_running=0");

	// SIGTERM: 同様
	__atomic_store_n(&g_running, 1, __ATOMIC_SEQ_CST);
	stamp_signal_handler(SIGTERM);
	EXPECT_TRUE(__atomic_load_n(&g_running, __ATOMIC_SEQ_CST) == 0,
		    "signal handler SIGTERM sets g_running=0");

	// SIGABRT: Phase 2で追加
	__atomic_store_n(&g_running, 1, __ATOMIC_SEQ_CST);
	stamp_signal_handler(SIGABRT);
	EXPECT_TRUE(__atomic_load_n(&g_running, __ATOMIC_SEQ_CST) == 0,
		    "signal handler SIGABRT sets g_running=0");

	// 無関係シグナル（SIGUSR1）: g_running に変化なし
	__atomic_store_n(&g_running, 1, __ATOMIC_SEQ_CST);
	stamp_signal_handler(SIGUSR1);
	EXPECT_TRUE(__atomic_load_n(&g_running, __ATOMIC_SEQ_CST) == 1,
		    "signal handler SIGUSR1 does not change g_running");

	// teardown: グローバル状態を既定値へ復元（他テストへの影響回避）
	reset_global_state();
}

/**
 * 7j. cleanup_helpers テスト
 */
static void test_cleanup_helpers(void)
{
	// cleanup_fd: valid fd
	int fd = open("/dev/null", O_RDONLY);
	if (fd >= 0) {
		cleanup_fd(&fd);
		EXPECT_TRUE(fd == -1, "cleanup_fd sets fd to -1");
		// double cleanup: no-op
		cleanup_fd(&fd);
		EXPECT_TRUE(fd == -1, "cleanup_fd no-op on -1");
	} else {
		SKIP_TEST("cleanup_fd: cannot open /dev/null");
	}

	// cleanup_socket: valid socket
	SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
	if (!SOCKET_ERROR_CHECK(s)) {
		cleanup_socket(&s);
		EXPECT_TRUE(SOCKET_ERROR_CHECK(s),
			    "cleanup_socket invalidates socket");
		// double cleanup: no-op
		cleanup_socket(&s);
		EXPECT_TRUE(SOCKET_ERROR_CHECK(s),
			    "cleanup_socket no-op on invalid");
	} else {
		SKIP_TEST("cleanup_socket: cannot create socket");
	}
}
#endif

/**
 * 6b. stamp_nsec_to_ntp_frac オーバーフロー境界テスト
 */
static void test_stamp_nsec_to_ntp_frac_overflow(void)
{
	// UINT64_MAX → クランプ: overflow → nsec=999999999
	// 999999999 * 2^32 = 4294967291705032704
	// (4294967291705032704 + 500000000) / 1000000000 = 4294967292
	uint32_t result = stamp_nsec_to_ntp_frac(UINT64_MAX);
	EXPECT_EQ_ULL(result,
		      4294967292U,
		      "stamp_nsec_to_ntp_frac(UINT64_MAX) clamped");

	// 4294967296ULL (2^32) → クランプ: overflow → nsec=999999999
	// (999999999 * 4294967296 + 500000000) / 1000000000 = 4294967292
	result = stamp_nsec_to_ntp_frac(4294967296ULL);
	EXPECT_EQ_ULL(result,
		      4294967292U,
		      "stamp_nsec_to_ntp_frac(2^32) clamped");

	// 999999999ULL (通常最大値)
	// 999999999 * 4294967296 = 4294967291705032704
	// (4294967291705032704 + 500000000) / 1000000000 = 4294967292
	result = stamp_nsec_to_ntp_frac(999999999ULL);
	EXPECT_EQ_ULL(result,
		      4294967292U,
		      "stamp_nsec_to_ntp_frac(999999999) max normal");
}

#ifndef _WIN32
/**
 * 6c. stamp_get_timestamp ディスパッチテスト
 */
static void test_stamp_get_timestamp_dispatch(void)
{
	uint32_t sec = 0;
	uint32_t frac = 0;

	// NTPモード
	int rc = stamp_get_timestamp(&sec, &frac, false);
	EXPECT_TRUE(rc == 0, "stamp_get_timestamp NTP mode returns 0");

	// PTPモード
	sec = 0;
	frac = 0;
	rc = stamp_get_timestamp(&sec, &frac, true);
	EXPECT_TRUE(rc == 0, "stamp_get_timestamp PTP mode returns 0");
	uint32_t nsec_host = ntohl(frac);
	EXPECT_TRUE(nsec_host <= PTP_NSEC_MAX,
		    "stamp_get_timestamp PTP nsec <= PTP_NSEC_MAX");
}

/**
 * 6d. stamp_timespec_to_stamp ディスパッチテスト
 */
static void test_stamp_timespec_to_stamp_dispatch(void)
{
	struct timespec ts = {1000, 500000000};
	uint32_t sec = 0;
	uint32_t frac = 0;

	// NTPモード
	stamp_timespec_to_stamp(&ts, &sec, &frac, false);
	EXPECT_EQ_ULL(ntohl(sec),
		      2208989800U,
		      "stamp_timespec_to_stamp NTP: sec");
	uint32_t frac_host = ntohl(frac);
	EXPECT_TRUE(frac_host >= 0x7FFFFFFF && frac_host <= 0x80000001,
		    "stamp_timespec_to_stamp NTP: frac ≈ 0x80000000");

	// PTPモード
	sec = 0;
	frac = 0;
	stamp_timespec_to_stamp(&ts, &sec, &frac, true);
	EXPECT_EQ_ULL(ntohl(sec),
		      2208989800U,
		      "stamp_timespec_to_stamp PTP: sec");
	EXPECT_EQ_ULL(ntohl(frac),
		      500000000U,
		      "stamp_timespec_to_stamp PTP: frac = 500000000 nsec");
}
#endif

/**
 * 6e. NTP 2036年ロールオーバーテスト
 */
static void test_ntp_2036_rollover(void)
{
	// sec=0xFFFFFFFF → NTP epoch + 2^32 - 1 = 2085978495.0 UNIX seconds
	double t = stamp_ntp_to_double(htonl(0xFFFFFFFF), htonl(0));
	EXPECT_NEAR_DOUBLE(t,
			   2085978495.0,
			   1.0,
			   "stamp_ntp_to_double(0xFFFFFFFF) ≈ 2085978495");

	// sec=NTP_OFFSET-1 → unsigned wrap (> 4e9)
	double t2 = stamp_ntp_to_double(htonl(NTP_OFFSET - 1), htonl(0));
	EXPECT_TRUE(t2 > 4e9,
		    "stamp_ntp_to_double(NTP_OFFSET-1) unsigned wrap");
}

/**
 * 6f. packet_loss underflow テスト (received > sent)
 */
static void test_packet_loss_underflow(void)
{
	double loss = stamp_packet_loss(10, 20);
	// unsigned underflow: (uint32_t)(10-20) wraps to 4294967286
	// 100.0 * 4294967286 / 10.0 = 42949672860.0
	EXPECT_TRUE(
		loss > 1e8,
		"packet_loss(10,20) unsigned underflow produces huge value");
}

#ifdef __linux__
/**
 * 6g-1. ts[1]フォールバックテスト
 * ts[2]=0, ts[0]=0, ts[1]!=0 の場合、ts[1]にフォールバック
 */
static void test_stamp_extract_kernel_timestamp_linux_legacy_fallback(void)
{
	struct timespec ts[3] = {
		{0, 0},		   // ts[0] (software): ゼロ
		{5000, 100000000}, // ts[1] (legacy)
		{0, 0},		   // ts[2] (raw HW): ゼロ
	};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPING,
				       ts,
				       sizeof(ts));

	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	EXPECT_TRUE(result, "Legacy fallback: timestamp extracted");
	if (result) {
		EXPECT_EQ_ULL(ntohl(ntp_sec),
			      2208993800U,
			      "Legacy fallback: sec matches ts[1]");
	}
}

/**
 * 6g-2. 全ゼロ → epoch
 */
static void test_stamp_extract_kernel_timestamp_linux_all_zero(void)
{
	struct timespec ts[3] = {
		{0, 0},
		{0, 0},
		{0, 0},
	};

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPING,
				       ts,
				       sizeof(ts));

	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	// 全ゼロでもepochとして抽出されるか、falseを返すか
	if (result) {
		EXPECT_EQ_ULL(ntohl(ntp_sec),
			      (uint32_t)NTP_OFFSET,
			      "All zero: sec = NTP_OFFSET (epoch)");
		EXPECT_EQ_ULL(ntohl(ntp_frac), 0U, "All zero: frac = 0");
	} else {
		EXPECT_TRUE(!result,
			    "All zero: no timestamp extracted (expected)");
	}
}

/**
 * 6g-3. tv_nsec >= 1e9 → 範囲外として扱われるか検証
 */
static void test_stamp_extract_kernel_timestamp_linux_invalid_nsec(void)
{
	struct timespec ts = {1000, 1000000000}; // nsec = 1e9 (無効)

	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPNS,
				       &ts,
				       sizeof(ts));

	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	EXPECT_TRUE(!result, "invalid nsec (1e9) correctly rejected");
}

/**
 * 6g-4. cmsg_len 不足 → rejected
 */
static void test_stamp_extract_kernel_timestamp_linux_truncated_cmsg(void)
{
	char control[256];
	memset(control, 0, sizeof(control));

	struct msghdr msg;
	struct iovec iov;
	char data = 0;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &data;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TIMESTAMPNS;
	// cmsg_len を timespec より小さく設定（切り詰め）
	cmsg->cmsg_len = CMSG_LEN(1); // 1 byte のみ
	msg.msg_controllen = (size_t)((char *)cmsg + cmsg->cmsg_len - control);

	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_linux(&msg,
							   &ntp_sec,
							   &ntp_frac,
							   false);
	EXPECT_TRUE(!result,
		    "truncated SCM_TIMESTAMPNS cmsg correctly rejected");
}

/**
 * 7e. SCM_TIMESTAMP invalid usec テスト
 */
static void
test_stamp_extract_kernel_timestamp_linux_scm_timestamp_invalid_usec(void)
{
	// tv_usec = 1000000 (>= USEC_PER_SEC) → rejected
	struct timeval tv = {1000, 1000000};
	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMP,
				       &tv,
				       sizeof(tv));
	uint32_t sec = 0;
	uint32_t frac = 0;
	bool result =
		stamp_extract_kernel_timestamp_linux(&msg, &sec, &frac, false);
	EXPECT_TRUE(!result, "SCM_TIMESTAMP invalid usec (1e6) rejected");

	// tv_usec = -1 → rejected
	tv.tv_usec = -1;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMP,
				       &tv,
				       sizeof(tv));
	result = stamp_extract_kernel_timestamp_linux(&msg, &sec, &frac, false);
	EXPECT_TRUE(!result, "SCM_TIMESTAMP negative usec rejected");
}

/**
 * 7f. SCM_TIMESTAMP truncated cmsg テスト
 */
static void test_stamp_extract_kernel_timestamp_linux_scm_timestamp_truncated(
	void)
{
	char control[256];
	memset(control, 0, sizeof(control));
	struct msghdr msg;
	struct iovec iov;
	char data = 0;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &data;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TIMESTAMP;
	cmsg->cmsg_len = CMSG_LEN(1); // too small for timeval
	msg.msg_controllen = (size_t)((char *)cmsg + cmsg->cmsg_len - control);
	uint32_t sec = 0;
	uint32_t frac = 0;
	bool result =
		stamp_extract_kernel_timestamp_linux(&msg, &sec, &frac, false);
	EXPECT_TRUE(!result, "SCM_TIMESTAMP truncated cmsg rejected");
}

/**
 * 7g. SCM_TIMESTAMPING truncated cmsg テスト
 */
static void
test_stamp_extract_kernel_timestamp_linux_scm_timestamping_truncated(void)
{
	char control[256];
	memset(control, 0, sizeof(control));
	struct msghdr msg;
	struct iovec iov;
	char data = 0;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &data;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TIMESTAMPING;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct timespec)); // need 3*timespec
	msg.msg_controllen = (size_t)((char *)cmsg + cmsg->cmsg_len - control);
	uint32_t sec = 0;
	uint32_t frac = 0;
	bool result =
		stamp_extract_kernel_timestamp_linux(&msg, &sec, &frac, false);
	EXPECT_TRUE(!result, "SCM_TIMESTAMPING truncated cmsg rejected");
}

/**
 * 7h. SCM_TIMESTAMPING all invalid nsec テスト
 */
static void test_stamp_extract_kernel_timestamp_linux_all_invalid_nsec(void)
{
	// 3つ全てのtimespecがtv_nsec=-1（無効）→ selected==NULL → false
	struct timespec ts[3] = {{1000, -1}, {2000, -1}, {3000, -1}};
	char control[256];
	struct msghdr msg;
	struct iovec iov;
	char data;
	build_mock_msghdr_timestamping(&msg,
				       &iov,
				       &data,
				       control,
				       sizeof(control),
				       SCM_TIMESTAMPING,
				       ts,
				       sizeof(ts));
	uint32_t sec = 0;
	uint32_t frac = 0;
	bool result =
		stamp_extract_kernel_timestamp_linux(&msg, &sec, &frac, false);
	EXPECT_TRUE(!result, "all invalid nsec in SCM_TIMESTAMPING rejected");
}

/**
 * 7i. stamp_get_phc_timestamp invalid clockid テスト
 */
static void test_stamp_get_phc_timestamp_invalid_clockid(void)
{
	uint32_t sec = 0;
	uint32_t frac = 0;
	int rc = stamp_get_phc_timestamp((clockid_t)-999, &sec, &frac, false);
	EXPECT_TRUE(rc == -1,
		    "stamp_get_phc_timestamp invalid clockid returns -1");
}
#endif // __linux__

// TODO: Known coverage gaps (require socket mocking infrastructure):
//   - reflector.c reflect_packet() error handling paths
//   - sender.c receive_and_process_packet() sequence mismatch detection
//   - sender.c send_stamp_packet() PHC/PTP/NTP three-way branching
//   - stamp.h stamp_extract_kernel_timestamp_windows() (Windows only)

#ifdef _WIN32
static void test_stamp_extract_kernel_timestamp_windows(void)
{
	// WSAMSGベースのmock制御メッセージを構築
	// SO_TIMESTAMP タイプで FILETIME を格納
	char control_buf[256];
	memset(control_buf, 0, sizeof(control_buf));

	WSAMSG msg;
	WSABUF wsa_buf;
	char data_buf = 0;
	memset(&msg, 0, sizeof(msg));
	wsa_buf.buf = &data_buf;
	wsa_buf.len = 1;
	msg.lpBuffers = &wsa_buf;
	msg.dwBufferCount = 1;
	msg.Control.buf = control_buf;
	msg.Control.len = sizeof(control_buf);

	// FILETIME: 2020-01-01 00:00:00.5 UTC を表現
	// 1601-01-01からの100ns刻み: UNIX 2020-01-01 = 1577836800 sec
	// Windows ticks = (1577836800 + 11644473600) * 10000000 + 5000000
	uint64_t win_ticks = (1577836800ULL + WINDOWS_TO_NTP_OFFSET) *
				     WINDOWS_TICKS_PER_SEC +
			     5000000ULL; // 0.5秒分の100ns単位
	FILETIME ft;
	ft.dwLowDateTime = (DWORD)(win_ticks & 0xFFFFFFFF);
	ft.dwHighDateTime = (DWORD)(win_ticks >> 32);

	WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SO_TIMESTAMP;
	cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(FILETIME));
	memcpy(WSA_CMSG_DATA(cmsg), &ft, sizeof(FILETIME));
	msg.Control.len = (ULONG)((char *)cmsg + cmsg->cmsg_len - control_buf);

	// NTPモード
	uint32_t ntp_sec = 0;
	uint32_t ntp_frac = 0;
	bool result = stamp_extract_kernel_timestamp_windows(&msg,
							     &ntp_sec,
							     &ntp_frac,
							     false);
	EXPECT_TRUE(result, "Windows timestamp NTP: extracted");
	if (result) {
		uint32_t sec_host = ntohl(ntp_sec);
		EXPECT_EQ_ULL(sec_host,
			      (uint32_t)(1577836800UL + NTP_OFFSET),
			      "Windows timestamp NTP: sec");
	}

	// PTPモード
	msg.Control.len = sizeof(control_buf);
	cmsg = WSA_CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SO_TIMESTAMP;
	cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(FILETIME));
	memcpy(WSA_CMSG_DATA(cmsg), &ft, sizeof(FILETIME));
	msg.Control.len = (ULONG)((char *)cmsg + cmsg->cmsg_len - control_buf);

	uint32_t ptp_sec = 0;
	uint32_t ptp_frac = 0;
	result = stamp_extract_kernel_timestamp_windows(&msg,
							&ptp_sec,
							&ptp_frac,
							true);
	EXPECT_TRUE(result, "Windows timestamp PTP: extracted");
	if (result) {
		uint32_t sec_host = ntohl(ptp_sec);
		EXPECT_EQ_ULL(sec_host,
			      (uint32_t)(1577836800UL + NTP_OFFSET),
			      "Windows timestamp PTP: sec");
		// PTPモードでは nsec 部分が格納される
		uint32_t nsec_host = ntohl(ptp_frac);
		EXPECT_TRUE(nsec_host <= PTP_NSEC_MAX,
			    "Windows timestamp PTP: nsec in valid range");
	}
}
#endif

// =============================================================================
// Phase 7-2: エッジケーステスト
// =============================================================================

static void test_edge_cases(void)
{
	// STAMP_MAX_SSID定数テスト
	EXPECT_TRUE(STAMP_MAX_SSID == 65535, "STAMP_MAX_SSID is 65535");

	// PTP_NSEC_MAX境界テスト
	EXPECT_TRUE(PTP_NSEC_MAX == 999999999, "PTP_NSEC_MAX is 999999999");
	uint32_t nsec_ptp = PTP_NSEC_MAX;
	EXPECT_TRUE(nsec_ptp <= PTP_NSEC_MAX, "PTP_NSEC_MAX boundary");

	// ntp_frac_to_nsec / nsec_to_ntp_frac ラウンドトリップ精度テスト
	// 500000000 nsec = 0.5 sec → NTP frac ≈ 2147483648 (0x80000000)
	uint32_t frac_half = stamp_nsec_to_ntp_frac(500000000ULL);
	uint32_t nsec_back = stamp_ntp_frac_to_nsec(frac_half);
	// ラウンドトリップ誤差は1ns以内
	EXPECT_TRUE(nsec_back >= 499999999 && nsec_back <= 500000001,
		    "ntp_frac roundtrip 500ms");

	// 0 nsec ラウンドトリップ
	uint32_t frac_zero = stamp_nsec_to_ntp_frac(0);
	uint32_t nsec_zero = stamp_ntp_frac_to_nsec(frac_zero);
	EXPECT_TRUE(nsec_zero == 0, "ntp_frac roundtrip 0ns");

	// stamp_validate_packet: Error Estimate multiplier==0 拒否テスト
	{
		uint8_t buf[STAMP_BASE_PACKET_SIZE];
		memset(buf, 0, sizeof(buf));
		// multiplier==0 → 拒否
		EXPECT_TRUE(stamp_validate_packet(buf,
						  STAMP_BASE_PACKET_SIZE) == 0,
			    "validate rejects multiplier==0");
		// Z=1, S=1, multiplier=1 → 受理
		buf[12] = 0xC0; // S=1, Z=1
		buf[13] = 0x01; // multiplier=1
		EXPECT_TRUE(stamp_validate_packet(buf,
						  STAMP_BASE_PACKET_SIZE) == 1,
			    "validate accepts PTP error_estimate");
	}

	// stamp_build_reflector_packet 単体テスト
	{
		uint8_t buf[STAMP_BASE_PACKET_SIZE];
		memset(buf, 0, sizeof(buf));
		// sender packet のフィールド設定
		struct stamp_sender_packet *sp =
			(struct stamp_sender_packet *)buf;
		sp->seq_num = htonl(42);
		sp->timestamp_sec = htonl(100);
		sp->timestamp_frac = htonl(200);
		sp->error_estimate = htons(ERROR_ESTIMATE_DEFAULT);

		stamp_build_reflector_packet(buf,
					     STAMP_BASE_PACKET_SIZE,
					     64,
					     htonl(300),
					     htonl(400),
					     htons(ERROR_ESTIMATE_PTP_DEFAULT));

		const struct stamp_reflector_packet *rp =
			(const struct stamp_reflector_packet *)buf;
		EXPECT_TRUE(ntohl(rp->seq_num) == 42,
			    "build_reflector: seq_num preserved");
		EXPECT_TRUE(ntohl(rp->sender_ts_sec) == 100,
			    "build_reflector: sender_ts_sec");
		EXPECT_TRUE(ntohl(rp->sender_ts_frac) == 200,
			    "build_reflector: sender_ts_frac");
		EXPECT_TRUE(rp->sender_ttl == 64,
			    "build_reflector: sender_ttl");
		EXPECT_TRUE(ntohl(rp->rx_sec) == 300,
			    "build_reflector: rx_sec");
		EXPECT_TRUE(ntohl(rp->rx_frac) == 400,
			    "build_reflector: rx_frac");
		EXPECT_TRUE(ntohs(rp->error_estimate) ==
				    ERROR_ESTIMATE_PTP_DEFAULT,
			    "build_reflector: error_estimate");
	}
}

// =============================================================================
// Phase 14: E2E Integration (loopback)
// =============================================================================

static int set_recv_timeout_ms_xplat(SOCKET sock, int timeout_ms)
{
#ifdef _WIN32
	DWORD tv = (DWORD)timeout_ms;
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000L);
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

static void e2e_stamp_loopback_impl(bool ptp_mode, const char *label)
{
	SOCKET sender_sock = INVALID_SOCKET;
	SOCKET reflector_sock = INVALID_SOCKET;
	char msg[128];

	uint16_t error_est = ptp_mode ? ERROR_ESTIMATE_PTP_DEFAULT
				      : ERROR_ESTIMATE_DEFAULT;

	sender_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(sender_sock)) {
		snprintf(msg, sizeof(msg), "%s: sender socket", label);
		SKIP_TEST(msg);
		return;
	}
	reflector_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(reflector_sock)) {
		snprintf(msg, sizeof(msg), "%s: reflector socket", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// reflector を 127.0.0.1:0 に bind
	struct sockaddr_in refl_addr;
	memset(&refl_addr, 0, sizeof(refl_addr));
	refl_addr.sin_family = AF_INET;
	refl_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	refl_addr.sin_port = htons(0);
	if (bind(reflector_sock,
		 (struct sockaddr *)&refl_addr,
		 sizeof(refl_addr)) < 0) {
		snprintf(msg, sizeof(msg), "%s: bind", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	socklen_t addr_len = (socklen_t)sizeof(refl_addr);
	if (getsockname(reflector_sock,
			(struct sockaddr *)&refl_addr,
			&addr_len) < 0) {
		snprintf(msg, sizeof(msg), "%s: getsockname", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// タイムアウト設定
	if (set_recv_timeout_ms_xplat(sender_sock, 500) != 0 ||
	    set_recv_timeout_ms_xplat(reflector_sock, 500) != 0) {
		snprintf(msg, sizeof(msg), "%s: set timeout", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// === Sender: パケット構築・送信 ===
	struct stamp_sender_packet spkt;
	memset(&spkt, 0, sizeof(spkt));
	spkt.seq_num = htonl(0);
	spkt.error_estimate = htons(error_est);
	uint32_t t1_sec;
	uint32_t t1_frac;
	if (stamp_get_timestamp(&t1_sec, &t1_frac, ptp_mode) != 0) {
		snprintf(msg, sizeof(msg), "%s: T1 timestamp", label);
		SKIP_TEST(msg);
		goto cleanup;
	}
	spkt.timestamp_sec = t1_sec;
	spkt.timestamp_frac = t1_frac;

	ssize_t sent = sendto(sender_sock,
			      (const char *)&spkt,
			      sizeof(spkt),
			      0,
			      (struct sockaddr *)&refl_addr,
			      sizeof(refl_addr));
	if (sent < (ssize_t)sizeof(spkt)) {
		snprintf(msg, sizeof(msg), "%s: sendto sender", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// === Reflector: 受信・検証・応答パケット構築・送信 ===
	uint8_t buf[STAMP_BASE_PACKET_SIZE];
	struct sockaddr_in sender_addr;
	socklen_t sender_addr_len = (socklen_t)sizeof(sender_addr);
	ssize_t recv_n = recvfrom(reflector_sock,
				  (char *)buf,
				  sizeof(buf),
				  0,
				  (struct sockaddr *)&sender_addr,
				  &sender_addr_len);
	if (recv_n < (ssize_t)STAMP_BASE_PACKET_SIZE) {
		snprintf(msg, sizeof(msg), "%s: reflector recvfrom", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	snprintf(msg, sizeof(msg), "%s: stamp_validate_test_payload_for_reflector", label);
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(buf, (int)recv_n),
		    msg);

	// T2 取得
	uint32_t t2_sec;
	uint32_t t2_frac;
	if (stamp_get_timestamp(&t2_sec, &t2_frac, ptp_mode) != 0) {
		snprintf(msg, sizeof(msg), "%s: T2 timestamp", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// Reflector パケット構築
	uint8_t refl_buf[STAMP_BASE_PACKET_SIZE];
	memcpy(refl_buf, buf, sizeof(refl_buf));
	stamp_build_reflector_packet(refl_buf, (int)recv_n, 64, t2_sec, t2_frac, htons(error_est));

	// T3 取得・設定
	uint32_t t3_sec;
	uint32_t t3_frac;
	if (stamp_get_timestamp(&t3_sec, &t3_frac, ptp_mode) != 0) {
		snprintf(msg, sizeof(msg), "%s: T3 timestamp", label);
		SKIP_TEST(msg);
		goto cleanup;
	}
	struct stamp_reflector_packet *rpkt =
		(struct stamp_reflector_packet *)refl_buf;
	rpkt->timestamp_sec = t3_sec;
	rpkt->timestamp_frac = t3_frac;

	ssize_t refl_sent = sendto(reflector_sock,
				   (const char *)refl_buf,
				   sizeof(refl_buf),
				   0,
				   (struct sockaddr *)&sender_addr,
				   sender_addr_len);
	if (refl_sent < (ssize_t)sizeof(refl_buf)) {
		snprintf(msg, sizeof(msg), "%s: sendto reflector", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// === Sender: 応答受信・検証 ===
	uint8_t resp_buf[STAMP_BASE_PACKET_SIZE];
	ssize_t resp_n = recvfrom(sender_sock,
				  (char *)resp_buf,
				  sizeof(resp_buf),
				  0,
				  NULL,
				  NULL);
	if (resp_n < (ssize_t)STAMP_BASE_PACKET_SIZE) {
		snprintf(msg, sizeof(msg), "%s: sender recvfrom", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// T4 取得
	uint32_t t4_sec = 0;
	uint32_t t4_frac = 0;
	if (stamp_get_timestamp(&t4_sec, &t4_frac, ptp_mode) != 0) {
		snprintf(msg, sizeof(msg), "%s: T4 timestamp", label);
		SKIP_TEST(msg);
		goto cleanup;
	}

	// パケット妥当性検証
	snprintf(msg, sizeof(msg), "%s: stamp_validate_packet", label);
	EXPECT_TRUE(stamp_validate_packet(resp_buf, (int)resp_n), msg);

	const struct stamp_reflector_packet *resp =
		(const struct stamp_reflector_packet *)resp_buf;

	// seq_num / sender フィールドの一致
	snprintf(msg, sizeof(msg), "%s: seq_num", label);
	EXPECT_TRUE(ntohl(resp->seq_num) == 0, msg);

	snprintf(msg, sizeof(msg), "%s: sender_seq_num", label);
	EXPECT_TRUE(ntohl(resp->sender_seq_num) == 0, msg);

	snprintf(msg, sizeof(msg), "%s: sender_ts_sec", label);
	EXPECT_TRUE(resp->sender_ts_sec == t1_sec, msg);

	snprintf(msg, sizeof(msg), "%s: sender_ts_frac", label);
	EXPECT_TRUE(resp->sender_ts_frac == t1_frac, msg);

	snprintf(msg, sizeof(msg), "%s: sender_ttl", label);
	EXPECT_TRUE(resp->sender_ttl == 64, msg);

	// sender_err_est エコーバック検証
	snprintf(msg, sizeof(msg), "%s: sender_err_est", label);
	EXPECT_TRUE(ntohs(resp->sender_err_est) == error_est, msg);

	// MBZ フィールドがゼロであることを検証 (RFC 8762 Section 4.3.1)
	snprintf(msg, sizeof(msg), "%s: mbz_1 == 0", label);
	EXPECT_TRUE(resp->mbz_1 == 0, msg);

	snprintf(msg, sizeof(msg), "%s: mbz_2 == 0", label);
	EXPECT_TRUE(resp->mbz_2 == 0, msg);

	snprintf(msg, sizeof(msg), "%s: mbz_3 all zero", label);
	EXPECT_TRUE(resp->mbz_3[0] == 0 && resp->mbz_3[1] == 0 &&
			    resp->mbz_3[2] == 0,
		    msg);

	// T2, T3 が非ゼロ
	snprintf(msg, sizeof(msg), "%s: rx_sec nonzero", label);
	EXPECT_TRUE(ntohl(resp->rx_sec) != 0, msg);

	snprintf(msg, sizeof(msg), "%s: timestamp_sec nonzero", label);
	EXPECT_TRUE(ntohl(resp->timestamp_sec) != 0, msg);

	// 遅延計算の検証
	double d_t1 = stamp_timestamp_to_double(t1_sec, t1_frac, error_est);
	double d_t2 = stamp_timestamp_to_double(resp->rx_sec, resp->rx_frac, error_est);
	double d_t3 = stamp_timestamp_to_double(resp->timestamp_sec,
						resp->timestamp_frac,
						error_est);
	double d_t4 = stamp_timestamp_to_double(t4_sec, t4_frac, error_est);

	double fwd = stamp_forward_delay(d_t1, d_t2);
	double bwd = stamp_backward_delay(d_t3, d_t4);
	double rtt = stamp_rtt(fwd, bwd);
	double offset = stamp_clock_offset(d_t1, d_t2, d_t3, d_t4);

	snprintf(msg, sizeof(msg), "%s: RTT >= -1ms", label);
	EXPECT_TRUE(rtt >= -1.0, msg);

	snprintf(msg, sizeof(msg), "%s: RTT < 100ms", label);
	EXPECT_TRUE(rtt < 100.0, msg);

	snprintf(msg, sizeof(msg), "%s: offset < 50ms", label);
	EXPECT_TRUE(fabs(offset) < 50.0, msg);

cleanup:
	if (!SOCKET_ERROR_CHECK(sender_sock)) {
		CLOSE_SOCKET(sender_sock);
	}
	if (!SOCKET_ERROR_CHECK(reflector_sock)) {
		CLOSE_SOCKET(reflector_sock);
	}
}

static void test_e2e_stamp_loopback(void)
{
	e2e_stamp_loopback_impl(false, "e2e NTP");
}

static void test_e2e_stamp_loopback_ptp(void)
{
	e2e_stamp_loopback_impl(true, "e2e PTP");
}

static void test_e2e_stamp_loopback_padded(void)
{
	SOCKET sender_sock = INVALID_SOCKET;
	SOCKET reflector_sock = INVALID_SOCKET;
	const char *label = "e2e padded";
	char msg[128];
	// 100 バイトのパディング付きパケット（44B 基本 + 56B パディング）
	const int padded_size = 100;

	sender_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(sender_sock)) {
		SKIP_TEST("e2e padded: sender socket");
		return;
	}
	reflector_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(reflector_sock)) {
		SKIP_TEST("e2e padded: reflector socket");
		goto cleanup;
	}

	struct sockaddr_in refl_addr;
	memset(&refl_addr, 0, sizeof(refl_addr));
	refl_addr.sin_family = AF_INET;
	refl_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	refl_addr.sin_port = htons(0);
	if (bind(reflector_sock,
		 (struct sockaddr *)&refl_addr,
		 sizeof(refl_addr)) < 0) {
		SKIP_TEST("e2e padded: bind");
		goto cleanup;
	}

	socklen_t addr_len = (socklen_t)sizeof(refl_addr);
	if (getsockname(reflector_sock,
			(struct sockaddr *)&refl_addr,
			&addr_len) < 0) {
		SKIP_TEST("e2e padded: getsockname");
		goto cleanup;
	}

	if (set_recv_timeout_ms_xplat(sender_sock, 500) != 0 ||
	    set_recv_timeout_ms_xplat(reflector_sock, 500) != 0) {
		SKIP_TEST("e2e padded: set timeout");
		goto cleanup;
	}

	// パディング付き sender パケット構築
	uint8_t send_buf[100];
	memset(send_buf, 0, sizeof(send_buf));
	struct stamp_sender_packet *spkt =
		(struct stamp_sender_packet *)send_buf;
	spkt->seq_num = htonl(77);
	spkt->error_estimate = htons(ERROR_ESTIMATE_DEFAULT);
	uint32_t t1_sec;
	uint32_t t1_frac;
	if (stamp_get_timestamp(&t1_sec, &t1_frac, false) != 0) {
		SKIP_TEST("e2e padded: T1 timestamp");
		goto cleanup;
	}
	spkt->timestamp_sec = t1_sec;
	spkt->timestamp_frac = t1_frac;

	ssize_t sent = sendto(sender_sock,
			      (const char *)send_buf,
			      (size_t)padded_size,
			      0,
			      (struct sockaddr *)&refl_addr,
			      sizeof(refl_addr));
	if (sent < padded_size) {
		SKIP_TEST("e2e padded: sendto");
		goto cleanup;
	}

	// Reflector 受信（100B を受け取る）
	uint8_t recv_buf[256];
	struct sockaddr_in sender_addr;
	socklen_t sa_len = (socklen_t)sizeof(sender_addr);
	ssize_t recv_n = recvfrom(reflector_sock,
				  (char *)recv_buf,
				  sizeof(recv_buf),
				  0,
				  (struct sockaddr *)&sender_addr,
				  &sa_len);
	if (recv_n < padded_size) {
		SKIP_TEST("e2e padded: reflector recvfrom");
		goto cleanup;
	}

	snprintf(msg, sizeof(msg), "%s: recv size == padded_size", label);
	EXPECT_TRUE(recv_n == padded_size, msg);

	snprintf(msg, sizeof(msg), "%s: validate payload", label);
	EXPECT_TRUE(stamp_validate_test_payload_for_reflector(recv_buf, (int)recv_n),
		    msg);

	// Reflector 応答パケット構築
	uint32_t t2_sec;
	uint32_t t2_frac;
	if (stamp_get_timestamp(&t2_sec, &t2_frac, false) != 0) {
		SKIP_TEST("e2e padded: T2 timestamp");
		goto cleanup;
	}

	stamp_build_reflector_packet(recv_buf, (int)recv_n, 64, t2_sec, t2_frac, htons(ERROR_ESTIMATE_DEFAULT));

	uint32_t t3_sec;
	uint32_t t3_frac;
	if (stamp_get_timestamp(&t3_sec, &t3_frac, false) != 0) {
		SKIP_TEST("e2e padded: T3 timestamp");
		goto cleanup;
	}
	struct stamp_reflector_packet *rpkt =
		(struct stamp_reflector_packet *)recv_buf;
	rpkt->timestamp_sec = t3_sec;
	rpkt->timestamp_frac = t3_frac;

	// パディング込みで返送
	ssize_t refl_sent = sendto(reflector_sock,
				   (const char *)recv_buf,
				   (size_t)padded_size,
				   0,
				   (struct sockaddr *)&sender_addr,
				   sa_len);
	if (refl_sent < padded_size) {
		SKIP_TEST("e2e padded: sendto reflector");
		goto cleanup;
	}

	// Sender 応答受信
	uint8_t resp_buf[256];
	ssize_t resp_n = recvfrom(sender_sock,
				  (char *)resp_buf,
				  sizeof(resp_buf),
				  0,
				  NULL,
				  NULL);
	if (resp_n < padded_size) {
		SKIP_TEST("e2e padded: sender recvfrom");
		goto cleanup;
	}

	// 応答サイズがパディング込みであることを確認
	snprintf(msg, sizeof(msg), "%s: resp size == padded_size", label);
	EXPECT_TRUE(resp_n == padded_size, msg);

	snprintf(msg, sizeof(msg), "%s: stamp_validate_packet", label);
	EXPECT_TRUE(stamp_validate_packet(resp_buf, (int)resp_n), msg);

	const struct stamp_reflector_packet *resp =
		(const struct stamp_reflector_packet *)resp_buf;

	snprintf(msg, sizeof(msg), "%s: seq_num", label);
	EXPECT_TRUE(ntohl(resp->seq_num) == 77, msg);

	snprintf(msg, sizeof(msg), "%s: sender_seq_num", label);
	EXPECT_TRUE(ntohl(resp->sender_seq_num) == 77, msg);

	snprintf(msg, sizeof(msg), "%s: sender_ts_sec", label);
	EXPECT_TRUE(resp->sender_ts_sec == t1_sec, msg);

	snprintf(msg, sizeof(msg), "%s: sender_ts_frac", label);
	EXPECT_TRUE(resp->sender_ts_frac == t1_frac, msg);

	snprintf(msg, sizeof(msg), "%s: sender_err_est", label);
	EXPECT_TRUE(ntohs(resp->sender_err_est) == ERROR_ESTIMATE_DEFAULT,
		    msg);

	// MBZ フィールドがゼロ
	snprintf(msg, sizeof(msg), "%s: mbz_1 == 0", label);
	EXPECT_TRUE(resp->mbz_1 == 0, msg);

	snprintf(msg, sizeof(msg), "%s: mbz_2 == 0", label);
	EXPECT_TRUE(resp->mbz_2 == 0, msg);

	snprintf(msg, sizeof(msg), "%s: mbz_3 all zero", label);
	EXPECT_TRUE(resp->mbz_3[0] == 0 && resp->mbz_3[1] == 0 &&
			    resp->mbz_3[2] == 0,
		    msg);

	// RTT 検証
	uint32_t t4_sec = 0;
	uint32_t t4_frac = 0;
	(void)stamp_get_timestamp(&t4_sec, &t4_frac, false);

	double d_t1 = stamp_timestamp_to_double(
		t1_sec,
		t1_frac,
		ERROR_ESTIMATE_DEFAULT);
	double d_t2 = stamp_timestamp_to_double(
		resp->rx_sec,
		resp->rx_frac,
		ERROR_ESTIMATE_DEFAULT);
	double d_t3 = stamp_timestamp_to_double(
		resp->timestamp_sec,
		resp->timestamp_frac,
		ERROR_ESTIMATE_DEFAULT);
	double d_t4 = stamp_timestamp_to_double(
		t4_sec,
		t4_frac,
		ERROR_ESTIMATE_DEFAULT);
	double rtt = stamp_rtt(stamp_forward_delay(d_t1, d_t2),
			       stamp_backward_delay(d_t3, d_t4));

	snprintf(msg, sizeof(msg), "%s: RTT >= -1ms", label);
	EXPECT_TRUE(rtt >= -1.0, msg);

	snprintf(msg, sizeof(msg), "%s: RTT < 100ms", label);
	EXPECT_TRUE(rtt < 100.0, msg);

cleanup:
	if (!SOCKET_ERROR_CHECK(sender_sock)) {
		CLOSE_SOCKET(sender_sock);
	}
	if (!SOCKET_ERROR_CHECK(reflector_sock)) {
		CLOSE_SOCKET(reflector_sock);
	}
}

static void test_e2e_stamp_loopback_multi_seq(void)
{
	SOCKET sender_sock = INVALID_SOCKET;
	SOCKET reflector_sock = INVALID_SOCKET;
	const int num_packets = 5;
	const char *label = "e2e multi-seq";
	char msg[128];

	sender_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(sender_sock)) {
		SKIP_TEST("e2e multi-seq: sender socket");
		return;
	}
	reflector_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SOCKET_ERROR_CHECK(reflector_sock)) {
		SKIP_TEST("e2e multi-seq: reflector socket");
		goto cleanup;
	}

	struct sockaddr_in refl_addr;
	memset(&refl_addr, 0, sizeof(refl_addr));
	refl_addr.sin_family = AF_INET;
	refl_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	refl_addr.sin_port = htons(0);
	if (bind(reflector_sock,
		 (struct sockaddr *)&refl_addr,
		 sizeof(refl_addr)) < 0) {
		SKIP_TEST("e2e multi-seq: bind");
		goto cleanup;
	}

	socklen_t addr_len = (socklen_t)sizeof(refl_addr);
	if (getsockname(reflector_sock,
			(struct sockaddr *)&refl_addr,
			&addr_len) < 0) {
		SKIP_TEST("e2e multi-seq: getsockname");
		goto cleanup;
	}

	if (set_recv_timeout_ms_xplat(sender_sock, 500) != 0 ||
	    set_recv_timeout_ms_xplat(reflector_sock, 500) != 0) {
		SKIP_TEST("e2e multi-seq: set timeout");
		goto cleanup;
	}

	for (int i = 0; i < num_packets; i++) {
		// Sender: パケット構築・送信
		struct stamp_sender_packet spkt;
		memset(&spkt, 0, sizeof(spkt));
		spkt.seq_num = htonl((uint32_t)i);
		spkt.error_estimate = htons(ERROR_ESTIMATE_DEFAULT);
		uint32_t t1_sec;
		uint32_t t1_frac;
		if (stamp_get_timestamp(&t1_sec, &t1_frac, false) != 0) {
			snprintf(msg, sizeof(msg), "%s[%d]: T1 timestamp", label, i);
			SKIP_TEST(msg);
			goto cleanup;
		}
		spkt.timestamp_sec = t1_sec;
		spkt.timestamp_frac = t1_frac;

		ssize_t sent = sendto(sender_sock,
				      (const char *)&spkt,
				      sizeof(spkt),
				      0,
				      (struct sockaddr *)&refl_addr,
				      sizeof(refl_addr));
		if (sent < (ssize_t)sizeof(spkt)) {
			snprintf(msg, sizeof(msg), "%s[%d]: sendto", label, i);
			SKIP_TEST(msg);
			goto cleanup;
		}

		// Reflector: 受信・応答
		uint8_t buf[STAMP_BASE_PACKET_SIZE];
		struct sockaddr_in sender_addr;
		socklen_t sa_len = (socklen_t)sizeof(sender_addr);
		ssize_t recv_n = recvfrom(reflector_sock,
					  (char *)buf,
					  sizeof(buf),
					  0,
					  (struct sockaddr *)&sender_addr,
					  &sa_len);
		if (recv_n < (ssize_t)STAMP_BASE_PACKET_SIZE) {
			snprintf(msg, sizeof(msg), "%s[%d]: reflector recvfrom", label, i);
			SKIP_TEST(msg);
			goto cleanup;
		}

		uint32_t t2_sec = 0;
		uint32_t t2_frac = 0;
		(void)stamp_get_timestamp(&t2_sec, &t2_frac, false);

		uint8_t refl_buf[STAMP_BASE_PACKET_SIZE];
		memcpy(refl_buf, buf, sizeof(refl_buf));
		stamp_build_reflector_packet(refl_buf, (int)recv_n, 64, t2_sec, t2_frac, htons(ERROR_ESTIMATE_DEFAULT));

		uint32_t t3_sec = 0;
		uint32_t t3_frac = 0;
		(void)stamp_get_timestamp(&t3_sec, &t3_frac, false);
		struct stamp_reflector_packet *rp =
			(struct stamp_reflector_packet *)refl_buf;
		rp->timestamp_sec = t3_sec;
		rp->timestamp_frac = t3_frac;

		ssize_t rs = sendto(reflector_sock,
				    (const char *)refl_buf,
				    sizeof(refl_buf),
				    0,
				    (struct sockaddr *)&sender_addr,
				    sa_len);
		if (rs < (ssize_t)sizeof(refl_buf)) {
			snprintf(msg, sizeof(msg), "%s[%d]: sendto reflector", label, i);
			SKIP_TEST(msg);
			goto cleanup;
		}

		// Sender: 応答受信
		uint8_t resp_buf[STAMP_BASE_PACKET_SIZE];
		ssize_t resp_n = recvfrom(sender_sock,
					  (char *)resp_buf,
					  sizeof(resp_buf),
					  0,
					  NULL,
					  NULL);
		if (resp_n < (ssize_t)STAMP_BASE_PACKET_SIZE) {
			snprintf(msg, sizeof(msg), "%s[%d]: sender recvfrom", label, i);
			SKIP_TEST(msg);
			goto cleanup;
		}

		uint32_t t4_sec = 0;
		uint32_t t4_frac = 0;
		(void)stamp_get_timestamp(&t4_sec, &t4_frac, false);

		const struct stamp_reflector_packet *resp =
			(const struct stamp_reflector_packet *)resp_buf;

		// seq_num 検証
		snprintf(msg, sizeof(msg), "%s[%d]: seq_num", label, i);
		EXPECT_TRUE(ntohl(resp->seq_num) == (uint32_t)i, msg);

		snprintf(msg, sizeof(msg), "%s[%d]: sender_seq_num", label, i);
		EXPECT_TRUE(ntohl(resp->sender_seq_num) == (uint32_t)i, msg);

		// sender タイムスタンプ一致
		snprintf(msg, sizeof(msg), "%s[%d]: sender_ts_sec", label, i);
		EXPECT_TRUE(resp->sender_ts_sec == t1_sec, msg);

		snprintf(msg, sizeof(msg), "%s[%d]: sender_ts_frac", label, i);
		EXPECT_TRUE(resp->sender_ts_frac == t1_frac, msg);

		// RTT 検証
		double d_t1 = stamp_timestamp_to_double(
			t1_sec,
			t1_frac,
			ERROR_ESTIMATE_DEFAULT);
		double d_t2 = stamp_timestamp_to_double(
			resp->rx_sec,
			resp->rx_frac,
			ERROR_ESTIMATE_DEFAULT);
		double d_t3 = stamp_timestamp_to_double(
			resp->timestamp_sec,
			resp->timestamp_frac,
			ERROR_ESTIMATE_DEFAULT);
		double d_t4 = stamp_timestamp_to_double(
			t4_sec,
			t4_frac,
			ERROR_ESTIMATE_DEFAULT);
		double rtt = stamp_rtt(stamp_forward_delay(d_t1, d_t2),
				       stamp_backward_delay(d_t3, d_t4));

		snprintf(msg, sizeof(msg), "%s[%d]: RTT >= -1ms", label, i);
		EXPECT_TRUE(rtt >= -1.0, msg);

		snprintf(msg, sizeof(msg), "%s[%d]: RTT < 100ms", label, i);
		EXPECT_TRUE(rtt < 100.0, msg);
	}

cleanup:
	if (!SOCKET_ERROR_CHECK(sender_sock)) {
		CLOSE_SOCKET(sender_sock);
	}
	if (!SOCKET_ERROR_CHECK(reflector_sock)) {
		CLOSE_SOCKET(reflector_sock);
	}
}

// =============================================================================
// Phase 7-3: テスト分離改善
// =============================================================================

#ifndef _WIN32
// reset_global_state() がグローバル状態を既定値へ復元することを単体で検証する。
// 前テストの後処理に依存しない自己完結テスト（順序非依存）。
static void test_signal_handler_reset(void)
{
	__atomic_store_n(&g_running, 0, __ATOMIC_SEQ_CST);
	reset_global_state();
	EXPECT_TRUE(__atomic_load_n(&g_running, __ATOMIC_SEQ_CST) == 1,
		    "reset_global_state restores g_running=1");
}
#endif

int main(void)
{
#ifdef _WIN32
	if (init_winsock() != 0) {
		printf("FAIL: WSAStartup\n");
		return 1;
	}
#endif

	g_ipv6_ok = ipv6_available();

#ifndef _WIN32
	test_signal_handler();
#endif

	test_protocol_constants();
	test_struct_layout();
	test_stamp_validate_packet();
	test_stamp_ntp_to_double();
	test_stamp_get_ntp_timestamp();
	test_byte_order();
	test_stamp_parse_port();
	// IPv6対応テスト
	test_stamp_get_sockaddr_len();
	test_stamp_sockaddr_get_port();
	test_stamp_sockaddr_to_string();
	test_stamp_resolve_address();
	// NOTE: Integration test - performs real UDP I/O on loopback.
	test_ipv6_socket_communication();
#ifndef _WIN32
	test_reflector_loopback_filtering_and_padding();
#endif
	// Windows getoptテスト (分割: basic/arguments/errors/mixed)
#ifdef _WIN32
	test_stamp_getopt_basic();
	test_stamp_getopt_arguments();
	test_stamp_getopt_errors();
	test_stamp_getopt_mixed();
#endif

	// ===== 新規追加テスト =====
	// Phase 1: NTP変換マクロ
	test_nsec_to_ntp_frac();
	test_usec_to_ntp_frac();
	test_stamp_nsec_to_ntp_frac_overflow();
	test_stamp_nsec_to_ntp_frac_boundary();
#ifdef _WIN32
	test_windows_100ns_to_ntp_frac();
#endif

	// Phase 2: timespec/timeval変換 (UNIX)
#ifndef _WIN32
	test_stamp_timespec_to_ntp();
	test_stamp_timeval_to_ntp();
#endif

	// Phase 3: sockaddrユーティリティ追加
	test_stamp_sockaddr_to_string_safe();
	test_stamp_format_sockaddr_with_port();
	test_stamp_format_sockaddr_with_port_null_addr();
	test_stamp_sockaddr_to_string_safe_truncation();

	// Phase 4: stamp_resolve_address_list
	test_stamp_resolve_address_list();

	// Phase 5: stamp_validate_packet拡張
	test_stamp_validate_packet_boundary_sizes();
	test_stamp_validate_test_payload_for_reflector();
	test_stamp_check_reflector_input();

	// Phase 6: RTT計算
	test_rtt_calculation();
	test_negative_delay_detection();

	// Phase 7: 統計計算
	test_statistics_calculation();
	test_packet_loss_calculation();
	test_packet_loss_underflow();
	test_stamp_jitter_edge_cases();
	test_stamp_packet_loss_edge_cases();

	// Phase 8: パケット構築
	test_sender_packet_fields();
	test_reflector_packet_fields();
	test_sender_ttl_setting();

	// Phase 9: Error Estimate
	test_error_estimate_fields();

	// Phase 10: HW タイムスタンプ
#ifdef __linux__
	test_stamp_extract_kernel_timestamp_linux_hw_priority();
	test_stamp_extract_kernel_timestamp_linux_sw_fallback();
	test_stamp_extract_kernel_timestamp_linux_ptp_hw();
	test_stamp_extract_kernel_timestamp_linux_ptp_sw();
	test_stamp_extract_kernel_timestamp_linux_timestampns();
	test_stamp_extract_kernel_timestamp_linux_timestamp();
	test_stamp_extract_kernel_timestamp_linux_legacy_fallback();
	test_stamp_extract_kernel_timestamp_linux_all_zero();
	test_stamp_extract_kernel_timestamp_linux_invalid_nsec();
	test_stamp_extract_kernel_timestamp_linux_truncated_cmsg();
	test_stamp_extract_kernel_timestamp_linux_scm_timestamp_invalid_usec();
	test_stamp_extract_kernel_timestamp_linux_scm_timestamp_truncated();
	test_stamp_extract_kernel_timestamp_linux_scm_timestamping_truncated();
	test_stamp_extract_kernel_timestamp_linux_all_invalid_nsec();
#endif
#ifdef _WIN32
	test_stamp_extract_kernel_timestamp_windows();
#endif

	// Phase 11: PTP タイムスタンプ変換
	test_stamp_ptp_to_double();
#ifndef _WIN32
	test_stamp_timespec_to_ptp();
#endif
	test_ntp_ptp_cross_conversion();
	test_stamp_timestamp_to_double_dispatch();
	test_error_estimate_ptp_default();
	test_stamp_get_ptp_timestamp();
#ifndef _WIN32
	test_stamp_get_timestamp_dispatch();
	test_stamp_timespec_to_stamp_dispatch();
#endif

	// Edge cases
	test_stamp_ntp_to_double_edge_cases();
	test_stamp_ptp_to_double_edge_cases();
	test_ntp_2036_rollover();

	// Phase 12: PHC マクロ
#ifdef __linux__
	test_phc_clockid_macros();
	test_phc_timestamp_with_realtime();
	test_hwts_caps_phc_index();
	test_stamp_get_phc_timestamp_invalid_clockid();
#endif

	// Cleanup helpers
#ifndef _WIN32
	test_cleanup_helpers();
#endif

	// Phase 13: ジッター統計
	test_jitter_calculation();

	// Phase 7: エッジケーステスト + stamp_build_reflector_packet
	test_edge_cases();

	// Phase 14: E2E Integration (loopback)
	test_e2e_stamp_loopback();
	test_e2e_stamp_loopback_ptp();
	test_e2e_stamp_loopback_multi_seq();
	test_e2e_stamp_loopback_padded();

#ifndef _WIN32
	// Phase 7-3: テスト分離確認
	test_signal_handler_reset();
#endif

	if (g_tests_failed == 0) {
		printf("PASS: %d tests (%d skipped)\n",
		       g_tests_run,
		       g_tests_skipped);
#ifdef _WIN32
		WSACleanup();
#endif
		return 0;
	}

	printf("FAIL: %d of %d tests (%d skipped)\n",
	       g_tests_failed,
	       g_tests_run,
	       g_tests_skipped);
#ifdef _WIN32
	WSACleanup();
#endif
	return 1;
}
