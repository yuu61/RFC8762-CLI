// RFC 8762 STAMP - ファイアウォール（システム設定）管理の実装
// reflector.c から分離。nftables による UDP ポート許可ルールの自動追加/削除。

#include "stamp_firewall.h"

#ifndef _WIN32

#include <sys/wait.h> // waitpid / WIFEXITED / WEXITSTATUS

// ファイアウォール管理用のグローバル変数
static uint16_t g_firewall_port = 0;
static int g_firewall_family = AF_UNSPEC;
static volatile sig_atomic_t g_firewall_rule_added = 0;

/**
 * nftコマンドをfork+execvpで安全に実行（シェルインジェクション防止）
 * @param argv execvp用の引数配列（NULL終端）
 * @param suppress_stderr
 * trueの場合、子プロセスでstderrを/dev/nullにリダイレクト
 * @return 子プロセスの終了コード、エラー時-1
 */
__attribute__((cold)) static int run_nft_command(const char *const argv[],
						 bool suppress_stderr)
{
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		if (suppress_stderr) {
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) {
				(void)dup2(devnull, STDERR_FILENO);
				close(devnull);
			}
		}
		// execvp は char *const argv[] を要求するが、
		// const char *const argv[] から安全にキャスト可能
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
		execvp(argv[0], (char *const *)argv);
#pragma GCC diagnostic pop
		_exit(127);
	}
	int status;
	if (waitpid(pid, &status, 0) < 0) {
		return -1;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int stamp_firewall_format_port(char *buf, size_t buflen, uint16_t port)
{
	if (port == 0) {
		return -1;
	}
	int n = snprintf(buf, buflen, "%u", port);
	if (n < 0 || (size_t)n >= buflen) {
		return -1;
	}
	return 0;
}

/**
 * ファイアウォールルールを追加（nftables使用）
 * @param port UDPポート番号
 * @param family アドレスファミリ（未使用：nftables inet
 * familyがIPv4/IPv6両対応のため）
 * @return 成功時0、エラー時-1
 */
__attribute__((cold)) static int add_firewall_rule(
	uint16_t port,
	__attribute__((unused)) int family)
{
	char port_str[16];

	if (geteuid() != 0) {
		return -1;
	}

	if (stamp_firewall_format_port(port_str, sizeof(port_str), port) != 0) {
		fprintf(stderr,
			"Error: Invalid port number for firewall rule: %u\n",
			port);
		return -1;
	}

	{
		const char *const argv[] = {"nft",
					    "add",
					    "table",
					    "inet",
					    "stamp_reflector",
					    NULL};
		if (run_nft_command(argv, true) != 0) {
			fprintf(stderr,
				"Warning: Failed to create nftables table\n");
			return -1;
		}
	}

	{
		const char *const argv[] = {
			"nft",
			"add",
			"chain",
			"inet",
			"stamp_reflector",
			"input",
			"{ type filter hook input priority 0 ; }",
			NULL};
		if (run_nft_command(argv, true) != 0) {
			fprintf(stderr,
				"Warning: Failed to create nftables chain\n");
			const char *const del_argv[] = {"nft",
							"delete",
							"table",
							"inet",
							"stamp_reflector",
							NULL};
			(void)run_nft_command(del_argv, true);
			return -1;
		}
	}

	{
		const char *const argv[] = {"nft",
					    "add",
					    "rule",
					    "inet",
					    "stamp_reflector",
					    "input",
					    "udp",
					    "dport",
					    port_str,
					    "accept",
					    NULL};
		if (run_nft_command(argv, false) != 0) {
			fprintf(stderr,
				"Warning: Failed to add nftables rule for "
				"port %u\n",
				port);
			const char *const del_argv[] = {"nft",
							"delete",
							"table",
							"inet",
							"stamp_reflector",
							NULL};
			(void)run_nft_command(del_argv, true);
			return -1;
		}
	}

	printf("Firewall rule added for UDP port %u (IPv4+IPv6 via nftables)\n",
	       port);
	g_firewall_port = port;
	g_firewall_family = family;
	g_firewall_rule_added = 1;
	return 0;
}

/**
 * ファイアウォールルールを削除
 */
__attribute__((cold)) static void remove_firewall_rule(void)
{
	uint16_t port;

	// 二重実行防止
	{
		sig_atomic_t expected = 1;
		if (!__atomic_compare_exchange_n(&g_firewall_rule_added,
						 &expected,
						 0,
						 false,
						 __ATOMIC_SEQ_CST,
						 __ATOMIC_SEQ_CST)) {
			return;
		}
	}

	port = g_firewall_port;

	if (port == 0) {
		return;
	}

	const char *const argv[] =
		{"nft", "delete", "table", "inet", "stamp_reflector", NULL};
	if (run_nft_command(argv, true) == 0) {
		printf("Firewall rules removed for UDP port %u (nftables table "
		       "deleted)\n",
		       port);
	} else {
		fprintf(stderr, "Warning: Failed to remove nftables table\n");
	}

	g_firewall_port = 0;
	g_firewall_family = AF_UNSPEC;
}

__attribute__((cold)) int stamp_firewall_setup(uint16_t port, int family)
{
	if (geteuid() != 0) {
		// 非 root ではファイアウォール設定を行わない（追加不要）
		return 0;
	}

	// TODO: atexit() が root 権限を必要とするため権限ドロップは未実装。
	// 将来的には CAP_NET_ADMIN のみ保持か systemd socket activation を検討。
	if (add_firewall_rule(port, family) != 0) {
		return -1;
	}
	if (atexit(remove_firewall_rule) != 0) {
		fprintf(stderr,
			"Warning: atexit() failed; firewall rule may not be "
			"cleaned up\n");
	}
	return 0;
}

#else
extern int stamp_firewall_windows_placeholder; // 空翻訳単位（ISO C 禁止）回避
#endif // !_WIN32
