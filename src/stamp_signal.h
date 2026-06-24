// RFC 8762 STAMP - シグナル処理（プロセスライフサイクル制御）
// Ctrl+C / SIGINT・SIGTERM・SIGABRT を受けて g_running を 0 にし、
// 計測・反射ループを安全に停止させる。アドレス解決とは別個の関心として分離する。

#ifndef STAMP_SIGNAL_H
#define STAMP_SIGNAL_H

#include "stamp_platform.h"

// グローバル変数（シグナルハンドラからアクセス、stamp_globals.c で定義）
extern volatile sig_atomic_t g_running;

/**
 * シグナルハンドラ（Ctrl+C対応）
 */
#ifdef _WIN32
static inline BOOL WINAPI stamp_signal_handler(DWORD signal)
{
	if (signal == CTRL_C_EVENT) {
		__atomic_store_n(&g_running, 0, __ATOMIC_SEQ_CST);
		return TRUE;
	}
	return FALSE;
}
#else
static inline void stamp_signal_handler(int signal)
{
	if (signal == SIGINT || signal == SIGTERM || signal == SIGABRT) {
		__atomic_store_n(&g_running, 0, __ATOMIC_SEQ_CST);
	}
}
#endif

#endif // STAMP_SIGNAL_H
