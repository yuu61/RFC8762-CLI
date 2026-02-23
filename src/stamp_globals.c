// RFC 8762 STAMP - グローバル変数定義
// シグナルハンドラからアクセスされる共有変数を一元管理

#include "stamp_protocol.h"

volatile sig_atomic_t g_running = 1;
