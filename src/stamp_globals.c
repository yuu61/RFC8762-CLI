// RFC 8762 STAMP - グローバル変数定義
// シグナルハンドラからアクセスされる共有変数を一元管理

#include "stamp.h"

volatile sig_atomic_t g_running = 1;

#ifdef _WIN32
// WSARecvMsg 関数ポインタ（stamp_recv.h の受信パスから参照、起動時に初期化）
LPFN_WSARECVMSG g_wsa_recvmsg = NULL;
#endif
