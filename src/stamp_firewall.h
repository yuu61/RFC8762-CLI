// RFC 8762 STAMP - ファイアウォール（システム設定）管理
// Reflector 専用。root 起動時に nftables で UDP ポート許可ルールを自動追加し、
// プロセス終了時に atexit で自動削除する。
//
// 重要: このモジュールは reflector / test_stamp 専用。アンブレラ stamp.h には
// 追加しないこと（sender.c 等に未使用シンボルを持ち込むと -Werror で失敗する）。

#ifndef STAMP_FIREWALL_H
#define STAMP_FIREWALL_H

#include "stamp_platform.h" // uint16_t / size_t / _WIN32 判定

#ifndef _WIN32

/**
 * ファイアウォールの初期設定
 * root 権限ならルールを追加し、atexit でクリーンアップを登録する。
 * 非 root・追加不要時は何もしない。
 * @param port UDP ポート番号
 * @param family アドレスファミリ（nftables inet が IPv4/IPv6 両対応のため実質未使用）
 * @return ルール追加成功または追加不要時 0、追加試行が失敗時 -1
 */
int stamp_firewall_setup(uint16_t port, int family);

/**
 * ポート番号を nft 用の十進文字列へ変換する純粋関数（副作用なし）
 * @param buf 出力バッファ
 * @param buflen バッファサイズ
 * @param port UDP ポート番号
 * @return 成功時 0、port==0 または buf 不足（切り詰め）時 -1
 */
int stamp_firewall_format_port(char *buf, size_t buflen, uint16_t port);

#endif // !_WIN32
#endif // STAMP_FIREWALL_H
