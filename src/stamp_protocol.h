// RFC 8762 STAMP - プロトコル定義・定数・構造体

#ifndef STAMP_PROTOCOL_H
#define STAMP_PROTOCOL_H

#include "stamp_platform.h"

// NTPタイムスタンプのオフセット (1900年1月1日から1970年1月1日までの秒数)
#define NTP_OFFSET 2208988800UL

// STAMPプロトコル定数
#define STAMP_PORT	       862	     // STAMP標準ポート番号 (RFC 8762 Section 4.1)
#define STAMP_MAX_PORT	       65535	     // ポート番号の最大値 (UINT16_MAX)
#define STAMP_BASE_PACKET_SIZE 44	     // 基本パケットサイズ(RFC 4.2.1, 4.3.1) (バイト)
#define STAMP_MAX_PACKET_SIZE  65507	     // UDPペイロード最大長
#define STAMP_MAX_SSID	       65535	     // セッションセンダーIDの最大値
#define NTP_FRAC_SCALE	       4294967296.0  // 2^32
#define NTP_FRAC_SCALE_INT     4294967296ULL // 2^32 (整数版: nsec/usec -> NTP小数部)

// コントロールメッセージバッファサイズ
// WSA_CMSG_SPACE/CMSG_SPACE マクロはMinGW環境で符号変換警告を出すため、
// 固定サイズを使用。128バイトはSO_TIMESTAMPING（3つのtimespec = 24バイト）、
// TTL/HopLimit用int、および制御メッセージヘッダを格納するのに十分なサイズ。
#define STAMP_CMSG_BUFSIZE 128

// TX HWタイムスタンプ取得用定数
#define STAMP_TX_TS_MAX_RETRIES 10 // MSG_ERRQUEUE ポーリング最大回数

// 時間単位変換定数
#define NSEC_PER_SEC   1000000000ULL
#define NSEC_PER_SEC_D 1000000000.0
#define USEC_PER_SEC   1000000ULL
#define MSEC_PER_SEC   1000.0
#define IP_TTL_MAX     255

// Error Estimate フィールド (RFC 8762 Section 4.2.1, RFC 4656 Section 4.1.2)
// Format: |S|Z|Scale(6bits)|Multiplier(8bits)|
#define ERROR_ESTIMATE_S_BIT	  0x8000 // Synchronized flag (bit 15)
#define ERROR_ESTIMATE_Z_BIT	  0x4000 // Timestamp format: 0=NTP, 1=PTP (bit 14)
#define ERROR_ESTIMATE_SCALE_MASK 0x3F00 // Scale field (bits 8-13)
#define ERROR_ESTIMATE_MULT_MASK  0x00FF // Multiplier field (bits 0-7)

// デフォルト Error Estimate: S=0 (同期未保証), Z=0 (NTP), Scale=0,
// Multiplier=1 エラー = Multiplier * 2^(-32) * 2^Scale 秒 = 1 * 2^(-32) 秒 ≈
// 0.23 ns
#define ERROR_ESTIMATE_DEFAULT 0x0001

// PTP truncated timestamp 定数
#define PTP_NSEC_MAX 999999999UL

// PTP モード用 Error Estimate: S=0 (同期未保証), Z=1 (PTP), Scale=0,
// Multiplier=1
#define ERROR_ESTIMATE_PTP_DEFAULT (ERROR_ESTIMATE_Z_BIT | 0x0001)

// RFC 8762 STAMPパケット構造体 (RFC 4.2.1)
// すべてのフィールドはネットワークバイトオーダー(ビッグエンディアン)で格納される
// unauthenticated mode の基本パケットサイズ: 44バイト
struct stamp_sender_packet {
	uint32_t seq_num;	 // シーケンス番号 (4 bytes)
	uint32_t timestamp_sec;	 // タイムスタンプ 秒部分 (4 bytes)
	uint32_t timestamp_frac; // タイムスタンプ 小数部分 (4 bytes)
	uint16_t error_estimate; // エラー推定値 (2 bytes)
	uint8_t mbz[30];	 // MBZ (Must Be Zero) - RFC 8762 Section 4.2.1 (30 bytes)
} STAMP_PACKED;

// RFC 8762 STAMPパケット構造体 (RFC 4.3.1)
// unauthenticated mode の基本パケットサイズ: 44バイト
struct stamp_reflector_packet {
	uint32_t seq_num;	 // シーケンス番号 (4 bytes)
	uint32_t timestamp_sec;	 // 送信タイムスタンプ 秒部分 (4 bytes)
	uint32_t timestamp_frac; // 送信タイムスタンプ 小数部分 (4 bytes)
	uint16_t error_estimate; // エラー推定値 (2 bytes)
	uint16_t mbz_1;		 // MBZ (Must Be Zero) - RFC 8762 Section 4.3.1 (2 bytes)
	uint32_t rx_sec;	 // 受信タイムスタンプ 秒部分 (4 bytes)
	uint32_t rx_frac;	 // 受信タイムスタンプ 小数部分 (4 bytes)
	uint32_t sender_seq_num; // Session-Sender Sequence Number (4 bytes)
	uint32_t sender_ts_sec;	 // Session-Sender Timestamp 秒部分 (4 bytes)
	uint32_t sender_ts_frac; // Session-Sender Timestamp 小数部分 (4 bytes)
	uint16_t sender_err_est; // Session-Sender Error Estimate (2 bytes)
	uint16_t mbz_2;		 // MBZ (Must Be Zero) - RFC 8762 Section 4.3.1 (2 bytes)
	uint8_t sender_ttl;	 // Session-Sender TTL/Hop Limit (1 byte)
	uint8_t mbz_3[3];	 // MBZ (Must Be Zero) - RFC 8762 Section 4.3.1 (3 bytes)
} STAMP_PACKED;

#undef STAMP_PACKED

#endif // STAMP_PROTOCOL_H
