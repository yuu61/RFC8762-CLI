// RFC 8762 STAMP - 純粋計算・パケット構築関数

#ifndef STAMP_CALC_H
#define STAMP_CALC_H

#include "stamp_protocol.h"

/**
 * モードに応じた既定 Error Estimate を htons 済み（ネットワークバイトオーダー）で返す
 *
 * Sender/Reflector の両 main() が同一ロジックで既定値を選択していたのを集約する。
 *
 * @param ptp_mode true=PTP(Z=1), false=NTP
 * @return htons 済み Error Estimate
 */
static inline uint16_t stamp_default_error_estimate_nbo(bool ptp_mode)
{
	return htons((uint16_t)(ptp_mode ? ERROR_ESTIMATE_PTP_DEFAULT
					 : ERROR_ESTIMATE_DEFAULT));
}

/**
 * 規定サイズ未満のパケットをゼロパディングし、送信長を算出（純粋計算、I/Oなし）
 *
 * STAMP_BASE_PACKET_SIZE 未満の場合のみバッファ末尾を 0 埋めし、送信長を
 * 基本サイズへ補正する。警告出力は I/O 担当の呼び出し元に委ねる。
 *
 * @param buffer         パケットバッファ（パディング時に末尾を 0 埋め）
 * @param recv_len       受信バイト数
 * @param out_send_len   送信に用いるパケット長を格納
 * @param out_was_padded パディングを行った場合 true を格納
 */
static inline void stamp_pad_to_base_size(uint8_t *buffer,
					  int recv_len,
					  int *out_send_len,
					  bool *out_was_padded)
{
	if (recv_len < STAMP_BASE_PACKET_SIZE) {
		memset(buffer + recv_len,
		       0,
		       (size_t)(STAMP_BASE_PACKET_SIZE - recv_len));
		*out_send_len = STAMP_BASE_PACKET_SIZE;
		*out_was_padded = true;
	} else {
		*out_send_len = recv_len;
		*out_was_padded = false;
	}
}

/**
 * Reflectorパケットを構築（純粋なデータ変換、I/Oなし）
 *
 * Session-Senderパケットの情報をReflectorパケットにコピーし、
 * T2タイムスタンプとメタデータを設定する。
 *
 * @param buffer       パケットバッファ（上書きされる）
 * @param send_len     送信パケットサイズ
 * @param ttl          受信時のTTL/Hop Limit
 * @param t2_sec       T2受信タイムスタンプ秒部分（NBO）
 * @param t2_frac      T2受信タイムスタンプ小数/ナノ秒部分（NBO）
 * @param error_est_nbo htons済みError Estimate値
 */
static inline void stamp_build_reflector_packet(uint8_t *buffer,
						int send_len,
						uint8_t ttl,
						uint32_t t2_sec,
						uint32_t t2_frac,
						uint16_t error_est_nbo)
{
	struct stamp_sender_packet sender;
	struct stamp_reflector_packet *packet;

	memset(&sender, 0, sizeof(sender));
	size_t copy_len = (size_t)(send_len < (int)sizeof(sender)
					   ? send_len
					   : (int)sizeof(sender));
	memcpy(&sender, buffer, copy_len);

	packet = (struct stamp_reflector_packet *)buffer;

	// Session-Sender の情報をコピー (RFC 8762 Section 4.3.1)
	packet->seq_num = sender.seq_num;
	packet->sender_seq_num = sender.seq_num;
	packet->sender_ts_sec = sender.timestamp_sec;
	packet->sender_ts_frac = sender.timestamp_frac;
	packet->sender_err_est = sender.error_estimate;
	packet->sender_ttl = ttl;

	// Reflector タイムスタンプと MBZ フィールド
	packet->rx_sec = t2_sec;
	packet->rx_frac = t2_frac;
	packet->error_estimate = error_est_nbo;
	packet->mbz_1 = 0;
	packet->mbz_2 = 0;
	memset(packet->mbz_3, 0, sizeof(packet->mbz_3));
}

#endif // STAMP_CALC_H
