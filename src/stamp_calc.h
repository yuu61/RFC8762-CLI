// RFC 8762 STAMP - 純粋計算・パケット構築関数

#ifndef STAMP_CALC_H
#define STAMP_CALC_H

#include "stamp_protocol.h"

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
