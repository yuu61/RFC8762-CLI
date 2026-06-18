// RFC 8762 STAMP - パケット入力検証（サイズ・Error Estimate・Reflector 入力前段チェック）

#ifndef STAMP_VALIDATION_H
#define STAMP_VALIDATION_H

#include "stamp_protocol.h"

/**
 * Error Estimate フィールドの multiplier 妥当性チェック
 * RFC 4656 Section 4.1.2: Multiplier MUST NOT be zero
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @return 妥当な場合1、不正な場合0
 */
static inline int stamp_validate_error_estimate_multiplier(const void *packet, int size)
{
	// Error Estimate は offset 12-13 にあるため、最低14バイト必要
	if (size < 14 || size > STAMP_MAX_PACKET_SIZE) {
		return 0;
	}
	const uint8_t *p = (const uint8_t *)packet;
	uint16_t ee = (uint16_t)((uint16_t)p[12] << 8 | p[13]);
	return (ee & ERROR_ESTIMATE_MULT_MASK) != 0 ? 1 : 0;
}

/**
 * Reflector受信前のSTAMP/TWAMP-Testペイロード妥当性チェック
 * 14-43バイトのTWAMP Light相互運用ペイロードも許容する。
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @return 妥当な場合1、不正な場合0
 */
static inline int
stamp_validate_test_payload_for_reflector(const void *packet, int size)
{
	return stamp_validate_error_estimate_multiplier(packet, size);
}

enum stamp_reflector_input_check_result {
	STAMP_REFLECTOR_INPUT_OK = 0,
	STAMP_REFLECTOR_INPUT_INVALID_PAYLOAD = 1,
	STAMP_REFLECTOR_INPUT_MISSING_TTL = 2,
};

/**
 * Reflector受信パケットの前段チェック（ペイロード妥当性 + TTL/HopLimit取得有無）
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @param sender_ttl 受信時TTL/HopLimit (0は未取得扱い)
 * @return enum stamp_reflector_input_check_result
 */
static inline enum stamp_reflector_input_check_result
stamp_check_reflector_input(const void *packet, int size, uint8_t sender_ttl)
{
	if (!stamp_validate_test_payload_for_reflector(packet, size)) {
		return STAMP_REFLECTOR_INPUT_INVALID_PAYLOAD;
	}
	if (sender_ttl == 0) {
		return STAMP_REFLECTOR_INPUT_MISSING_TTL;
	}
	return STAMP_REFLECTOR_INPUT_OK;
}

/**
 * STAMP反射パケットの妥当性チェック（サイズ + Error Estimate検証）
 * @param packet パケットデータへのポインタ
 * @param size パケットサイズ（バイト）
 * @return 妥当な場合1、不正な場合0
 */
static inline int stamp_validate_packet(const void *packet, int size)
{
	if (size < STAMP_BASE_PACKET_SIZE) {
		return 0;
	}
	return stamp_validate_error_estimate_multiplier(packet, size);
}

#endif // STAMP_VALIDATION_H
