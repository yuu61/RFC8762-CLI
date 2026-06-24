// RFC 8762 STAMP - 統計レポートの機械可読出力（JSON / CSV）
//
// human / JSON / CSV の 3 形式を同一の struct stamp_report から生成する。
// 外部ライブラリ非依存の手書きシリアライザ。-Wformat-nonliteral 対策として
// すべての format 文字列はリテラル直書きとし、ロケール非依存化のため出力後に
// 小数点を '.' へ正規化する。非有限値(NaN/Inf)は JSON では null、CSV では空。

#ifndef STAMP_REPORT_H
#define STAMP_REPORT_H

#include "stamp_platform.h"

// JSON 文字列エスケープ後のターゲット表記を収める最大長
#define STAMP_REPORT_STR_MAX 128
// ISO8601 UTC タイムスタンプ "YYYY-MM-DDTHH:MM:SSZ" + NUL
#define STAMP_REPORT_TS_MAX 24
// 数値整形バッファ長
#define STAMP_REPORT_NUM_MAX 32

// 出力形式
enum output_format {
	OUTPUT_HUMAN = 0,
	OUTPUT_JSON,
	OUTPUT_CSV,
};

// 数値メトリクス 1 件（value が非有限なら未集計＝JSON null / CSV 空フィールド）
struct stamp_report_field {
	const char *key;
	double value;
};

// レポート全体（メタデータ + 数値メトリクス配列）
struct stamp_report {
	const char *target; // 例 "127.0.0.1:862"（呼び出し側が所有）
	const char *family; // "IPv4" / "IPv6"
	bool ptp;
	bool oneway;
	uint32_t packets_tx;
	uint32_t packets_rx;
	uint32_t timeouts;
	double loss_ratio; // 0.0–1.0
	const struct stamp_report_field *fields;
	size_t field_count;
};

/**
 * 現在時刻を ISO8601 UTC 文字列 "YYYY-MM-DDTHH:MM:SSZ" に整形する。
 * @param buf 出力バッファ
 * @param buflen バッファ長（STAMP_REPORT_TS_MAX 以上）
 * @return 成功時 0、失敗時 -1（buf は空文字）
 */
__attribute__((nonnull(1))) static inline int
stamp_report_iso8601_utc(char *buf, size_t buflen)
{
	time_t now = time(NULL);
	if (now == (time_t)-1) {
		buf[0] = '\0';
		return -1;
	}
	struct tm tm_utc;
#ifdef _WIN32
	if (gmtime_s(&tm_utc, &now) != 0) {
		buf[0] = '\0';
		return -1;
	}
#else
	if (gmtime_r(&now, &tm_utc) == NULL) {
		buf[0] = '\0';
		return -1;
	}
#endif
	if (strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
		buf[0] = '\0';
		return -1;
	}
	return 0;
}

/**
 * double をロケール非依存の固定小数文字列に整形する。
 * 非有限値（NaN/Inf）は空文字を返す（呼び出し側で null/空を出し分ける）。
 * @param buf 出力バッファ
 * @param buflen バッファ長
 * @param v 値
 * @param prec 小数桁数（6 のみ高精度、その他は 3 桁）
 */
__attribute__((nonnull(1))) static inline void
stamp_report_fmt_double(char *buf, size_t buflen, double v, int prec)
{
	if (!isfinite(v)) {
		buf[0] = '\0';
		return;
	}
	int written = (prec == 6) ? snprintf(buf, buflen, "%.6f", v)
				  : snprintf(buf, buflen, "%.3f", v);
	if (written < 0 || (size_t)written >= buflen) {
		buf[0] = '\0';
		return;
	}
	// ロケールが ',' を小数点に使う環境でも '.' に正規化する
	for (char *p = buf; *p != '\0'; p++) {
		if (*p == ',') {
			*p = '.';
		}
	}
}

/**
 * JSON 文字列エスケープ（" と \ と制御文字 0x00-0x1F を \uXXXX に）。
 * @param in 入力文字列
 * @param out 出力バッファ
 * @param outlen 出力バッファ長
 */
__attribute__((nonnull(1, 2))) static inline void
stamp_report_json_escape(const char *in, char *out, size_t outlen)
{
	size_t o = 0;
	// 最長エスケープ "\u00XX"(6) + NUL に備え o+7 で余白を確保
	for (size_t i = 0; in[i] != '\0' && o + 7 < outlen; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c == '"' || c == '\\') {
			out[o++] = '\\';
			out[o++] = (char)c;
		} else if (c < 0x20) {
			int w = snprintf(out + o, outlen - o, "\\u%04x", c);
			if (w < 0) {
				break;
			}
			o += (size_t)w;
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

/**
 * レポートを JSON で出力（メタデータ + 全メトリクス）。
 * 非有限値は null。format_version を埋め込む。
 * @param fp 出力先
 * @param r レポート
 */
__attribute__((nonnull(1, 2))) static inline void
stamp_report_write_json(FILE *fp, const struct stamp_report *r)
{
	char ts[STAMP_REPORT_TS_MAX];
	stamp_report_iso8601_utc(ts, sizeof(ts));
	char target[STAMP_REPORT_STR_MAX];
	stamp_report_json_escape(r->target != NULL ? r->target : "",
				 target,
				 sizeof(target));
	char loss[STAMP_REPORT_NUM_MAX];
	stamp_report_fmt_double(loss, sizeof(loss), r->loss_ratio, 6);

	fputs("{\n", fp);
	fputs("  \"format_version\": \"1.0\",\n", fp);
	fprintf(fp, "  \"timestamp\": \"%s\",\n", ts);
	fprintf(fp, "  \"target\": \"%s\",\n", target);
	fprintf(fp,
		"  \"family\": \"%s\",\n",
		r->family != NULL ? r->family : "");
	fputs("  \"protocol\": \"STAMP\",\n", fp);
	fprintf(fp, "  \"ptp\": %s,\n", r->ptp ? "true" : "false");
	fprintf(fp, "  \"oneway\": %s,\n", r->oneway ? "true" : "false");
	fprintf(fp, "  \"packets_tx\": %u,\n", r->packets_tx);
	fprintf(fp, "  \"packets_rx\": %u,\n", r->packets_rx);
	fprintf(fp, "  \"timeouts\": %u,\n", r->timeouts);
	fprintf(fp, "  \"loss_ratio\": %s", loss[0] != '\0' ? loss : "null");
	for (size_t i = 0; i < r->field_count; i++) {
		char val[STAMP_REPORT_NUM_MAX];
		stamp_report_fmt_double(val,
					sizeof(val),
					r->fields[i].value,
					3);
		fprintf(fp,
			",\n  \"%s\": %s",
			r->fields[i].key,
			val[0] != '\0' ? val : "null");
	}
	fputs("\n}\n", fp);
}

/**
 * レポートを CSV で出力（# コメント行 + ヘッダ行 + データ 1 行、列固定）。
 * 非有限値は空フィールド。
 * @param fp 出力先
 * @param r レポート
 */
__attribute__((nonnull(1, 2))) static inline void
stamp_report_write_csv(FILE *fp, const struct stamp_report *r)
{
	char ts[STAMP_REPORT_TS_MAX];
	stamp_report_iso8601_utc(ts, sizeof(ts));
	char loss[STAMP_REPORT_NUM_MAX];
	stamp_report_fmt_double(loss, sizeof(loss), r->loss_ratio, 6);

	fputs("# format_version=1.0\n", fp);
	fputs("timestamp,target,family,protocol,ptp,oneway,"
	      "packets_tx,packets_rx,timeouts,loss_ratio",
	      fp);
	for (size_t i = 0; i < r->field_count; i++) {
		fprintf(fp, ",%s", r->fields[i].key);
	}
	fputc('\n', fp);

	fprintf(fp,
		"%s,%s,%s,STAMP,%s,%s,%u,%u,%u,%s",
		ts,
		r->target != NULL ? r->target : "",
		r->family != NULL ? r->family : "",
		r->ptp ? "true" : "false",
		r->oneway ? "true" : "false",
		r->packets_tx,
		r->packets_rx,
		r->timeouts,
		loss);
	for (size_t i = 0; i < r->field_count; i++) {
		char val[STAMP_REPORT_NUM_MAX];
		stamp_report_fmt_double(val,
					sizeof(val),
					r->fields[i].value,
					3);
		fprintf(fp, ",%s", val);
	}
	fputc('\n', fp);
}

#endif // STAMP_REPORT_H
