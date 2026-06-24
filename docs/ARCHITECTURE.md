# アーキテクチャ

## プロジェクト構成

```
RFC8762-CLI/
├── CMakeLists.txt        # CMake ビルド設定
├── CMakePresets.json     # CMake プリセット (debug/release)
├── README.md             # プロジェクト概要
├── ROADMAP.md            # 開発ロードマップ
├── CONTRIBUTING.md       # 貢献ガイド
├── .clang-format         # コードフォーマット設定 (Linux Kernel スタイル)
├── .clang-tidy           # 命名規則・品質チェック設定
├── .cppcheck-suppressions # cppcheck 抑制リスト
├── .github/
│   └── workflows/ci.yml  # GitHub Actions CI
├── build/                # ビルド成果物（自動生成）
├── docs/
│   ├── RFC8762.txt       # RFC 8762 仕様書
│   ├── BUILD.md          # ビルドガイド
│   ├── USAGE.md          # 使い方ガイド
│   └── ARCHITECTURE.md   # このファイル
├── src/
│   ├── stamp.h           # アンブレラヘッダー
│   ├── stamp_platform.h  # プラットフォーム抽象化 + getopt
│   ├── stamp_protocol.h  # プロトコル定数・パケット構造体
│   ├── stamp_time.h      # タイムスタンプ取得・変換・計算関数
│   ├── stamp_kernel_ts.h # カーネル/HW タイムスタンプ・PHC 連携
│   ├── stamp_net.h       # アドレス解決・整形・ポートパース
│   ├── stamp_signal.h    # シグナルハンドラ（プロセスライフサイクル制御）
│   ├── stamp_firewall.h  # ファイアウォール自動設定（reflector 専用・非 Windows）
│   ├── stamp_firewall.c  # ファイアウォール自動設定の実装
│   ├── reflector.c       # Reflector 実装
│   └── sender.c          # Sender 実装
└── tests/
    └── test_stamp.c      # ユニットテスト（250+ テスト）
```

## ヘッダー分割の設計思想

`stamp.h` はアンブレラヘッダーとして機能し、5 つの専用ヘッダーを `#include` します。各ヘッダーは単一の責務を持ち、依存関係を明確にしています。

| ヘッダー | 責務 |
| -- | -- |
| `stamp_platform.h` | OS 判定マクロ、型定義、`getopt` 互換レイヤー（Windows 向け） |
| `stamp_protocol.h` | RFC 8762 パケット構造体、プロトコル定数、シーケンス番号管理 |
| `stamp_time.h` | NTP/PTP タイムスタンプ変換、遅延計算、統計処理 |
| `stamp_kernel_ts.h` | `SO_TIMESTAMPING` / HW タイムスタンプ制御、PHC デバイス連携 |
| `stamp_net.h` | アドレス解決・整形、ポートパース |
| `stamp_signal.h` | シグナルハンドラ（プロセスライフサイクル制御） |
| `stamp_firewall.h` / `.c` | ファイアウォール自動設定（Linux/UNIX のみ・nftables による UDP ポート許可ルールの自動追加/削除・reflector 専用） |

この分割により:

- ヘッダー単体での理解が容易になる
- 変更の影響範囲が限定される
- テストで特定モジュールだけを含められる

## コーディング規約と静的解析

### スタイル

Linux Kernel スタイルを採用。`.clang-format` で自動整形します。

- **インデント**: タブ（幅 8）
- **中括弧**: K&R スタイル（関数定義のみ次の行に `{`）— `BreakBeforeBraces: Linux`
- **カラム制限**: 80 文字

### 命名規則

`.clang-tidy` の `readability-identifier-naming` で強制します。

| 対象 | ルール | 例 |
| -- | -- | -- |
| 関数（公開 API） | `stamp_` + `snake_case` | `stamp_get_ntp_timestamp()` |
| 関数（static） | `snake_case` | `print_statistics()` |
| グローバル変数 | `g_` + `snake_case` | `g_running` |
| ローカル変数・パラメータ | `snake_case` | `sockfd`, `buf` |
| マクロ | `UPPER_CASE` | `STAMP_PORT` |
| 構造体・共用体・typedef | `snake_case`（`_t` なし） | `struct stamp_sender_packet` |
| 列挙定数 | `UPPER_CASE` | `ERROR_ESTIMATE_S_BIT` |

例外: `likely`/`unlikely` マクロは Linux Kernel 慣例で小文字を許容。

### 静的解析ツール

| ツール | 設定ファイル | 役割 |
| -- | -- | -- |
| clang-format | `.clang-format` | コード整形（インデント・中括弧・空白） |
| clang-tidy | `.clang-tidy` | 命名規則、バグ検出、品質チェック |
| cppcheck | `.cppcheck-suppressions` | メモリリーク、未定義動作、静的解析 |
| GCC `-Werror` | `CMakeLists.txt` | 30+ の厳格な警告フラグ（ビルド時） |
| CodeQL | `.github/workflows/ci.yml` | セキュリティ・品質の静的解析（CI） |

## GNU 拡張の活用方針

本プロジェクトは GCC 14+ を必須とし、GNU C17（`-std=gnu17`）でビルドします。以下の GNU 拡張を積極的に活用しています:

- **分岐予測ヒント** (`__builtin_expect`): エラーパスを cold path としてマーク
- **関数属性** (`__attribute__((hot))`, `__attribute__((cold))`): ホットパス/コールドパスの最適化ヒント
- **RAII cleanup** (`__attribute__((cleanup))`): リソースの自動解放
- **オーバーフロー検出** (`__builtin_add_overflow` 等): 安全な整数演算
- **アトミック操作** (`__atomic_*`): シグナルハンドラとの安全な共有変数アクセス
- **フォーマット属性** (`__attribute__((format))`): printf 系関数の型チェック強化

## STAMP パケットフォーマット

RFC 8762 で定義されている非認証モードのパケットフォーマットを実装しています。

- **シーケンス番号**: 各パケットに一意の識別子
- **タイムスタンプ**: 64 ビット（NTP 形式または PTP truncated 形式）
- **エラー推定**: タイムスタンプの精度情報（Z-bit で NTP/PTP 自動判定）

## タイムスタンプ体系

### タイムスタンプ形式

| 形式 | フォーマット | オプション | 精度 |
| -- | -- | -- | -- |
| NTP（デフォルト） | 32bit 秒 + 32bit 小数部（1900 年起点） | なし | ~0.23 ns |
| PTP truncated | 32bit 秒 + 32bit ナノ秒 | `-P` | 1 ns |

### タイムスタンプ取得元

| レベル | 取得元 | オプション | 備考 |
| -- | -- | -- | -- |
| ユーザースペース | `clock_gettime(CLOCK_REALTIME)` / `GetSystemTimeAsFileTime` | なし | 全プラットフォーム |
| カーネル | `SO_TIMESTAMPING` / `SIO_TIMESTAMPING` | なし（自動有効化） | Linux / Windows |
| NIC ハードウェア | `SCM_TIMESTAMPING` ts[2] (raw HW) | `-i <iface>` | Linux のみ |
| PHC クロック | `/dev/ptpN` 経由 `clock_gettime` | `-c -i <iface>` | Linux のみ |

### HW タイムスタンプの適用範囲

STAMP の 4 つのタイムスタンプ（T1〜T4）のうち、HW TX タイムスタンプを適用できるのは T1 のみです。

| タイムスタンプ | 役割 | HW TS | 取得方法 |
| -- | -- | -- | -- |
| T1 | Sender 送信時刻 | 可 | `sendto()` 後に `MSG_ERRQUEUE` から取得し上書き |
| T2 | Reflector 受信時刻 | 可 | `recvmsg()` の `SCM_TIMESTAMPING` ts[2] から取得 |
| T3 | Reflector 送信時刻 | 不可 | パケットに格納してから送信するため、送信後取得では間に合わない |
| T4 | Sender 受信時刻 | 可 | `recvmsg()` の `SCM_TIMESTAMPING` ts[2] から取得 |

**T3 の制約**: T3 は Reflector 応答パケットのフィールドに書き込んでから `sendto()` する必要がある。T1 のように送信後に `MSG_ERRQUEUE` から HW TX タイムスタンプを取得して上書きする方式は、既にパケットが送出済みのため使えない。

この制約に対する代替手法:

| 手法 | 概要 | STAMP での適用 |
| -- | -- | -- |
| One-step TX | NIC が送出時にパケット内にタイムスタンプを書き込む | Linux カーネルは PTP フレーム専用で、任意 UDP パケットに非対応 |
| Two-step | 送信後に Follow-Up メッセージで実際のタイムスタンプを通知 | RFC 8762 に Follow-Up の定義がない |
| PHC 読み取り（採用） | `sendto()` 直前に NIC と同一の HW クロック（`/dev/ptpN`）を読む | 本実装で `-c -i <iface>` オプション時に使用 |

PHC 読み取りは真の HW TX タイムスタンプではないが、NIC と同一クロックソースのため、カーネル SW タイムスタンプより高精度な近似値となる。

### クロックドメインの一貫性

遅延計算の正確性には、各タイムスタンプのクロックドメインの一貫性が必要である。

- **Forward delay** (T2 - T1): T1 と T2 が同一クロックドメインであること
- **Backward delay** (T4 - T3): T3 と T4 が同一クロックドメインであること

PHC モード（`-c -i`）では T3 を PHC（`/dev/ptpN`）から直接取得する。T1・T2・T4 は `SCM_TIMESTAMPING` の `ts[2]`（raw HW タイムスタンプ）から取得されるため、パケットが物理 NIC を通過する異なるマシン間の通信では全タイムスタンプが NIC の HW クロックドメインに統一される。

ただし、同一マシン上で Sender と Reflector を実行した場合、パケットはカーネル内部でローカル配送され物理 NIC を通過しない。この場合 `ts[2]` はゼロとなり `ts[0]`（ソフトウェアタイムスタンプ、`CLOCK_REALTIME` ベース）にフォールバックする。T3 のみが PHC から読み取られるため、PHC と `CLOCK_REALTIME` にオフセットがあると Backward delay が不正な値となる。

| 条件 | T1 | T2 | T3 | T4 | 結果 |
| -- | -- | -- | -- | -- | -- |
| 異なるマシン間 + 両方 `-c -i` | HW (PHC) | HW (PHC) | PHC | HW (PHC) | 正常（最高精度） |
| 異なるマシン間 + Reflector のみ `-c -i` | SW (REALTIME) | HW (PHC) or SW | **PHC** | SW (REALTIME) | T2 フォールバック時に不一致 |
| 異なるマシン間 + PHC なし | SW (REALTIME) | SW (REALTIME) | SW (REALTIME) | SW (REALTIME) | 正常 |
| 同一マシン + PHC | SW (REALTIME) | SW (REALTIME) | **PHC** | SW (REALTIME) | T3 のみクロックドメイン不一致 |
| 同一マシン + PHC なし | SW (REALTIME) | SW (REALTIME) | SW (REALTIME) | SW (REALTIME) | 正常 |
| Windows/WSL2 含む構成 + `-c` | Win (REALTIME) | **PHC** or SW | **PHC** | Win (REALTIME) | T2 フォールバック時に不一致 |
| Windows/WSL2 含む構成 + `-c` なし | Win (REALTIME) | SW (REALTIME) | SW (REALTIME) | Win (REALTIME) | 正常 |

**`-c` オプションの使用条件:**

- Sender と Reflector の**両方**に `-c -i <iface>` を指定すること
- 両方がネイティブ Linux で PHC 対応の物理 NIC を搭載していること
- パケットが物理 NIC を経由すること（同一マシンでのテストは不可）
- Windows / WSL / WSL2 は PHC 非対応のため、これらが含まれる構成では `-c` を使用しないこと（WSL2 は仮想 NIC 経由のため物理 NIC の PHC にアクセス不可）

片方のみ `-c` を指定した場合、T2 が HW RX タイムスタンプを取得できればクロックドメインは一致するが、ソフトウェアタイムスタンプにフォールバックすると T2（`CLOCK_REALTIME`）と T3（PHC）が不一致となり RTT が不正な値になる。NIC が任意の UDP パケットに HW RX タイムスタンプを付与するとは限らない（PTP イベントフレーム専用の NIC もある）ため、フォールバックの可能性を排除できない。

## 出力カラム

| カラム | 説明 |
| -- | -- |
| Seq | シーケンス番号 |
| Fwd(ms) | 往路遅延（Sender → Reflector） |
| Bwd(ms) | 復路遅延（Reflector → Sender） |
| RTT(ms) | 往復遅延（Fwd + Bwd） |
| Offset(ms) | クロックオフセット（Reflector の時計のずれ） |
| [adj_Fwd] | オフセット補正した往路遅延（参考値） |
| [adj_Bwd] | オフセット補正した復路遅延（参考値） |

**補正値の意味**: Sender と Reflector の時計が完全に同期していない場合、Fwd/Bwd の値は非対称になります。`[adj_Fwd]` と `[adj_Bwd]` は、クロックオフセットを考慮した推定値で、理想的には対称な値になります。

## ポート番号

- **デフォルトポート**: 862/UDP（IANA 登録済み STAMP ポート）
- カスタムポートの使用も可能
