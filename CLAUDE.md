# CLAUDE.md

RFC 8762 STAMP (Simple Two-way Active Measurement Protocol) の C 言語 CLI 実装。
ネットワーク遅延・ジッター・パケットロスを測定する。

## ビルドとテスト

```bash
# Debug ビルド & テスト
cmake --preset debug && cmake --build --preset debug && ctest --preset debug

# Release ビルド & テスト
cmake --preset release && cmake --build --preset release && ctest --preset release

# ASan/UBSan（Linux のみ）
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
```

**必須環境**: GCC 14+, CMake 3.25+, Ninja
**推奨ツール**: mdformat (`pipx install mdformat && pipx inject mdformat mdformat-gfm mdformat-tables`)
**C 標準**: GNU C17 (`-std=gnu17`). GNU 拡張を積極使用（`__builtin_expect`, `__attribute__`, `__atomic_*` 等）
**`-Werror` 有効**: 警告ゼロ必須。30+ の厳格な警告フラグが設定済み

## プロジェクト構成

```
src/
├── stamp.h             # アンブレラヘッダー（8つの専用ヘッダーを include）
├── stamp_platform.h    # OS 判定・型定義・getopt 互換レイヤー
├── stamp_protocol.h    # パケット構造体・プロトコル定数
├── stamp_time.h        # NTP/PTP タイムスタンプ変換・遅延計算・統計
├── stamp_calc.h        # 純粋計算・パケット構築関数
├── stamp_validation.h  # パケット入力検証（サイズ・Error Estimate・Reflector 前段チェック）
├── stamp_kernel_ts.h   # SO_TIMESTAMPING / HW タイムスタンプ・ソケット TS 設定・PHC 連携
├── stamp_recv.h        # タイムスタンプ付き受信 plumbing（Sender/Reflector 共通）
├── stamp_net.h         # シグナルハンドラ・アドレス解決
├── stamp_firewall.h    # ファイアウォール自動設定（reflector 専用・非 Windows）
├── stamp_firewall.c    # ファイアウォール自動設定の実装（nftables）
├── stamp_globals.c     # グローバル変数定義（シグナルハンドラ共有変数）
├── sender.c            # Sender 実装
└── reflector.c         # Reflector 実装
tests/
└── test_stamp.c        # ユニットテスト（250+ テスト）
```

## コーディング規約

- **スタイル**: Linux Kernel スタイル（`.clang-format` 準拠）
- **インデント**: タブ（幅 8）
- **括弧**: K&R スタイル（関数定義のみ次の行に `{`）
- **命名規則**（`.clang-tidy` で強制）:
  - 関数: `snake_case`（公開 API は `stamp_` プレフィックス）
  - グローバル変数・ファイルスコープ static: `g_` + `snake_case`
  - ローカル変数・パラメータ: `snake_case`
  - マクロ: `UPPER_CASE`（`likely`/`unlikely` は例外）
  - 構造体・共用体・typedef: `snake_case`（`_t` サフィックスなし）
  - 列挙定数: `UPPER_CASE`
- **クロスプラットフォーム**: `#ifdef` でプラットフォーム分岐（Windows / Linux / macOS）
- **エラー処理**: 全システムコールの戻り値をチェック

## 静的解析

```bash
# clang-tidy（命名規則・品質チェック）
clang-tidy -p build/debug src/*.c

# cppcheck（メモリリーク・未定義動作等）
cppcheck --enable=all --std=c17 \
  --suppressions-list=.cppcheck-suppressions \
  --library=posix -I src/ src/ tests/
```

設定ファイル: `.clang-format`, `.clang-tidy`, `.cppcheck-suppressions`

## コード修正後のチェック

コードを修正した後は、必要に応じて以下を順に実行する:

1. **C フォーマッター**: `clang-format -i src/*.c src/*.h tests/*.c`
2. **Markdown フォーマッター**: `mdformat --number --compact-tables docs/*.md CLAUDE.md`
3. **ビルド & テスト**: `cmake --build --preset debug && ctest --preset debug`
4. **リンター**: `clang-tidy -p build/debug src/*.c src/*.h tests/*.c`
5. **静的解析**: `cppcheck --enable=all --std=c17 --suppressions-list=.cppcheck-suppressions --library=posix --error-exitcode=1 --inline-suppr --check-level=exhaustive --force -I src/ src/ tests/`

## テストの追加・更新

- 機能追加・変更時は `tests/test_stamp.c` に対応するテストを追加・更新する
- 既存テストが壊れていないことを確認してからコミットする
- バグ修正時はリグレッション防止のためテストケースを追加する
- テスト関数名は `test_<対象機能>_<テスト内容>` の形式にする

## ドキュメントの追加・更新

- 公開 API の追加・変更時はヘッダーファイル内のコメントを更新する
- プロジェクト構成やビルド手順に影響する変更があれば `CLAUDE.md` を更新する
- RFC 関連のドキュメントは `docs/RFC/` に配置する

## コミットメッセージ

```
<type>: <簡潔な説明>
```

タイプ: `feat:`, `fix:`, `improve:`, `refactor:`, `docs:`, `test:`, `build:`, `chore:`

## CI

GitHub Actions（`.github/workflows/ci.yml`）: Ubuntu 24.04 + Windows (MSYS2 UCRT64) で Debug/Release ビルド & テスト、CodeQL 静的解析

## 言語

コード中のコメント・ドキュメント・コミットメッセージ・レビューコメントは日本語。
