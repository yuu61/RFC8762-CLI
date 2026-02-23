# ビルドガイド

## 必要な環境

- **コンパイラ**: GCC 14 以降（必須）
  - MSVC はサポートしていません
- **C 標準**: GNU C17（C17 + GNU 拡張）
  - 分岐予測ヒント（`__builtin_expect`）、関数属性（`__attribute__`）等の GNU 拡張を使用
- **ビルドツール**: CMake 3.25 以上、Ninja

## プラットフォーム別のセットアップ

### Windows (MSYS2)

Windows では MSYS2 環境が必要です。

```bash
# 1. MSYS2をインストール: https://www.msys2.org/
# 2. MSYS2 UCRT64ターミナルを開いて以下を実行:
pacman -Syu
# 再起動後、再度UCRT64ターミナルを開いて以下を実行:
pacman -Syu

pacman -S --needed mingw-w64-ucrt-x86_64-toolchain
```

```powershell
# 3. CMakeとNinjaのインストール
winget install Kitware.CMake Ninja-build.Ninja
```

```bash
# 4. GCCバージョン確認（14以上であること）
gcc --version
```

### Linux (Debian/Ubuntu)

```bash
# GCC 14のインストール（Ubuntu 24.04以降、またはPPA使用）
sudo apt update
sudo apt install gcc-14 cmake ninja-build

# デフォルトコンパイラに設定
# 既にインストールされている任意のバージョンを選択してください
# sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 13
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 14
```

### ランタイム依存関係

- **Windows**: Winsock2 (ws2_32.lib, mswsock.lib) - システム標準
- **Linux**: librt (リアルタイムライブラリ), libm (数学ライブラリ) - CMake が自動リンク
- **macOS**: libm (数学ライブラリ) - CMake が自動リンク

## ビルド方法

### Debug ビルド

```bash
cmake --preset debug
cmake --build --preset debug
```

### Release ビルド

```bash
cmake --preset release
cmake --build --preset release
```

実行ファイルは `build/` ディレクトリに生成されます:

- `build/debug/reflector` - Reflector (デバッグ版)
- `build/debug/sender` - Sender (デバッグ版)
- `build/release/reflector` - Reflector (リリース版)
- `build/release/sender` - Sender (リリース版)

## ビルドオプション

CMake のオプションで追加機能を制御できます。`cmake --preset <preset> -D<OPTION>=ON` の形式で指定します。

| オプション | デフォルト | 説明 |
| --- | --- | --- |
| `PORTABLE_BUILD` | OFF | 配布用ポータブルバイナリのビルド（`-march=native` を無効化） |
| `ENABLE_LTO` | ON | リンク時最適化（ビルド時間とメモリ使用量が増加） |
| `ENABLE_PGO_GENERATE` | OFF | PGO プロファイルデータ生成（ステップ 1） |
| `ENABLE_PGO_USE` | OFF | PGO プロファイルデータを使用した最適化（ステップ 2） |
| `ENABLE_GRAPHITE` | OFF | Graphite 多面体ループ最適化（実験的、ISL 付き GCC が必要） |
| `ENABLE_REFLECTOR_DEBUG_LOG` | OFF | Reflector の詳細デバッグログを有効化 |

### PGO (Profile-Guided Optimization) の使い方

```bash
# ステップ1: プロファイルデータ生成
cmake --preset release -DENABLE_PGO_GENERATE=ON
cmake --build --preset release
./build/release/sender 127.0.0.1  # ワークロードを実行

# ステップ2: プロファイルデータを使用した最適化ビルド
cmake --preset release -DENABLE_PGO_USE=ON
cmake --build --preset release
```

> **注意**: プロファイル生成と使用で同じコンパイラバージョンを使用してください。

## テストの実行

```bash
ctest --preset debug
# または
ctest --preset release
```

## 静的解析ツールのインストール

### Linux (Debian/Ubuntu)

```bash
sudo apt install clang-format clang-tidy cppcheck
```

### Windows (MSYS2 UCRT64)

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-clang-tools-extra mingw-w64-ucrt-x86_64-cppcheck
```

### macOS

```bash
brew install llvm cppcheck
```

> **注意**: macOS では Homebrew の llvm に clang-format と clang-tidy が含まれます。パスを通すか `$(brew --prefix llvm)/bin/clang-format` のようにフルパスで実行してください。

## 静的解析

### clang-format（コード整形）

```bash
# 整形チェック（差分表示のみ）
clang-format --dry-run -Werror src/*.c src/*.h

# 自動整形
clang-format -i src/*.c src/*.h
```

### clang-tidy（命名規則・品質チェック）

`compile_commands.json` が必要です（CMake が自動生成）。

```bash
# 単一ファイルの検査
clang-tidy -p build/debug src/sender.c

# 全ソースの検査
clang-tidy -p build/debug src/*c src/*h tests/*c

# 自動修正付き
clang-tidy -p build/debug --fix src/sender.c
```

### cppcheck（静的解析）

```bash
cppcheck --enable=all --std=c17 --suppressions-list=.cppcheck-suppressions --library=posix --error-exitcode=1 --inline-suppr --check-level=exhaustive --force -I src/ src/ tests/
```

設定ファイルの詳細は [ARCHITECTURE.md](ARCHITECTURE.md) を参照。

## クリーンアップ

```bash
# 各ビルドディレクトリを削除
cmake -E rm -rf build/debug
cmake -E rm -rf build/release

# 全てのビルドを削除
cmake -E rm -rf build
```
