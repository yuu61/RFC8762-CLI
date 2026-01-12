# RFC 8762 STAMP Implementation

RFC 8762 STAMP(Simple Two-way Active Measurement Protocol)のC言語実装です。
ネットワーク性能測定（遅延、遅延変動、パケットロス）を行うための軽量なプロトコルです。

## 概要

STAMPは、ネットワークの性能測定を行うための標準化されたプロトコルです。このプロジェクトでは、RFC 8762で定義されているSTAMPプロトコルのSender（送信側）とReflector（反射側）を実装しています。

このプロジェクトは、Qiitaの記事「[クリスマスの夜に「RFC8762: 双方向遅延測定プロトコル STAMP」について勉強しよう!!](https://qiita.com/Kinukui2003/items/af9e4a3dfea71cc2c152)」に触発されて作成しました。

### 主な機能

- **RTT (Round-Trip Time) 測定**: パケットの往復時間を精密に測定
- **遅延測定**: 一方向および双方向の遅延を計測
- **統計情報**: パケット送受信数、最小/最大/平均RTTを表示
- **IPv4/IPv6 デュアルスタック対応**: IPv4とIPv6の両方に対応
- **ホスト名解決**: IPアドレスだけでなくホスト名でも指定可能
- **クロスプラットフォーム対応**: Windows、Linux、macOS で動作

### 関連ドキュメント

- 📘 [USECASES.md](USECASES.md) - 具体的な使用例とトラブルシューティング
- 🗺️ [ROADMAP.md](ROADMAP.md) - 今後の開発予定と展望
- 🤝 [CONTRIBUTING.md](CONTRIBUTING.md) - 貢献方法とコーディングガイドライン
- 📄 [LICENSE.md](LICENSE.md) - ライセンス情報

## 必要な環境

- **コンパイラ**: GCC 14 以降（必須）
  - ⚠️ MSVCはサポートしていません
- **C標準**: C2x
- **ビルドツール**: CMake 3.16 以上、Ninja

### プラットフォーム別のセットアップ

#### Windows (MSYS2)

WindowsではMSYS2環境が必要です。

```bash
# 1. MSYS2をインストール: https://www.msys2.org/
# 2. MSYS2 UCRT64ターミナルを開いて以下を実行:
pacman -Syu
# 再起動後、再度UCRT64ターミナルを開いて以下を実行:
pacman -Syu

pacman -S --needed mingw-w64-ucrt-x86_64-toolchain

# 3. GCCバージョン確認（14以上であること）
gcc --version
```

```pwsh
# 4. CMakeとNinjaのインストール
winget install Kitware.CMake Ninja-build.Ninja
```

#### Linux (Debian/Ubuntu)

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
- **Linux**: librt (リアルタイムライブラリ) - CMakeが自動リンク
- **その他 UNIX 系**: 標準のソケットライブラリ

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

実行ファイルは `build/` ディレクトリに生成されます：

- `build/debug/reflector` - Reflector (デバッグ版)
- `build/debug/sender` - Sender (デバッグ版)
- `build/release/reflector` - Reflector (リリース版)
- `build/release/sender` - Sender (リリース版)

### テストの実行

```bash
ctest --preset debug
# または
ctest --preset release
```

### クリーンアップ

```bash
# 各ビルドディレクトリを削除
cmake -E rm -rf build/debug
cmake -E rm -rf build/release

# 全てのビルドを削除
cmake -E rm -rf build
```

## 使い方

### クイックスタート

**1. Reflector の起動（サーバー側）:**

```bash
./build/release/reflector
```

**2. Sender の起動（クライアント側）:**

```bash
./build/release/sender 127.0.0.1
```

**出力例:**

```bash
STAMP Sender targeting 127.0.0.1:862
Press Ctrl+C to stop and show statistics
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)  [adj_Fwd]  [adj_Bwd]
--------------------------------------------------------------------------------------------
0    0.152     0.148     0.300    0.002       0.150      0.150
1    0.145     0.155     0.300    -0.005      0.150      0.150
2    0.148     0.152     0.300    -0.002      0.150      0.150
^C
--- STAMP Statistics ---
Packets sent: 3
Packets received: 3
Packet loss: 0.00%
RTT min/avg/max = 0.300/0.300/0.300 ms
```

### 基本的なコマンド

```bash
# デフォルトポート (862) で起動（デュアルスタック）
./build/release/reflector

# カスタムポート (8888) で起動
./build/release/reflector 8888

# リモートホストに接続
./build/release/sender 192.168.1.100

# カスタムポートで接続
./build/release/sender 192.168.1.100 8888
```

### ファイアウォール自動設定（Linux/UNIX）
Reflector を root 権限で起動すると、iptables/ip6tables で UDP ポート許可ルールを自動追加・削除します。`system()` を利用するため、運用環境では内容を確認し、不要であれば非 root で起動してください。

### IPv6 での使用

```bash
# IPv6 ローカルホストに接続
./build/release/sender ::1

# IPv6 アドレスに接続
./build/release/sender 2001:db8::1

# ホスト名で接続（自動解決）
./build/release/sender example.com
```

### アドレスファミリの指定

```bash
# IPv4 を強制
./build/release/sender -4 192.168.1.100
./build/release/reflector -4

# IPv6 を強制
./build/release/sender -6 ::1
./build/release/reflector -6

# ホスト名を IPv4 で解決
./build/release/sender -4 example.com

# ホスト名を IPv6 で解決
./build/release/sender -6 example.com
```

**より詳しい使用例は [USECASES.md](USECASES.md) をご覧ください。**

## プロジェクト構成

```bash
RFC8762/
├── CMakeLists.txt        # CMake ビルド設定
├── CMakePresets.json     # CMake プリセット
├── README.md             # このファイル
├── build/                # ビルド成果物（自動生成）
├── docs/
│   └── RFC8762.txt       # RFC 8762 仕様書
├── src/
│   ├── stamp.h           # STAMPプロトコルのヘッダーファイル
│   ├── reflector.c       # Reflector実装
│   └── sender.c          # Sender実装
└── tests/
    └── test_stamp.c      # ユニットテスト
```

## 技術仕様

### STAMPパケットフォーマット

このプロジェクトは、RFC 8762で定義されている非認証モードのSTAMPパケットフォーマットを実装しています。

- **シーケンス番号**: 各パケットに一意の識別子
- **NTPタイムスタンプ**: 高精度な時刻情報（64ビット）
- **エラー推定**: タイムスタンプの精度情報

### タイムスタンプ

- NTPフォーマット（1900年1月1日からの経過時間）を使用
- 高精度タイマーを利用（Windows: QueryPerformanceCounter、UNIX: clock_gettime）

### 出力カラムの説明

| カラム | 説明 |
|--------|------|
| Seq | シーケンス番号 |
| Fwd(ms) | 往路遅延（Sender → Reflector） |
| Bwd(ms) | 復路遅延（Reflector → Sender） |
| RTT(ms) | 往復遅延（Fwd + Bwd） |
| Offset(ms) | クロックオフセット（Reflectorの時計のずれ） |
| [adj_Fwd] | オフセット補正した往路遅延（参考値） |
| [adj_Bwd] | オフセット補正した復路遅延（参考値） |

**補正値の意味**: SenderとReflectorの時計が完全に同期していない場合、Fwd/Bwdの値は非対称になります。`[adj_Fwd]`と`[adj_Bwd]`は、クロックオフセットを考慮した推定値で、理想的には対称な値になります。

### ポート番号

- **デフォルトポート**: 862/UDP（IANA登録済みSTAMPポート）
- カスタムポートの使用も可能

## トラブルシューティング

### よくある問題

**ビルドエラー: `winsock2.h: No such file or directory`**

- MSYS2環境でビルドしてください（「必要な環境」セクション参照）

**ビルドエラー: `undefined reference to clock_gettime`**

- Linuxでは `librt-dev` パッケージが必要です（CMakeが自動でリンクします）

**実行エラー: `bind: Address already in use`**

- 別のReflectorが実行中です。ポート番号を変更してください

**接続エラー: `Connection timeout`**

- Reflectorが起動しているか、ファイアウォールでUDP通信が許可されているか確認してください

**詳細なトラブルシューティングは [USECASES.md](USECASES.md) をご覧ください。**

## 参考資料

- [RFC 8762 - Simple Two-Way Active Measurement Protocol](https://www.rfc-editor.org/info/rfc8762)
- [docs/RFC8762.txt](docs/RFC8762.txt) - RFC仕様書のテキスト版

## 貢献・ライセンス

このプロジェクトはMITライセンスで公開されています。
バグ報告や機能追加の提案は、issueを作成してください。プルリクエストも歓迎します。

- 貢献方法の詳細: [CONTRIBUTING.md](CONTRIBUTING.md)
- ライセンス情報: [LICENSE.md](LICENSE.md)
- 今後の開発予定: [ROADMAP.md](ROADMAP.md)
