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
- **クロスプラットフォーム対応**: Windows、Linux、macOS で動作

### 関連ドキュメント

- 📘 [USECASES.md](USECASES.md) - 具体的な使用例とトラブルシューティング
- 🗺️ [ROADMAP.md](ROADMAP.md) - 今後の開発予定と展望
- 🤝 [CONTRIBUTING.md](CONTRIBUTING.md) - 貢献方法とコーディングガイドライン
- 📄 [LICENSE.md](LICENSE.md) - ライセンス情報

## 必要な環境

- C コンパイラ (GCC, Clang, MSVC など)
- C2x 標準サポート
- make ユーティリティ

### プラットフォーム別の依存関係

- **Windows**: Winsock2 (ws2_32.lib, mswsock.lib)
- **Linux**: librt (リアルタイムライブラリ)
- **その他 UNIX 系**: 標準のソケットライブラリ

## ビルド方法

### 基本的なビルド

```bash
make
```

**Windows環境の場合:**
```powershell
make CC=gcc
```

実行ファイルは `build/` ディレクトリに生成されます：
- `build/reflector` - Reflector (パケット反射側)
- `build/sender` - Sender (パケット送信側)

### テストの実行

```bash
make test
```

**Windows環境の場合:**
```powershell
make CC=gcc test
```

### クリーンアップ

```bash
make clean
```

**Windows環境の場合:**
```powershell
make CC=gcc clean
```

## 使い方

### クイックスタート

**1. Reflector の起動（サーバー側）:**
```bash
./build/reflector
```

**2. Sender の起動（クライアント側）:**
```bash
./build/sender 127.0.0.1
```

**出力例:**
```
Seq=1, RTT=0.234 ms
Seq=2, RTT=0.256 ms
Seq=3, RTT=0.223 ms
^C
--- Statistics ---
Sent: 3, Received: 3, Timeouts: 0
Min RTT: 0.223 ms, Max RTT: 0.256 ms, Avg RTT: 0.238 ms
```

### 基本的なコマンド

```bash
# デフォルトポート (862) で起動
./build/reflector

# カスタムポート (8888) で起動
./build/reflector 8888

# リモートホストに接続
./build/sender 192.168.1.100

# カスタムポートで接続
./build/sender 192.168.1.100 8888
```

**より詳しい使用例は [USECASES.md](USECASES.md) をご覧ください。**

## プロジェクト構成

```
RFC8762/
├── Makefile              # ビルドファイル
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

### ポート番号

- **デフォルトポート**: 862/UDP（IANA登録済みSTAMPポート）
- カスタムポートの使用も可能

## トラブルシューティング

### よくある問題

**ビルドエラー: `winsock2.h: No such file or directory`**
- MinGW-w64またはMSVCを使用してください

**ビルドエラー: `undefined reference to clock_gettime`**
- Linuxでは `-lrt` オプションが必要です（Makefileに含まれています）

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
