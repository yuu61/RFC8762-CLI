# RFC 8762 STAMP Implementation

RFC 8762 STAMP(Simple Two-way Active Measurement Protocol)の C 言語実装です。
ネットワーク性能測定（遅延、遅延変動、パケットロス）を行うための軽量なプロトコルです。

## 概要

STAMP は、ネットワークの性能測定を行うための標準化されたプロトコルです。このプロジェクトでは、RFC 8762 で定義されている STAMP プロトコルの Sender（送信側）と Reflector（反射側）を実装しています。

このプロジェクトは、Qiita の記事「[クリスマスの夜に「RFC8762: 双方向遅延測定プロトコル STAMP」について勉強しよう!!](https://qiita.com/Kinukui2003/items/af9e4a3dfea71cc2c152)」に触発されて作成しました。

### 主な機能

- **RTT (Round-Trip Time) 測定**: パケットの往復時間を精密に測定
- **片方向遅延測定**: Forward / Backward delay の個別統計（`-O` オプション）
- **統計情報**: パケット送受信数、最小/最大/平均 RTT、ジッターを表示
- **IPv4/IPv6 デュアルスタック対応**: IPv4 と IPv6 の両方に対応
- **ホスト名解決**: IP アドレスだけでなくホスト名でも指定可能
- **PTP タイムスタンプ**: NTP 形式に加え、PTP truncated format に対応（`-P` オプション）
- **ハードウェアタイムスタンプ**: Linux NIC の HW タイムスタンプに対応（`-i` オプション）
- **PHC クロック連携**: NIC の PTP Hardware Clock から直接時刻取得（`-c` オプション）
- **クロスプラットフォーム対応**: Windows、Linux、macOS で動作

## クイックスタート

### ビルド

```bash
cmake --preset release
cmake --build --preset release
```

### 実行

```bash
# ターミナル1: Reflectorを起動
./build/release/reflector

# ターミナル2: Senderを起動
./build/release/sender 127.0.0.1
```

**出力例:**

```
STAMP Sender targeting 127.0.0.1:862
Press Ctrl+C to stop and show statistics
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)
-------------------------------------------------
0    0.152     0.148     0.300    0.002
1    0.145     0.155     0.300    -0.005
2    0.148     0.152     0.300    -0.002
^C
--- STAMP Statistics ---
Packets sent: 3
Packets received: 3
Packet loss: 0.00%
RTT min/avg/max = 0.300/0.300/0.300 ms
```

## ドキュメント

- [docs/BUILD.md](docs/BUILD.md) - 環境構築・ビルド手順・ビルドオプション
- [docs/USAGE.md](docs/USAGE.md) - CLI リファレンス・使用例・トラブルシューティング
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - 技術仕様・ヘッダー構成・タイムスタンプ体系
- [CONTRIBUTING.md](CONTRIBUTING.md) - 貢献方法とコーディングガイドライン
- [ROADMAP.md](ROADMAP.md) - 今後の開発予定と展望
- [LICENSE.md](docs/LICENSE.md) - ライセンス情報

## 参考資料

- [RFC 8762 - Simple Two-Way Active Measurement Protocol](https://www.rfc-editor.org/info/rfc8762)
- [docs/RFC8762.txt](docs/RFC8762.txt) - RFC 仕様書のテキスト版

## 貢献・ライセンス

このプロジェクトは MIT ライセンスで公開されています。
バグ報告や機能追加の提案は、issue を作成してください。プルリクエストも歓迎します。

- 貢献方法の詳細: [CONTRIBUTING.md](CONTRIBUTING.md)
- ライセンス情報: [LICENSE.md](docs/LICENSE.md)
- 今後の開発予定: [ROADMAP.md](ROADMAP.md)
