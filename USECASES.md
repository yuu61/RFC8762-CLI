# ユースケース

## 基本的な使用例

### ローカルホストでの測定

最も簡単な使用例です。

```bash
# ターミナル1: Reflectorを起動
./build/reflector

# ターミナル2: Senderを起動
./build/sender
```

### リモートホストでの測定

ネットワーク越しの性能測定を行います。

```bash
# サーバー側 (192.168.1.100)
./build/reflector

# クライアント側
./build/sender 192.168.1.100
```

### カスタムポートの使用

デフォルトポート862が使用できない場合：

```bash
# Reflectorをポート8888で起動
./build/reflector 8888

# Senderでポート8888に接続
./build/sender 192.168.1.100 8888
```

## 実践的なユースケース

### ネットワーク品質の監視

定期的にネットワーク遅延を測定し、品質を監視します。

```bash
# 長時間測定する場合
./build/sender 192.168.1.100 > network_log.txt
```

### VPN接続の性能評価

VPN接続前後でRTTを比較し、VPNのオーバーヘッドを測定します。

```bash
# VPN接続前
./build/sender remote.server.com

# VPN接続後
./build/sender remote.server.com
```

### データセンター間の遅延測定

複数のデータセンター間の通信遅延を測定します。

```bash
# データセンターA → データセンターB
./build/sender dc-b.example.com

# データセンターB → データセンターC
./build/sender dc-c.example.com
```

## 典型的な出力例

### 正常な測定

```
Seq=1, RTT=0.234 ms
Seq=2, RTT=0.256 ms
Seq=3, RTT=0.223 ms
Seq=4, RTT=0.245 ms
Seq=5, RTT=0.239 ms
^C
--- Statistics ---
Sent: 5, Received: 5, Timeouts: 0
Min RTT: 0.223 ms, Max RTT: 0.256 ms, Avg RTT: 0.239 ms
```

### パケットロスがある場合

```
Seq=1, RTT=0.234 ms
Seq=2, RTT=0.256 ms
Seq=3, Timeout
Seq=4, RTT=0.245 ms
Seq=5, RTT=0.239 ms
^C
--- Statistics ---
Sent: 5, Received: 4, Timeouts: 1
Min RTT: 0.234 ms, Max RTT: 0.256 ms, Avg RTT: 0.244 ms
```

### 遅延が大きい場合

```
Seq=1, RTT=125.34 ms
Seq=2, RTT=128.56 ms
Seq=3, RTT=122.23 ms
^C
--- Statistics ---
Sent: 3, Received: 3, Timeouts: 0
Min RTT: 122.23 ms, Max RTT: 128.56 ms, Avg RTT: 125.38 ms
```

## トラブルシューティングシナリオ

### シナリオ1: タイムアウトが頻発する

**症状:**
```
Seq=1, Timeout
Seq=2, Timeout
Seq=3, RTT=0.234 ms
Seq=4, Timeout
```

**考えられる原因:**
- ネットワークの輻輳
- パケットロス率が高い
- Reflectorの負荷が高い

**対処法:**
- ネットワーク経路を確認
- Reflectorのリソース使用状況を確認
- ファイアウォール設定を確認

### シナリオ2: 接続できない

**症状:**
```
Error: sendto() failed
Connection timeout
```

**考えられる原因:**
- Reflectorが起動していない
- ファイアウォールでUDPがブロックされている
- IPアドレスまたはポート番号が間違っている

**対処法:**
1. Reflectorが起動していることを確認
2. ファイアウォールでUDP 862番ポートを許可
3. IPアドレスとポート番号を再確認

### シナリオ3: ビルドエラー

**症状 (Windows):**
```
fatal error: winsock2.h: No such file or directory
```

**対処法:**
- MinGW-w64またはMSVCを使用

**症状 (Linux):**
```
undefined reference to clock_gettime
```

**対処法:**
- 古いシステムでは `librt-dev` パッケージをインストール（CMakeが自動でリンクします）

**症状:**
```
CMake Error: Could not find CMAKE_PROJECT_VERSION
```

**対処法:**
- CMake 3.16以上をインストール
