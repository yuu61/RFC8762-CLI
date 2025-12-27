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

### 出力カラムの説明

```
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)  [adj_Fwd]  [adj_Bwd]
```

| カラム | 説明 | 計算式 |
|--------|------|--------|
| Seq | シーケンス番号 | - |
| Fwd(ms) | 往路遅延 | T2 - T1 |
| Bwd(ms) | 復路遅延 | T4 - T3 |
| RTT(ms) | 往復遅延 | Fwd + Bwd |
| Offset(ms) | クロックオフセット | ((T2-T1) + (T3-T4)) / 2 |
| [adj_Fwd] | 補正往路遅延 | Fwd - Offset |
| [adj_Bwd] | 補正復路遅延 | Bwd + Offset |

**タイムスタンプの意味:**
- T1: Senderがパケットを送信した時刻
- T2: Reflectorがパケットを受信した時刻
- T3: Reflectorがパケットを返送した時刻
- T4: Senderがパケットを受信した時刻

**Offset（クロックオフセット）について:**
- 正の値: Reflectorの時計がSenderより進んでいる
- 負の値: Reflectorの時計がSenderより遅れている
- 0に近い値: 両者の時計がほぼ同期している

**補正値 [adj_Fwd]/[adj_Bwd] について:**
クロック差を考慮した推定値です。両システムの時計が同期していない場合、生のFwd/Bwdは非対称になりますが、補正値は理想的には対称（同じ値）になります。

### 正常な測定（ローカルホスト）

```
STAMP Sender targeting 127.0.0.1:862
Press Ctrl+C to stop and show statistics
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)  [adj_Fwd]  [adj_Bwd]
--------------------------------------------------------------------------------------------
0    0.152     0.148     0.300    0.002       0.150      0.150
1    0.155     0.145     0.300    0.005       0.150      0.150
2    0.148     0.152     0.300    -0.002      0.150      0.150
^C
--- STAMP Statistics ---
Packets sent: 3
Packets received: 3
Packet loss: 0.00%
RTT min/avg/max = 0.300/0.300/0.300 ms
```

### パケットロスがある場合

```
STAMP Sender targeting 192.168.1.100:862
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)  [adj_Fwd]  [adj_Bwd]
--------------------------------------------------------------------------------------------
0    0.523     0.489     1.012    0.017       0.506      0.506
1    0.510     0.502     1.012    0.004       0.506      0.506
Timeout waiting for response
3    0.515     0.497     1.012    0.009       0.506      0.506
^C
--- STAMP Statistics ---
Packets sent: 4
Packets received: 3
Packet loss: 25.00%
Timeouts: 1
RTT min/avg/max = 1.012/1.012/1.012 ms
```

### クロックがずれている場合

SenderとReflectorの時計が同期していない場合、Offsetが大きくなります：

```
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)  [adj_Fwd]  [adj_Bwd]
--------------------------------------------------------------------------------------------
0    15.523    -14.489   1.034    15.006      0.517      0.517
1    15.510    -14.502   1.008    15.006      0.504      0.504
```

この例では、Reflectorの時計がSenderより約15ms進んでいます。生のFwd/Bwdは非対称ですが、補正値は対称になっています。

**注意:** 負の遅延が検出された場合、警告メッセージが表示されます：
```
Warning: Negative delay detected (clock skew?)
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
