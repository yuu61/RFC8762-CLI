# 使い方ガイド

## クイックスタート

```bash
# ターミナル1: Reflectorを起動
./build/release/reflector

# ターミナル2: Senderを起動
./build/release/sender 127.0.0.1
```

## コマンドラインオプション

### Sender

```
Usage: sender [-4|-6] [-P] [-c] [-O] [-i iface] [server_ip|hostname] [port]
```

| オプション | 説明 |
| --- | --- |
| `-4` | IPv4 を強制 |
| `-6` | IPv6 を強制 |
| `-P` | PTP タイムスタンプ形式を使用（Z=1） |
| `-i iface` | HW タイムスタンプ用ネットワークインターフェース（Linux のみ） |
| `-c` | PHC (PTP Hardware Clock) を使用（`-i` 必須、Linux のみ） |
| `-O` | 片方向遅延測定モード |

### Reflector

```
Usage: reflector [-4|-6] [-d] [-P] [-c] [-i iface] [port]
```

| オプション | 説明 |
| --- | --- |
| `-4` | IPv4 のみ |
| `-6` | IPv6 のみ |
| `-d` | デバッグ出力を有効化 |
| `-P` | PTP タイムスタンプ形式を使用（Z=1） |
| `-i iface` | HW タイムスタンプ用ネットワークインターフェース（Linux のみ） |
| `-c` | PHC (PTP Hardware Clock) を使用（`-i` 必須、Linux のみ） |

## 基本的な使用例

### ローカルホストでの測定

```bash
# ターミナル1: Reflectorを起動
./build/release/reflector

# ターミナル2: Senderを起動
./build/release/sender 127.0.0.1
```

### リモートホストでの測定

```bash
# サーバー側 (192.168.1.100)
./build/release/reflector

# クライアント側
./build/release/sender 192.168.1.100
```

### カスタムポートの使用

デフォルトポート 862 が使用できない場合:

```bash
# Reflectorをポート8888で起動
./build/release/reflector 8888

# Senderでポート8888に接続
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

# リンクローカルアドレス（ゾーン識別子のサポートはOS実装に依存）
./build/release/sender fe80::1%eth0
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

## 高精度タイムスタンプ

### ハードウェアタイムスタンプ (Linux)

NIC のハードウェアタイムスタンプを使って、カーネルのオーバーヘッドを排除した精密な測定を行います。

```bash
# HW タイムスタンプ付きで Reflector を起動
sudo ./build/release/reflector -i eth0

# HW タイムスタンプ付きで Sender を起動
sudo ./build/release/sender -i eth0 192.168.1.100
```

NIC が HW タイムスタンプに対応していない場合、自動的にソフトウェアタイムスタンプにフォールバックします。

### PHC (PTP Hardware Clock) クロック連携 (Linux)

NIC の PTP ハードウェアクロック (`/dev/ptpN`) から直接時刻を取得します。PTP で同期された環境での高精度測定に最適です。

```bash
# PHC クロックを使用（-i が必須）
sudo ./build/release/sender -c -i eth0 192.168.1.100
sudo ./build/release/reflector -c -i eth0
```

PHC クロックが検出できない場合はシステムクロックにフォールバックし、警告メッセージが表示されます:

```
Warning: No PHC available on eth0; using system clock
```

### PTP タイムスタンプ形式

NTP 形式（32bit 秒 + 32bit 小数部）の代わりに PTP truncated format（32bit 秒 + 32bit ナノ秒）を使用します。Sender と Reflector の両方で同じ形式を指定してください。

```bash
./build/release/sender -P 192.168.1.100
./build/release/reflector -P
```

PTP 形式は Error Estimate の Z-bit（bit 14）で自動判定されるため、Sender が `-P` を指定すれば Reflector 側で自動的に認識されます。

### 片方向遅延測定モード

Forward delay（往路）と Backward delay（復路）の個別統計を表示します。クロック同期の状態や非対称なネットワーク経路の分析に有用です。

```bash
./build/release/sender -O 192.168.1.100
```

### オプションの組み合わせ

複数のオプションは組み合わせて使用できます:

```bash
# HW タイムスタンプ + PTP 形式 + PHC クロック + 片方向遅延
sudo ./build/release/sender -P -c -O -i eth0 192.168.1.100

# IPv6 + PTP 形式
./build/release/sender -6 -P ::1
```

## 実践的なユースケース

### ネットワーク品質の監視

```bash
# 長時間測定する場合
./build/release/sender 192.168.1.100 > network_log.txt
```

### VPN 接続の性能評価

VPN 接続前後で RTT を比較し、VPN のオーバーヘッドを測定します。

```bash
# VPN接続前
./build/release/sender remote.server.com

# VPN接続後
./build/release/sender remote.server.com
```

### データセンター間の遅延測定

```bash
# データセンターA → データセンターB
./build/release/sender dc-b.example.com

# データセンターB → データセンターC
./build/release/sender dc-c.example.com
```

## 出力の見方

### 出力カラム

```
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)  [adj_Fwd]  [adj_Bwd]
```

| カラム | 説明 | 計算式 |
| --- | --- | --- |
| Seq | シーケンス番号 | - |
| Fwd(ms) | 往路遅延 | T2 - T1 |
| Bwd(ms) | 復路遅延 | T4 - T3 |
| RTT(ms) | 往復遅延 | Fwd + Bwd |
| Offset(ms) | クロックオフセット | ((T2-T1) + (T3-T4)) / 2 |
| [adj_Fwd] | 補正往路遅延 | Fwd - Offset |
| [adj_Bwd] | 補正復路遅延 | Bwd + Offset |

**タイムスタンプの意味:**

- T1: Sender がパケットを送信した時刻
- T2: Reflector がパケットを受信した時刻
- T3: Reflector がパケットを返送した時刻
- T4: Sender がパケットを受信した時刻

**Offset（クロックオフセット）について:**

- 正の値: Reflector の時計が Sender より進んでいる
- 負の値: Reflector の時計が Sender より遅れている
- 0 に近い値: 両者の時計がほぼ同期している

**補正値 [adj_Fwd]/[adj_Bwd] について:**
クロック差を考慮した推定値です。両システムの時計が同期していない場合、生の Fwd/Bwd は非対称になりますが、補正値は理想的には対称（同じ値）になります。

### 典型的な出力例

#### 正常な測定（ローカルホスト）

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

#### パケットロスがある場合

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

#### クロックがずれている場合

Sender と Reflector の時計が同期していない場合、Offset が大きくなります:

```
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)  [adj_Fwd]  [adj_Bwd]
--------------------------------------------------------------------------------------------
0    15.523    -14.489   1.034    15.006      0.517      0.517
1    15.510    -14.502   1.008    15.006      0.504      0.504
```

この例では、Reflector の時計が Sender より約 15ms 進んでいます。生の Fwd/Bwd は非対称ですが、補正値は対称になっています。

負の遅延が検出された場合、警告メッセージが表示されます:

```
Warning: Negative delay detected (clock skew?)
```

#### 片方向遅延統計

`-O` オプション使用時は追加の統計が表示されます:

```
--- One-way Delay Statistics ---
Forward  min/avg/max/jitter = 0.510/0.516/0.523/0.005 ms
Backward min/avg/max/jitter = 0.489/0.496/0.502/0.005 ms
Warning: Clock may not be synchronized (asymmetry > 10 ms threshold)
```

## トラブルシューティング

### ビルドエラー

**`winsock2.h: No such file or directory`**

- MSYS2 環境でビルドしてください（[ビルドガイド](BUILD.md) 参照）

**`undefined reference to clock_gettime`**

- 古いシステムでは `librt-dev` パッケージをインストール（CMake が自動でリンクします）

**`CMake Error: Could not find CMAKE_PROJECT_VERSION`**

- CMake 3.25 以上をインストール

### 実行時エラー

**`bind: Address already in use`**

- 別の Reflector が実行中です。ポート番号を変更してください

**`Connection timeout` / `sendto() failed`**

- Reflector が起動しているか確認
- ファイアウォールで UDP 通信（デフォルト 862 番ポート）が許可されているか確認
- IP アドレスとポート番号を再確認

### タイムアウトが頻発する

**考えられる原因:**

- ネットワークの輻輳
- パケットロス率が高い
- Reflector の負荷が高い

**対処法:**

- ネットワーク経路を確認
- Reflector のリソース使用状況を確認
- ファイアウォール設定を確認

### IPv6 関連

**`getaddrinfo failed`（IPv6 接続時）**

1. IPv6 が有効か確認: `ip -6 addr show`（Linux）/ `ipconfig`（Windows）
2. `-4` オプションで IPv4 を強制使用
3. ファイアウォールで UDP 862 番ポートの IPv6 を許可

**デュアルスタックで IPv4 クライアントから接続できない**

- Reflector が `-6` で起動されている可能性があります。オプションなし（デュアルスタック）または `-4` で起動してください

**ホスト名の解決に失敗**

1. `nslookup` や `dig` でホスト名を確認
2. IP アドレスを直接指定
3. `-4` / `-6` を外して自動選択に任せる

### ハードウェアタイムスタンプ関連

**`SIOCSHWTSTAMP failed; using software timestamps`**

- NIC が HW タイムスタンプに対応していない可能性があります。`ethtool -T eth0` で確認
- `sudo` で実行してください
- 物理 NIC を指定してください（veth, docker0 等の仮想 NIC は非対応）

**`Failed to open /dev/ptp0; using system clock`**

1. デバイスファイルの存在を確認: `ls /dev/ptp*`
2. root 権限で実行
3. `-i` オプションで正しいインターフェースを指定しているか確認
