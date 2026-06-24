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
Usage: sender [-4|-6] [-P] [-c] [-O] [-n count] [-w sec] [-o fmt] [-i iface] [server_ip|hostname] [port]
```

| オプション | 説明 |
| -- | -- |
| `-4` | IPv4 を強制 |
| `-6` | IPv6 を強制 |
| `-P` | PTP タイムスタンプ形式を使用（Z=1） |
| `-i iface` | HW タイムスタンプ用ネットワークインターフェース（Linux のみ） |
| `-c` | PHC (PTP Hardware Clock) を使用（`-i` 必須、Linux のみ） |
| `-O` | 片方向遅延測定モード |
| `-n count` | 指定本数を送信したら停止（パーセンタイルを有効化） |
| `-w sec` | 指定秒数で停止（パーセンタイルを有効化） |
| `-o fmt` | 出力形式: `human`（既定）/ `json` / `csv` |

`-n` / `-w` のいずれも指定しない場合は `Ctrl+C` まで無制限に測定する（パーセンタイル・PDV は全サンプル保持が必要なため、有限計測時のみ算出される）。`-n` と `-w` を同時に指定した場合は先に到達した条件で停止する。

### Reflector

```
Usage: reflector [-4|-6] [-d] [-P] [-c] [-i iface] [port]
```

| オプション | 説明 |
| -- | -- |
| `-4` | IPv4 のみ |
| `-6` | IPv6 のみ |
| `-d` | デバッグ出力を有効化 |
| `-P` | PTP タイムスタンプ形式を使用（Z=1） |
| `-i iface` | HW タイムスタンプ用ネットワークインターフェース（Linux のみ） |
| `-c` | PHC (PTP Hardware Clock) を使用（`-i` 必須、Linux のみ） |

## 統計出力

測定終了時（`Ctrl+C` または `-n`/`-w` 到達）に Sender が統計サマリを出力する。標準偏差はすべて標本標準偏差（n-1）で計算する。

| 指標 | 説明 |
| -- | -- |
| RTT min/avg/max/stddev | 往復遅延の最小・平均・最大・標準偏差 |
| Clock offset min/avg/max/stddev | 推定クロックオフセット（送受信の非対称性の指標） |
| Forward/Backward min/avg/max/jitter | 片方向遅延（`-O` 時）。jitter は標本標準偏差 |
| IPDV avg/max | 連続パケット間遅延変動 \|D(i)−D(i−1)\|（RFC 3393）。ロスで seq が飛んだペアは除外 |
| p50/p95/p99 | パーセンタイル（中央値=p50）。`-n`/`-w` 指定時のみ |
| PDV (p95−min) | パケット遅延変動（RFC 5481）。`-n`/`-w` 指定時のみ |

数値計算には Welford のオンラインアルゴリズムを用い、平均 ≫ 標準偏差の場合でも桁落ちなく分散を求める。

### 機械可読出力（JSON / CSV）

`-o json` / `-o csv` で構造化出力に切り替える（毎パケット行と開始バナーは抑制され、最終サマリのみを 1 オブジェクト / 1 行で出力する）。クロックスキュー警告は全形式で `stderr` に出る。

```bash
# JSON（500本測定して 1 オブジェクトを出力）
./build/release/sender -o json -n 500 192.168.1.100 | jq .

# CSV（コメント行 + ヘッダ行 + データ 1 行）
./build/release/sender -o csv -w 10 192.168.1.100 > result.csv
```

- 全形式に `format_version`（現行 `"1.0"`）を埋め込む。遅延はミリ秒、`loss_ratio` は 0.0–1.0、タイムスタンプは ISO8601 UTC。
- 未集計の指標（例: 非 `-O` モードの `fwd_*`、サンプル未保持時の `*_p95_ms`）は **JSON では `null`、CSV では空フィールド**となる。`null`/空は「欠損」を意味する。
- 小数点はロケールに依存せず常に `.`。

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

Reflector を root 権限で起動すると、**nftables**（`inet` family・IPv4/IPv6 両対応・テーブル名 `stamp_reflector`）で UDP ポート許可ルールを自動追加します。`nft` コマンドは `fork()`+`execvp()` で直接実行し、シェルを介さないためコマンドインジェクションを防止します。

- 正常終了（Ctrl+C / SIGTERM 等）時は `atexit` でルールを自動削除します。
- SIGKILL や OOM killer による異常終了ではルールが残留するため、その場合は `nft delete table inet stamp_reflector` で手動削除してください。
- 非 root で起動した場合はファイアウォール設定をスキップします。

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

> **注意: `-c` は Sender と Reflector の両方に指定してください。**
> `-c` を使う場合、Sender と Reflector の双方で `-c -i <iface>` を指定する必要があります。片方だけ指定すると、T2 の HW RX タイムスタンプがフォールバックした際に T3（PHC）とクロックドメインが不一致になり、RTT が異常な値になります。
>
> **使用条件:**
>
> - 両方がネイティブ Linux で PHC 対応の物理 NIC を搭載していること
> - パケットが物理 NIC を経由すること（同一マシンでのテストは不可）
> - Windows / WSL / WSL2 は PHC 非対応のため、これらが含まれる構成では `-c` を使用しないこと（WSL2 は仮想 NIC 経由のため物理 NIC の PHC にアクセス不可）
>
> **推奨構成:**
>
> | 構成 | `-c` | RTT 精度 |
> | -- | -- | -- |
> | 両方 Linux + PHC 対応 NIC | 両方に `-c -i` | 最高精度 |
> | 両方 Linux + PHC 対応 NIC + 片方だけ `-c -i` | **非推奨** | 下記参照 |
> | 片方が Windows / WSL2 または PHC 非対応 | 使用しない | NTP/カーネル TS 精度 |
> | 同一マシンテスト | 使用しない | ソフトウェア TS 精度 |
>
> **片方だけ `-c -i` を指定した場合（両方 Linux + PHC 対応 NIC）:**
> RTT 計算は T1・T4（Sender 側）と T2・T3（Reflector 側）のペアが各々同一クロックドメインであれば正しくなります。Reflector のみ `-c -i` の場合、T3 は PHC から読み取られ、T2 も HW RX タイムスタンプ（PHC ドメイン）が取得できれば T2・T3 が一致し RTT は正確です。しかし NIC が任意の UDP パケットに HW RX タイムスタンプを付与しない場合、T2 が `CLOCK_REALTIME` にフォールバックし T3（PHC）との不一致で RTT が不正値になります。HW RX の動作は NIC・ドライバ依存であり保証できないため、両方に指定するか両方外すことを推奨します。

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
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)
```

| カラム | 説明 | 計算式 |
| -- | -- | -- |
| Seq | シーケンス番号 | - |
| Fwd(ms) | 往路遅延 | T2 - T1 |
| Bwd(ms) | 復路遅延 | T4 - T3 |
| RTT(ms) | 往復遅延 | Fwd + Bwd |
| Offset(ms) | クロックオフセット | ((T2-T1) + (T3-T4)) / 2 |

**タイムスタンプの意味:**

- T1: Sender がパケットを送信した時刻
- T2: Reflector がパケットを受信した時刻
- T3: Reflector がパケットを返送した時刻
- T4: Sender がパケットを受信した時刻

**Offset（クロックオフセット）について:**

- 正の値: Reflector の時計が Sender より進んでいる
- 負の値: Reflector の時計が Sender より遅れている
- 0 に近い値: 両者の時計がほぼ同期している

**片方向遅延（Fwd/Bwd）の正確性について:**
Fwd/Bwd が真の片方向遅延を表すのは、Sender と Reflector のクロックが同期している場合に限られます。クロックがずれていると、Offset がそのまま Fwd に `+Offset`、Bwd に `-Offset` の系統誤差として乗ります（RTT は Offset に依存せず常に正しい）。

非同期クロックでは、単一往復の 4 タイムスタンプから「経路の非対称性」と「クロックオフセット」を分離して真の片方向遅延を復元することは原理的にできません（未知数 3 に対し独立な式が 2 本しかない劣決定問題）。`Offset` を使って Fwd/Bwd を「補正」しても、経路対称（Fwd = Bwd）を暗黙に仮定することと等価で、補正後の値は常に `RTT/2` に潰れるため追加情報を持ちません（このため補正列は提供していません）。

真の片方向遅延が必要な場合は、両端のクロックを同期させてください。PTP タイムスタンプ形式（`-P`）と PHC ハードウェアタイムスタンプを使い、`ptp4l`/`phc2sys` 等で両端の PHC を共通基準に同期させれば、生の Fwd/Bwd がそのまま真の片方向遅延になります。その場合 `Offset` 列は残留同期誤差の診断に使えます。

### 典型的な出力例

#### 正常な測定（ローカルホスト）

```
STAMP Sender targeting 127.0.0.1:862
Press Ctrl+C to stop and show statistics
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)
-------------------------------------------------
0    0.152     0.148     0.300    0.002
1    0.155     0.145     0.300    0.005
2    0.148     0.152     0.300    -0.002
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
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)
-------------------------------------------------
0    0.523     0.489     1.012    0.017
1    0.510     0.502     1.012    0.004
Timeout waiting for response
3    0.515     0.497     1.012    0.009
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
Seq  Fwd(ms)   Bwd(ms)   RTT(ms)  Offset(ms)
-------------------------------------------------
0    15.523    -14.489   1.034    15.006
1    15.510    -14.502   1.008    15.006
```

この例では、Reflector の時計が Sender より約 15ms 進んでいます。RTT は正しい一方、生の Fwd/Bwd には Offset 分の系統誤差が乗っており（Fwd に +15ms、Bwd に -15ms）、片方向遅延としては信頼できません。正確な片方向遅延を得るには両端のクロック同期が必要です（上記「片方向遅延（Fwd/Bwd）の正確性について」を参照）。

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

**PHC 使用時に Backward delay が異常に大きい（数百ms〜数秒）**

T3（PHC）と他のタイムスタンプ（`CLOCK_REALTIME` フォールバック）のクロックドメインが不一致になっています。以下のいずれかに該当します:

- 同一マシン上で Sender と Reflector を実行している（パケットが物理 NIC を経由しない）
- 片方だけ `-c` を指定している（両方に必要）
- NIC が任意の UDP パケットに HW RX タイムスタンプを付与しない（PTP フレーム専用の NIC 等）
- Windows を含む構成で `-c` を使用している（Windows は PHC 非対応）

対処法: `-c` を両方から外してテストしてください
