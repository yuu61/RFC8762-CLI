# ネイティブ Git Hooks セットアップ ガイド

このドキュメントでは、**pre-commit フレームワークを使わず**、ネイティブな Git Hooks だけでコミット前チェックを実行する方法を説明します。

## セットアップ

### 方法 1: Git設定で hooks フォルダを指定（推奨）

```bash
# プロジェクトルートで実行
git config core.hooksPath .githooks
```

このコマンドで `.githooks` フォルダ内のスクリプトが自動的に Git hooks として認識されます。

### 方法 2: 手動で `.git/hooks` にコピー

```bash
# Windows (PowerShell)
Copy-Item .githooks/pre-commit .git/hooks/pre-commit

# Linux/macOS
cp .githooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## チェック内容

| 項目 | チェック内容 |
|------|-----------|
| マージコンフリクト | コンフリクト残骸(`<<<<<<<`など)の検出 |
| 末尾の空白 | 自動削除 |
| ファイル末行 | 改行がない場合は自動追加 |
| エンコーディング | UTF-8 以外は エラー |
| 改行コード | CRLF を LF に自動変換 |
| インデント | C ファイルはスペース、Markdown はタブ (警告) |

## 使用方法

### 通常のコミット

セットアップ後は、通常通りコミットするだけで自動的にチェックが実行されます：

```bash
git add <files>
git commit -m "commit message"
```

### チェック結果

#### ✅ すべてのチェックに合格

```bash
=== Pre-commit Hook ===

Checking for merge conflicts... OK
Removing trailing whitespace... OK
Checking final newline... OK
Checking file encoding (UTF-8)... OK
Checking line endings (LF)... OK
Checking indentation (.editorconfig)... OK

=== Check Complete ===

✓ All checks passed!
```

#### ⚠️ チェックが引っかかった場合（自動修正)

```bash
=== Pre-commit Hook ===

Checking for merge conflicts... OK
Removing trailing whitespace... FIXED
  Modified: src/sender.c
Checking final newline... OK
...
```

ファイルが自動修正されている場合は、修正内容を確認して再度コミットしてください：

```bash
git diff src/sender.c
git add src/sender.c
git commit -m "commit message"
```

#### ❌ チェックに失敗（エラー）

エラーが発生した場合（例：UTF-8 以外のエンコーディング）：

```bash
Checking file encoding (UTF-8)... FAILED
  UTF-8 以外のエンコーディングが見つかりました：
    - src/data.txt (utf-16)
```

ファイルを修正して再度コミットしてください。

## 手動でチェックを実行

セットアップ後、手動でチェックを実行したい場合：

```bash
# bash/sh で実行
./.githooks/pre-commit

# PowerShell で実行
bash ./.githooks/pre-commit
```

## チェックをスキップする（非推奨）

やむを得ない場合のみ：

```bash
git commit --no-verify -m "commit message"
```

## トラブルシューティング

### Windows で hooks が実行されない

Git for Windows は `core.hooksPath` の `.githooks` を正しく認識しない場合があります。この場合は「方法 2」を使用してください：

```powershell
Copy-Item .githooks/pre-commit .git/hooks/pre-commit -Force
```

### Permission denied エラー

Linux/macOS で以下のエラーが出た場合：

```bash
Permission denied: .git/hooks/pre-commit
```

実行権限を付与してください：

```bash
chmod +x .git/hooks/pre-commit
chmod +x .githooks/pre-commit
```

### DOS2Unix が見つからない

CRLF→LF 変換で `dos2unix` コマンドが見つからない場合、スクリプトが自動的に `sed` で処理します。特に対応は不要です。

### Bash が見つからない

Windows 上で bash がない場合、Git Bash をインストールするか、WSL を使用してください。

## .editorconfig について

`.editorconfig` に定義されているルール：

```properties
# 基本ルール（全ファイル）
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

# Markdown
[*.md]
indent_style = tab

# Makefile
[Makefile]
indent_style = tab
```

pre-commit hook は、主に自動修正可能な項目（末尾空白、改行、改行コード）を処理します。インデント規則の詳細は IDE/エディタの EditorConfig 対応機能に委ねます。

## 参考リンク

- [Git Hooks Documentation](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [EditorConfig](https://editorconfig.org/)
