# amano-ts.sh — アマノタイムスタンプ 取得・検証ツール

アマノ株式会社のタイムスタンプサービス(e-timing)からタイムスタンプを取得し、検証するためのコマンドラインツールです。
UPKI電子証明書発行サービスでの利用を想定しています。

OpenSSL 3.x の標準検証コマンド(`openssl ts -verify`)は、本サービスのトークンに対して「ESS証明書ID不一致(`ess cert id not found`)」で失敗します。本ツールはこれを CMS 署名検証と検証済みデータからの直接照合の組み合わせで回避し、あわせて失効確認(OCSP)や nonce 照合まで一括で行います。技術的背景は同梱の「タイムスタンプ検証技術マニュアル」を参照してください。

## 動作環境

macOS または Linux。以下が必要です。

- **OpenSSL 3.x** — macOS 標準の `/usr/bin/openssl` は LibreSSL のため使えません。`brew install openssl@3` で導入してください(ツールが自動検出します)。
- **curl** — 通常はプリインストールされています。

## 導入

`amano-ts.sh` を任意の場所(例: `~/bin/`)に置き、実行権限を付けます。

```bash
chmod +x amano-ts.sh
```

初回に一度だけセットアップを実行します。セコムトラストシステムズの公式リポジトリから中間CA・ルートCA証明書を取得し、公表されている SHA-256 フィンガープリントとの一致を確認したうえで `~/.amano-ts/` に保存します。

```bash
./amano-ts.sh setup
```

フィンガープリントが一致しない場合はエラーで停止します(通信経路の問題、または CA 証明書が更新された可能性。後者の場合はリポジトリの公表値を確認のうえ、環境変数で新しい値を指定してください)。

### TSA の URL の設定

タイムスタンプの取得(`stamp`)には TSA エンドポイントの URL が必要です。この URL は契約時に通知される「タイムスタンプ利用情報」に記載されている契約者向けの情報のため、**本リポジトリには含まれていません**。同梱の `config.example` をコピーして記入してください。

```bash
mkdir -p ~/.amano-ts
cp config.example ~/.amano-ts/config
chmod 600 ~/.amano-ts/config
# ~/.amano-ts/config を編集し、TSA_URL="..." に通知された URL を記入
```

環境変数 `AMANO_TS_URL` でも指定できます(設定ファイルより優先されます)。なお、検証(`verify`・`diag`)は TSA に接続しないため、URL の設定なしで実行できます。

## 使い方

### タイムスタンプの取得

```bash
./amano-ts.sh stamp report.pdf
```

`report.pdf.tsr`(タイムスタンプ応答)と `report.pdf.tsq`(要求)が保存され、続けて検証まで自動実行されます。**この2ファイルは原本とセットで保管してください。** `.tsr` がタイムスタンプの本体です。既存の `.tsr` を上書きする場合は `--force` を付けます。

### 検証

```bash
./amano-ts.sh verify report.pdf              # report.pdf.tsr を検証
./amano-ts.sh verify report.pdf backup.tsr   # 応答ファイルを明示指定
```

出力例:

```
=== タイムスタンプ検証: report.pdf / report.pdf.tsr ===
  [OK  ] 応答ステータス — Granted
  [OK  ] 署名・証明書チェーン検証(CMS) — 発行後の改ざんなし/正規の証明書チェーン/タイムスタンプ用途
  [OK  ] 失効確認(OCSP) — good(応答署名も検証済み)
  [OK  ] 原本ハッシュ照合(sha256) — 5891B5B5...
  [OK  ] nonce 照合 — 0x8A21...

タイムスタンプ時刻: Jul  3 03:15:19 2026 GMT
判定: 検証成功
```

全項目 OK であれば「このファイルが、表示された時刻に確かに存在し、その後1ビットも変更されていない」ことが確認されたことになります。

### 診断

`openssl ts -verify` が失敗する原因(ESSCertID の不一致)を解析します。

```bash
./amano-ts.sh diag report.pdf.tsr
```

トークン内に列挙された証明書IDと、手元の証明書チェーンを突き合わせ、どのIDが一致しないかを表示します。

## 検証範囲(重要)

本ツールの verify は次を確認します: 応答ステータス(Granted)、トークン署名の完全性、署名者証明書からルートCAまでの信頼チェーン、証明書がタイムスタンプ発行用であること、署名者証明書の失効状態(OCSP)、原本ハッシュとの一致、nonce の一致(`.tsq` がある場合)。

一方、**ESS 証明書ID照合(RFC 3161 の signingCertificate 属性の照合)は実施しません**。これは本サービスのトークンが列挙する中間CA証明書IDが公開されている証明書と一致せず、照合が構造的に成功しないためです(検証者側では解消できません。詳細は技術マニュアル §7)。ESS 照合は「署名に使われた証明書が発行時に宣言されたものと同じか」の二重チェックにあたり、署名検証自体で正規の証明書によることは確認済みのため、省略による影響は限定的と考えられますが、RFC 3161 完全準拠の検証ではない点はご留意ください。

## オプション・環境変数

| オプション | 説明 |
|---|---|
| `--certs-dir DIR` | 証明書の保存先(既定: `~/.amano-ts`) |
| `--strict` | OCSP レスポンダに到達できない場合を失敗扱いにする(既定は警告+継続) |
| `--force` | stamp で既存の `.tsr` を上書き |

| 環境変数 | 説明 |
|---|---|
| `OPENSSL_BIN` | 使用する OpenSSL のパスを明示指定 |
| `AMANO_TS_URL` | TSA エンドポイント URL(設定ファイル `~/.amano-ts/config` より優先) |
| `AMANO_TS_INTER_URL` / `AMANO_TS_ROOT_URL` | 証明書のダウンロード元 |
| `AMANO_TS_INTER_FP` / `AMANO_TS_ROOT_FP` | 期待する SHA-256 フィンガープリント |
| `AMANO_TS_HOME` | `--certs-dir` と同じ(オプションが優先) |
| `AMANO_TS_HASH` | ハッシュアルゴリズム(既定: sha256) |

終了コードは 0=成功、1=検証失敗、2=環境・引数エラー です。バッチ処理での利用を想定しています。

## トラブルシューティング

**「TSA の URL が設定されていません」** — `stamp` には契約者向けの「タイムスタンプ利用情報」の URL が必要です。「TSA の URL の設定」の手順で `~/.amano-ts/config` を作成してください。

**「OpenSSL 3.x が見つかりません」** — macOS では `brew install openssl@3`。導入済みなのに検出されない場合は `OPENSSL_BIN=/opt/homebrew/opt/openssl@3/bin/openssl ./amano-ts.sh ...` のようにパスを明示してください。

**「フィンガープリントが一致しません」** — まず通信環境(社内プロキシ等)を確認。CA 証明書の世代交代の場合は、リポジトリ(中間CA: repo1.secomtrust.net/spcpp/ts/、ルートCA: repository.secomtrust.net/SC-Root3/)の公表値を確認し、`AMANO_TS_INTER_FP` 等で新しい値を指定して setup を再実行してください。

**OCSP が警告になる** — レスポンダへの接続に失敗しています。ネットワークを確認して再実行してください。失効確認を必須にしたい場合は `--strict` を使います。

**`openssl ts -verify` で直接検証したい** — 本サービスのトークンでは成功しません。理由と診断方法は `diag` サブコマンドおよび技術マニュアル §7 を参照してください。

## テスト

`test-amano-ts.sh` を `amano-ts.sh` と同じディレクトリに置いて実行すると、実サービスに接続せずローカルの使い捨てTSA(実サービスと同じ3階層構成)で回帰テストを行います。

```bash
bash test-amano-ts.sh
```

セットアップ、フィンガープリント改ざん検出、正常検証、原本改ざん検出、不正ルートCA検出、nonce 不一致検出、ESSCertID 診断、エラー処理の9項目を確認します。

## ファイル構成

- `amano-ts.sh` — 本体
- `README.md` — 本書
- `config.example` — 設定ファイルのひな形(TSA の URL を記入して `~/.amano-ts/config` に置く)
- `~/.amano-ts/config` — 実際の設定(契約者向けの URL を含むため、リポジトリにはコミットしない)
- `~/.amano-ts/tsa-intermediate.pem`, `~/.amano-ts/tsa-root.pem` — setup が保存する検証用証明書
