#!/usr/bin/env bash
# desc: アマノタイムスタンプの取得・検証を行う
#
# amano-ts.sh — アマノタイムスタンプサービス 取得・検証ツール
#
# 「タイムスタンプ検証技術マニュアル (OpenSSL 3.x 対応版)」の手順を自動化する。
# OpenSSL 3.x の ts -verify が ESS 照合で失敗する問題を、CMS 検証 + TSTInfo
# 直接照合で回避する(詳細は README.md および技術マニュアル参照)。
#
# 使い方: amano-ts.sh help
#
set -euo pipefail

VERSION="1.0.0"

# ---------------------------------------------------------------------------
# 設定(環境変数で上書き可能)
# ---------------------------------------------------------------------------
# TSA エンドポイント URL — 契約者に通知される「タイムスタンプ利用情報」のため
# 既定値を持たない。環境変数 AMANO_TS_URL、または設定ファイル
# ($CERTS_DIR/config)の TSA_URL= で指定する(config.example 参照)。
TSA_URL="${AMANO_TS_URL:-}"

# 中間CA (SECOM TimeStamping CA3) / ルートCA (Security Communication RootCA3)
INTER_URL="${AMANO_TS_INTER_URL:-https://repo1.secomtrust.net/spcpp/ts/ca3/ca3-der.cer}"
ROOT_URL="${AMANO_TS_ROOT_URL:-https://repository.secomtrust.net/SC-Root3/SCRoot3ca.cer}"

# SHA-256 フィンガープリント(SECOM リポジトリ公表値・2026年7月時点)
INTER_FP="${AMANO_TS_INTER_FP:-0E984339724A267C2A3DC4FCC8D020B3B4BA329A0AD7E390CFBF76E88823E11B}"
ROOT_FP="${AMANO_TS_ROOT_FP:-24A55C2AB051442D0617766541239A4AD032D7C55175AA34FFDE2FBC4F5C5294}"

CERTS_DIR="${AMANO_TS_HOME:-$HOME/.amano-ts}"
HASH_ALG="${AMANO_TS_HASH:-sha256}"
STRICT=0
FORCE=0

# ---------------------------------------------------------------------------
# 共通処理
# ---------------------------------------------------------------------------
WORK=""
cleanup() { if [ -n "$WORK" ]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT
WORK="$(mktemp -d "${TMPDIR:-/tmp}/amano-ts.XXXXXX")"

die()  { printf 'エラー: %s\n' "$*" >&2; exit 2; }
info() { printf '%s\n' "$*"; }
warn() { printf '警告: %s\n' "$*" >&2; }

# 検証結果の集計
NG=0
WARNED=0
report() { # report <OK|NG|WARN|SKIP> <項目> [詳細]
    local st="$1" label="$2" detail="${3:-}"
    case "$st" in
        NG)   NG=$((NG + 1)) ;;
        WARN) WARNED=$((WARNED + 1)) ;;
    esac
    if [ -n "$detail" ]; then
        printf '  [%-4s] %s — %s\n' "$st" "$label" "$detail"
    else
        printf '  [%-4s] %s\n' "$st" "$label"
    fi
}

upper() { tr 'a-f' 'A-F'; }

# ---------------------------------------------------------------------------
# 設定ファイルの読み込み($CERTS_DIR/config)
# ---------------------------------------------------------------------------
load_config() {
    local cfg="$CERTS_DIR/config"
    [ -f "$cfg" ] || return 0
    # shellcheck disable=SC1090
    . "$cfg"
    # 環境変数の指定を設定ファイルより優先する
    TSA_URL="${AMANO_TS_URL:-$TSA_URL}"
}

require_tsa_url() {
    [ -n "$TSA_URL" ] || die "TSA の URL が設定されていません。
       契約時に通知された「タイムスタンプ利用情報」の URL を、
       設定ファイル $CERTS_DIR/config(同梱の config.example 参照)
       または環境変数 AMANO_TS_URL で指定してください。"
}

# ---------------------------------------------------------------------------
# OpenSSL 3.x の検出(macOS 標準の LibreSSL は不可)
# ---------------------------------------------------------------------------
OSSL=""
find_openssl() {
    local cand v
    for cand in "${OPENSSL_BIN:-}" \
                openssl \
                /opt/homebrew/opt/openssl@3/bin/openssl \
                /usr/local/opt/openssl@3/bin/openssl \
                /opt/homebrew/bin/openssl \
                /usr/local/bin/openssl; do
        [ -n "$cand" ] || continue
        command -v "$cand" >/dev/null 2>&1 || continue
        v="$("$cand" version 2>/dev/null)" || continue
        case "$v" in
            OpenSSL\ 3.*) OSSL="$cand"; return 0 ;;
        esac
    done
    return 1
}

require_tools() {
    find_openssl || die "OpenSSL 3.x が見つかりません。macOS では 'brew install openssl@3' で導入し、
       必要なら環境変数 OPENSSL_BIN でパスを指定してください。
       (/usr/bin/openssl は LibreSSL のため使用できません)"
    command -v curl >/dev/null 2>&1 || die "curl が見つかりません。"
}

# ---------------------------------------------------------------------------
# setup: 証明書の取得・フィンガープリント照合・保存
# ---------------------------------------------------------------------------
fp_sha256() { # fp_sha256 <DERファイル>
    "$OSSL" x509 -inform DER -in "$1" -noout -fingerprint -sha256 2>/dev/null \
        | sed -e 's/^.*=//' -e 's/://g' | upper
}

fetch_and_pin() { # fetch_and_pin <URL> <期待FP> <保存先PEM> <名称>
    local url="$1" want="$2" dest="$3" name="$4" der="$WORK/dl.der" got
    info "取得中: $name"
    curl -fsSL "$url" -o "$der" || die "$name のダウンロードに失敗しました: $url"
    got="$(fp_sha256 "$der")" || die "$name を証明書として読み込めません(ダウンロード内容を確認してください)"
    want="$(printf '%s' "$want" | upper)"
    if [ "$got" != "$want" ]; then
        die "$name のフィンガープリントが一致しません。
       期待値: $want
       実際値: $got
       ダウンロード経路の改ざん、または証明書の更新の可能性があります。
       リポジトリの公表値を確認してください。"
    fi
    "$OSSL" x509 -inform DER -in "$der" -out "$dest"
    info "  フィンガープリント一致: $got"
}

cmd_setup() {
    require_tools
    mkdir -p "$CERTS_DIR"
    chmod 700 "$CERTS_DIR"
    fetch_and_pin "$INTER_URL" "$INTER_FP" "$CERTS_DIR/tsa-intermediate.pem" "中間CA証明書"
    fetch_and_pin "$ROOT_URL"  "$ROOT_FP"  "$CERTS_DIR/tsa-root.pem"        "ルートCA証明書"
    info "セットアップ完了: 証明書を $CERTS_DIR に保存しました。"
}

ensure_certs() {
    if [ ! -f "$CERTS_DIR/tsa-intermediate.pem" ] || [ ! -f "$CERTS_DIR/tsa-root.pem" ]; then
        info "証明書が未設定のため、初回セットアップを実行します。"
        cmd_setup
    fi
}

# ---------------------------------------------------------------------------
# stamp: タイムスタンプの取得(取得後に自動検証)
# ---------------------------------------------------------------------------
cmd_stamp() {
    local file="${1:-}" tsq tsr http_err
    [ -n "$file" ] || die "対象ファイルを指定してください: amano-ts.sh stamp <file>"
    [ -f "$file" ] || die "ファイルが見つかりません: $file"
    require_tools
    require_tsa_url
    ensure_certs
    tsq="$file.tsq"
    tsr="$file.tsr"
    if [ -e "$tsr" ] && [ "$FORCE" -ne 1 ]; then
        die "$tsr が既に存在します。上書きする場合は --force を付けてください。"
    fi

    info "タイムスタンプ要求(TSQ)を作成しています..."
    "$OSSL" ts -query -data "$file" "-$HASH_ALG" -cert -out "$tsq" 2>/dev/null

    info "TSAに送信しています: $TSA_URL"
    if ! http_err="$(curl -fsS -H "Content-Type: application/timestamp-query" \
            --data-binary @"$tsq" "$TSA_URL" -o "$tsr" 2>&1)"; then
        rm -f "$tsr"
        die "TSAへの接続に失敗しました: $http_err"
    fi

    info "タイムスタンプ応答を $tsr に保存しました。続けて検証します。"
    echo
    do_verify "$file" "$tsr" "$tsq"
}

# ---------------------------------------------------------------------------
# verify: 検証本体
# ---------------------------------------------------------------------------
split_embedded_certs() { # トークン埋め込み証明書を $WORK/embcert_N.pem に分割。個数を echo
    "$OSSL" pkcs7 -in "$WORK/token.p7s" -inform DER -print_certs 2>/dev/null \
        > "$WORK/embedded.pem"
    awk -v dir="$WORK" '
        /-----BEGIN CERTIFICATE-----/ { n++; f=1 }
        f { print >> (dir "/embcert_" n ".pem") }
        /-----END CERTIFICATE-----/ { f=0 }
        END { print n+0 }
    ' "$WORK/embedded.pem"
}

cert_hash() { # cert_hash <ハッシュアルゴリズム> <証明書PEM>(DER 全体のハッシュを大文字16進で echo)
    "$OSSL" x509 -in "$2" -outform DER | "$OSSL" dgst "-$1" -r | cut -d' ' -f1 | upper
}

# signingCertificate(V1)/signingCertificateV2 属性に列挙された証明書IDを
# 出現順に「<V1|V2> <ハッシュアルゴリズム> <ハッシュ値> <属性内の順番>」の形式で
# 出力する。V1 と V2 が併記されている場合は属性ごとに順番を1から数える。
# V1 は SHA-1 固定。V2 は certHash の直前・1段深い位置の OID を hashAlgorithm
# とし、省略時は SHA-256(RFC 5035)。
extract_ess_ids() { # extract_ess_ids <トークン(DER)>
    "$OSSL" asn1parse -inform DER -in "$1" 2>/dev/null | awk '
        { match($0, /d=[0-9]+/); d = substr($0, RSTART+2, RLENGTH-2) + 0 }
        /:id-smime-aa-signingCertificateV2/ { on=2; dep=d; k=0; obj=""; next }
        /:id-smime-aa-signingCertificate$/  { on=1; dep=d; k=0; obj=""; next }
        on && d <= dep && /prim: *OBJECT/   { on=0 }
        on && /prim: *OBJECT/ {
            obj=$0; sub(/.*OBJECT *:/, "", obj); sub(/ *$/, "", obj); objd=d; next
        }
        on && /OCTET STRING/ && /HEX DUMP/  {
            sub(/.*HEX DUMP\]:/, "")
            alg = (on==1 ? "sha1" : "sha256")
            if (on==2 && obj != "" && objd == d + 1) alg = obj
            print (on==1 ? "V1" : "V2"), alg, toupper($0), ++k
            obj=""
        }
    '
}

valid_ess_alg() {
    case "$1" in sha1|sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512) return 0 ;; esac
    return 1
}

# ESS 照合(署名者証明書のみ): RFC 2634 §5.4 / RFC 5035 により、
# signingCertificate(V2) の1件目は署名検証に使った証明書でなければならない。
# V1 と V2 が併記されていれば両方の1件目を照合する。
# 2件目以降(中間CA等)は本サービスでは公開証明書と一致しないため照合しない。
check_ess() { # check_ess <署名者証明書PEM>
    local signer="$1" kind alg hash k ok="" rest=0
    extract_ess_ids "$WORK/token.p7s" > "$WORK/essids.txt"
    if [ ! -s "$WORK/essids.txt" ]; then
        report NG "ESS 署名者証明書ID照合" "signingCertificate 属性がありません(RFC 3161 の必須属性)"
        return 0
    fi
    while read -r kind alg hash k; do
        if [ "$k" -ne 1 ]; then rest=$((rest + 1)); continue; fi
        if ! valid_ess_alg "$alg"; then
            report NG "ESS 署名者証明書ID照合" "$kind: 未対応のハッシュアルゴリズム: $alg"
            return 0
        fi
        if [ "$(cert_hash "$alg" "$signer")" != "$hash" ]; then
            report NG "ESS 署名者証明書ID照合" "$kind: 署名者証明書が signingCertificate の1件目と一致しません(証明書差し替えの疑い)"
            return 0
        fi
        ok="${ok:+$ok, }$kind/$alg"
    done < "$WORK/essids.txt"
    if [ "$rest" -gt 0 ]; then
        report OK "ESS 署名者証明書ID照合" "$ok 一致(2件目以降の $rest 件は照合対象外)"
    else
        report OK "ESS 署名者証明書ID照合" "$ok 一致"
    fi
}

check_ocsp() { # check_ocsp <署名者証明書PEM>
    local signer="$1" url out
    url="$("$OSSL" x509 -in "$signer" -noout -ocsp_uri 2>/dev/null)" || url=""
    if [ -z "$url" ]; then
        report SKIP "失効確認(OCSP)" "証明書に OCSP URL の記載なし"
        return 0
    fi
    out="$("$OSSL" ocsp -issuer "$CERTS_DIR/tsa-intermediate.pem" -cert "$signer" \
            -url "$url" -CAfile "$CERTS_DIR/tsa-root.pem" 2>&1)" || true
    if printf '%s' "$out" | grep -q ": revoked"; then
        report NG "失効確認(OCSP)" "証明書は失効しています(タイムスタンプを信頼してはならない)"
    elif printf '%s' "$out" | grep -q "Response verify OK" \
      && printf '%s' "$out" | grep -q ": good"; then
        report OK "失効確認(OCSP)" "good(応答署名も検証済み)"
    elif printf '%s' "$out" | grep -q ": good"; then
        report WARN "失効確認(OCSP)" "状態は good だが応答署名を検証できず"
    else
        if [ "$STRICT" -eq 1 ]; then
            report NG "失効確認(OCSP)" "レスポンダに到達できず(--strict 指定のため失敗扱い)"
        else
            report WARN "失効確認(OCSP)" "レスポンダに到達できず(ネットワークを確認)"
        fi
    fi
}

do_verify() { # do_verify <原本ファイル> <TSRファイル> [TSQファイル]
    local file="$1" tsr="$2" tsq="${3:-}"
    local reply_txt="$WORK/reply.txt" cms_err ncert alg imprint calc
    local qnonce rnonce gentime

    [ -f "$file" ] || die "原本ファイルが見つかりません: $file"
    [ -f "$tsr" ]  || die "タイムスタンプ応答が見つかりません: $tsr"
    require_tools
    ensure_certs
    NG=0; WARNED=0

    info "=== タイムスタンプ検証: $file / $tsr ==="

    # --- (1) 応答ステータス ---
    if ! "$OSSL" ts -reply -in "$tsr" -text > "$reply_txt" 2>/dev/null; then
        die "$tsr をタイムスタンプ応答として読み込めません。"
    fi
    if grep -q "Status: Granted" "$reply_txt"; then
        report OK "応答ステータス" "Granted"
    else
        report NG "応答ステータス" "$(grep "Status:" "$reply_txt" | head -1 | sed 's/^ *//')"
    fi

    # --- トークンと証明書の抽出 ---
    "$OSSL" ts -reply -in "$tsr" -token_out -out "$WORK/token.p7s" 2>/dev/null
    ncert="$(split_embedded_certs)"
    if [ "$ncert" -lt 1 ]; then
        report NG "署名者証明書の抽出" "トークンに証明書が含まれていません(-cert なしの応答?)"
        echo; info "判定: 検証失敗"; return 1
    fi

    # --- (2) CMS 署名・証明書パス検証 ---
    # 注: OpenSSL 3.0〜3.4 では -certfile がチェーン構築に使われないため、
    # フィンガープリント照合済みのルートCA+中間CAを連結して -CAfile に渡す
    # (全 OpenSSL 3.x で動作する方式)。
    cat "$CERTS_DIR/tsa-root.pem" "$CERTS_DIR/tsa-intermediate.pem" > "$WORK/trust.pem"
    if cms_err="$("$OSSL" cms -verify -inform DER -in "$WORK/token.p7s" \
            -CAfile "$WORK/trust.pem" \
            -purpose timestampsign \
            -signer "$WORK/signer.pem" \
            -out "$WORK/tstinfo.der" 2>&1)"; then
        report OK "署名・証明書チェーン検証(CMS)" "発行後の改ざんなし/正規の証明書チェーン/タイムスタンプ用途"
    else
        report NG "署名・証明書チェーン検証(CMS)" \
            "$(printf '%s' "$cms_err" | grep -v '^CMS Verification' | head -1)"
        echo; info "判定: 検証失敗(署名検証エラーのため以降の照合は省略)"; return 1
    fi

    # --- (3) ESS 署名者証明書ID照合 ---
    # 署名者証明書は同梱順に依存せず、CMS 検証で実際に使われたものを用いる
    check_ess "$WORK/signer.pem"

    # --- (4) OCSP 失効確認 ---
    check_ocsp "$WORK/signer.pem"

    # --- (5) 原本ハッシュ照合(検証済み TSTInfo と比較) ---
    alg="$("$OSSL" asn1parse -inform DER -in "$WORK/tstinfo.der" 2>/dev/null \
            | awk -F: '/prim: *OBJECT/ { print $4 }' | sed -n 2p)"
    case "$alg" in
        sha256|sha384|sha512|sha1) : ;;
        *) alg="$HASH_ALG" ;;
    esac
    imprint="$("$OSSL" asn1parse -inform DER -in "$WORK/tstinfo.der" 2>/dev/null \
            | awk '/OCTET STRING/ { sub(/.*HEX DUMP\]:/, ""); print; exit }' | upper)"
    calc="$("$OSSL" dgst "-$alg" -r "$file" | cut -d' ' -f1 | upper)"
    if [ -n "$imprint" ] && [ "$imprint" = "$calc" ]; then
        report OK "原本ハッシュ照合($alg)" "$calc"
    else
        report NG "原本ハッシュ照合($alg)" "タイムスタンプは この原本に対するものではありません"
    fi

    # --- (6) nonce 照合(TSQ がある場合のみ) ---
    if [ -n "$tsq" ] && [ -f "$tsq" ]; then
        qnonce="$("$OSSL" ts -query -in "$tsq" -text 2>/dev/null \
                | awk '/^Nonce:/ { print $2 }')"
        rnonce="$(awk '/^Nonce:/ { print $2 }' "$reply_txt")"
        if [ -z "$qnonce" ]; then
            report SKIP "nonce 照合" "要求に nonce が含まれていません"
        elif [ "$qnonce" = "$rnonce" ]; then
            report OK "nonce 照合" "$qnonce"
        else
            report NG "nonce 照合" "要求($qnonce)と応答($rnonce)が不一致"
        fi
    else
        report SKIP "nonce 照合" "TSQ ファイルなし(アーカイブ検証では省略可)"
    fi

    # --- genTime 表示 ---
    gentime="$(awk -F': ' '/^Time stamp:/ { print $2 }' "$reply_txt")"
    echo
    info "タイムスタンプ時刻: ${gentime:-（取得できず）}"

    if [ "$NG" -gt 0 ]; then
        info "判定: ★検証失敗★($NG 項目が不合格)"
        return 1
    elif [ "$WARNED" -gt 0 ]; then
        info "判定: 検証成功(ただし警告 $WARNED 件 — 内容を確認してください)"
    else
        info "判定: 検証成功"
    fi
    info "(注: ESS の2件目以降(中間CA等)の照合は実施していません。詳細は README の「検証範囲」参照)"
    return 0
}

cmd_verify() {
    local file="${1:-}" tsr="${2:-}" tsq=""
    [ -n "$file" ] || die "使い方: amano-ts.sh verify <file> [<file>.tsr]"
    [ -n "$tsr" ] || tsr="$file.tsr"
    if [ -f "$file.tsq" ]; then tsq="$file.tsq"; fi
    do_verify "$file" "$tsr" "$tsq" || exit 1
}

# ---------------------------------------------------------------------------
# diag: ESSCertID 診断(ts -verify が失敗する原因の特定)
# ---------------------------------------------------------------------------
cmd_diag() {
    local tsr="${1:-}" ncert i f found subj kind alg hash idx mismatch=0 signer_ng=0
    [ -n "$tsr" ] || die "使い方: amano-ts.sh diag <file>.tsr"
    [ -f "$tsr" ] || die "ファイルが見つかりません: $tsr"
    require_tools
    ensure_certs

    "$OSSL" ts -reply -in "$tsr" -token_out -out "$WORK/token.p7s" 2>/dev/null \
        || die "$tsr をタイムスタンプ応答として読み込めません。"
    ncert="$(split_embedded_certs)"

    extract_ess_ids "$WORK/token.p7s" > "$WORK/essids.txt"
    if [ ! -s "$WORK/essids.txt" ]; then
        info "signingCertificate 属性が見つかりません(RFC 3161 の必須属性が欠落)。"
        return 0
    fi

    # 署名者証明書: 同梱順に依存せず、署名を検証できた証明書を取り出す
    # (診断用のため証明書パスは検証しない)
    if ! "$OSSL" cms -verify -noverify -inform DER -in "$WORK/token.p7s" \
            -signer "$WORK/signer.pem" -out /dev/null >/dev/null 2>&1; then
        rm -f "$WORK/signer.pem"
    fi

    info "=== ESSCertID 診断: $tsr ==="
    info "signingCertificate 属性に列挙された証明書ID:"
    while read -r kind alg hash idx; do
        if ! valid_ess_alg "$alg"; then
            mismatch=$((mismatch + 1))
            [ "$idx" -eq 1 ] && signer_ng=1
            info "  [不一致] $kind/$alg $hash"
            info "           → 未対応のハッシュアルゴリズムのため照合できません"
            continue
        fi
        if [ "$idx" -eq 1 ]; then
            # 各属性の1件目: 署名者証明書と一致しなければならない(RFC 2634 §5.4 / RFC 5035)
            if [ ! -f "$WORK/signer.pem" ]; then
                mismatch=$((mismatch + 1)); signer_ng=1
                info "  [不明]   $kind/$alg $hash"
                info "           → トークンの署名を検証できず、署名者証明書を特定できません"
            elif [ "$(cert_hash "$alg" "$WORK/signer.pem")" = "$hash" ]; then
                subj="$("$OSSL" x509 -in "$WORK/signer.pem" -noout -subject | sed 's/^subject=//')"
                info "  [一致]   $kind/$alg $hash"
                info "           → 署名者証明書 ($subj)"
            else
                mismatch=$((mismatch + 1)); signer_ng=1
                info "  [不一致] $kind/$alg $hash"
                info "           → 署名者証明書と一致しません(1件目は署名者証明書でなければならない)"
            fi
            continue
        fi
        # 2件目以降: フィンガープリント照合済みの手元の証明書とだけ照合する。
        # トークン同梱の証明書は未確認のため、一致しても「一致」とはみなさない。
        found=""
        for f in "$CERTS_DIR/tsa-intermediate.pem" "$CERTS_DIR/tsa-root.pem"; do
            if [ "$(cert_hash "$alg" "$f")" = "$hash" ]; then
                found="手元の $(basename "$f" .pem) ($("$OSSL" x509 -in "$f" -noout -subject | sed 's/^subject=//'))"
                break
            fi
        done
        if [ -n "$found" ]; then
            info "  [一致]   $kind/$alg $hash"
            info "           → $found"
            continue
        fi
        mismatch=$((mismatch + 1))
        info "  [不一致] $kind/$alg $hash"
        i=1
        while [ "$i" -le "$ncert" ]; do
            f="$WORK/embcert_$i.pem"
            if [ "$(cert_hash "$alg" "$f")" = "$hash" ]; then
                found="$("$OSSL" x509 -in "$f" -noout -subject -serial -enddate | tr '\n' ' ')"
                break
            fi
            i=$((i + 1))
        done
        if [ -n "$found" ]; then
            info "           → 手元の公開証明書とは不一致。トークン同梱の証明書$i とのみ一致"
            info "             ($found)"
            info "             公開版とは別の版(旧版・再発行版など)の証明書を指している可能性があります"
        else
            info "           → 手元のどの証明書とも一致しません"
        fi
    done < "$WORK/essids.txt"

    echo
    if [ "$signer_ng" -eq 1 ] && [ ! -f "$WORK/signer.pem" ]; then
        info "トークンの署名を検証できません(破損または改ざんの可能性)。本ツールの verify でも"
        info "検証失敗となります。"
    elif [ "$signer_ng" -eq 1 ]; then
        info "署名者証明書のIDが一致しません。RFC 3161 の必須要件を満たさないトークンであり、"
        info "本ツールの verify でも検証失敗となります。"
    elif [ "$mismatch" -gt 0 ]; then
        info "不一致の証明書IDが $mismatch 件あります。これが openssl ts -verify が"
        info "「ess cert id not found」で失敗する原因です(OpenSSL 3.x は列挙された"
        info "全IDが検証に使う証明書チェーン内に見つかることを要求します)。"
        info "署名者証明書のIDは一致しているため、本ツールの verify で検証できます。"
    else
        info "全ての証明書IDが手元の証明書と一致しています。ts -verify が失敗する場合は別の原因です。"
    fi
}

# ---------------------------------------------------------------------------
# usage / main
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
amano-ts.sh v$VERSION — アマノタイムスタンプ 取得・検証ツール

使い方:
  amano-ts.sh [オプション] setup
      証明書(中間CA・ルートCA)を公式リポジトリから取得し、
      フィンガープリント照合のうえ $CERTS_DIR に保存する。

  amano-ts.sh [オプション] stamp <file> [--force]
      <file> のタイムスタンプを取得し <file>.tsr / <file>.tsq に保存、
      続けて検証まで実行する。--force で既存 .tsr を上書き。

  amano-ts.sh [オプション] verify <file> [<tsr>]
      <file> とタイムスタンプ応答(省略時 <file>.tsr)を検証する。
      <file>.tsq があれば nonce も照合する。

  amano-ts.sh [オプション] diag <tsr>
      ESSCertID を解析し、ts -verify が失敗する原因を診断する。

オプション:
  --certs-dir DIR   証明書の保存先(既定: ~/.amano-ts)
  --strict          OCSP に到達できない場合を失敗扱いにする
  --force           stamp で既存の .tsr を上書きする

設定ファイル:
  stamp には TSA の URL(契約時に通知される「タイムスタンプ利用情報」)が
  必要です。$CERTS_DIR/config に TSA_URL="..." を記述するか(同梱の
  config.example 参照)、環境変数 AMANO_TS_URL で指定してください。

終了コード: 0=成功 / 1=検証失敗 / 2=環境・引数エラー
EOF
}

main() {
    local args cmd
    args=""
    cmd=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --certs-dir) [ $# -ge 2 ] || die "--certs-dir にはディレクトリを指定してください"
                         CERTS_DIR="$2"; shift 2 ;;
            --strict)    STRICT=1; shift ;;
            --force)     FORCE=1; shift ;;
            -h|--help|help) usage; exit 0 ;;
            -V|--version|version) echo "amano-ts.sh v$VERSION"; exit 0 ;;
            -*)          die "不明なオプション: $1(help で使い方を表示)" ;;
            *)  if [ -z "$cmd" ]; then cmd="$1"; else args="$args
$1"; fi; shift ;;
        esac
    done
    [ -n "$cmd" ] || { usage; exit 2; }
    load_config

    # 位置引数を復元(改行区切り → $1 $2 ...)
    set --
    if [ -n "$args" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then set -- "$@" "$line"; fi
        done <<EOF
$args
EOF
    fi

    case "$cmd" in
        setup)  cmd_setup ;;
        stamp)  cmd_stamp "$@" ;;
        verify) cmd_verify "$@" ;;
        diag)   cmd_diag "$@" ;;
        *)      die "不明なサブコマンド: $cmd(help で使い方を表示)" ;;
    esac
}

main "$@"
