# CTI システム 利用ガイド

## 概要

このシステムは2つのインターフェースを持ちます。

    JSONアPI (port 8888)   プログラムやスクリプトからの利用向け。全レスポンスはJSON。
    Web UI  (port 8889)   ブラウザから使う人間向けUI。APIに裏でクエリしHTMLで表示。

---

## 起動方法

### APIサーバー（JSON）

    cd /home/kei/llm_vault/hermes_qwen_cti
    .venv/bin/uvicorn api:app --host 0.0.0.0 --port 8888

### Web UI

    cd /home/kei/llm_vault/hermes_qwen_cti
    .venv/bin/python3 ui.py

### OS起動時に自動起動（systemd）

    systemctl --user daemon-reload
    systemctl --user enable cti-api cti-ui
    systemctl --user start cti-api cti-ui

    # ログアウト後も動かす場合
    loginctl enable-linger kei

    # 状態確認
    systemctl --user status cti-api
    systemctl --user status cti-ui

    # ログ確認
    journalctl --user -u cti-api -f
    journalctl --user -u cti-ui -f

---

## 認証（オプション）

.env に CTI_API_KEY を設定した場合、すべてのAPIリクエストにヘッダーが必要です。

    X-API-Key: your_key_here

設定していない場合は認証不要。Web UIは内部でAPIを呼ぶため、UIにアクセスするだけなら
このヘッダーを意識する必要はありません。

---

## データストアの関係

    全フィードアイテム
           │
           ▼
      processed_items  ── 見たURLの記録（dedup用。内容なし）
           │
       LLMトリアージ
           │
      価値なし → 捨てる
           │
      価値あり
           ├──→ findings    ── 26時間バッファ（daily報告用）
           └──→ RAG(Chroma) ── 永久蓄積（歴史的文脈用）

    /findings エンドポイント → findingsテーブルを検索
    /search エンドポイント   → RAG(ChromaDB)を検索

---

## Web UI の使い方 (port 8889)

ブラウザで http://localhost:8889 を開くと4つのページが使えます。

### ダッシュボード（/）

開いた直後に表示されるトップページ。

    統計カード
      直近26h Findings件数 / 累計Findings件数 / RAGドキュメント数 / 処理済みURL数

    脅威度内訳（全期間）
      critical / high / medium / low それぞれの件数をバッジで表示

    直近26時間のFindings（上位10件）
      脅威度バッジ・タイトル・ソース・公開日時・LLMサマリー・影響製品タグのカード一覧

### Findings検索（/findings）

SQLiteのfindingsテーブルをフォームで検索するページ。

フォームの各項目:

    過去N時間          何時間前まで遡るか。デフォルト26時間。9999で全期間。

    脅威度チェックボックス  critical / high / medium / low を任意に組み合わせて選択。

    キーワード          タイトルとLLMサマリーの両方を検索。
                      例: weblogic、actively exploited

    CVE ID（部分一致）   CVE-2024-21182 でその1件、CVE-2024 で2024年の全CVEにマッチ。

    ソース（部分一致）   BleepingComputer、threatfox など。大文字小文字を区別しない。

    公開日 From / To   記事の公開日（取り込み日ではない）で絞り込む。

    表示件数           1ページに表示する件数。20 / 50 / 100 / 200から選択。

検索結果はカード形式で表示されます。各カードには以下が含まれます。

    脅威度バッジ / CVE ID / ソース名 / 公開日時
    記事タイトル（クリックで元記事を新タブで開く）
    LLMサマリー
    影響製品タグ（最大6件）

件数が多い場合はページ下部に「前へ / 次へ」ボタンが表示されます。

### RAG検索（/search）

ChromaDB全履歴（5,000件超）をブラウザから検索するページ。

モード切替ボタンで2つのモードを選択します。

    ベクトル検索モード（デフォルト）
      自然言語または技術用語で検索。キーワードが一致しなくても概念的に近いものを返す。
      例: "iot botnet command and control" でMiraiやBotenaGoが見つかる。
      例: "supply chain attack npm package"

    CVEモード
      CVE IDを完全一致で検索。ベクトル検索を使わず、そのCVEに関する
      全記録を確実に取得する。
      例: CVE-2024-21182

共通フィルター:

    threshold（ベクトル検索のみ）
      距離の上限値。低いほど厳しく絞られる。
      0.0〜0.5 ほぼ同一 / 0.5〜0.8 強い類似 / 0.8〜1.2 関連トピック / 1.2以上 弱い関連
      空欄にすると上限なし（件数上限まで全部返す）。

    日付 From / To    ドキュメントのdateメタデータで絞り込む。

    ソース（部分一致）  mandiant、kaspersky など。

    脅威度（完全一致）  1種類のみ指定可。

    件数上限          返す最大件数。デフォルト10、最大200。

検索結果には距離スコアバー（青いバー。長いほど類似度高）が表示されます。
キーワードが文字列として一致した場合は「★キーワード一致」ラベルが付きます。
CVEモードでは「✓ CVE完全一致」ラベルが付きます。

### ソース（/sources）

どのフィードソースから何件のFindingsが来ているかを確認するページ。

    過去N時間フォームで期間を変えて「更新」ボタンを押す。
    ソース名 / 件数 / 割合バーの3列テーブルで表示。

---

## APIエンドポイント一覧 (port 8888)

    GET /health           死活確認
    GET /stats            全DBの統計
    GET /findings         findingsテーブルの検索
    GET /findings/sources ソース別件数
    GET /search           RAGベクトル検索 / CVE完全一致検索

インタラクティブドキュメント（ブラウザで全パラメーターを試せる）:
    http://localhost:8888/docs

---

## GET /health

パラメーターなし。

    curl http://localhost:8888/health

レスポンス例:
    {"status": "ok", "time": "2026-06-03 00:30 JST"}

---

## GET /stats

全データストアの統計を返します。パラメーターなし。

    curl http://localhost:8888/stats

主なレスポンスフィールド:

    as_of                    現在時刻（JST）
    findings.total           累計findings件数
    findings.last_26h        直近26時間のfindings件数（daily報告対象）
    findings.by_severity     脅威度別件数 {critical:N, high:N, medium:N, low:N}
    rag.total_documents      ChromaDBのドキュメント総数
    processed_items.total    処理済みURL総数

---

## GET /findings

SQLiteのfindingsテーブルを検索します。LLMが「高価値」と判定したアイテムのみが格納されています。
結果は脅威度順（critical先頭）、同一脅威度内は新着順で返されます。

すべてのパラメーターはオプションで、自由に組み合わせ可能です。

### パラメーター

    hours
      型: 整数  デフォルト: 26
      何時間前まで遡るか。9999を指定すると全期間。
      例: hours=48

    severity
      型: 文字列（カンマ区切り）
      脅威度でフィルター。値: critical, high, medium, low
      例: severity=critical,high

    source
      型: 文字列（部分一致・大文字小文字無視）
      フィードソース名でフィルター。
      例: source=BleepingComputer
      例: source=threatfox

    cve
      型: 文字列（部分一致）
      CVE IDでフィルター。部分一致なのでCVE-2024で2024年のCVE全件にマッチ。
      例: cve=CVE-2024-21182
      例: cve=CVE-2024

    q
      型: 文字列（キーワード検索）
      タイトルとサマリーの両方を検索。
      例: q=weblogic
      例: q=actively exploited

    start_date
      型: 文字列 YYYY-MM-DD
      指定日以降に公開された記事のみ返す。記事の公開日を使用。
      例: start_date=2026-06-01

    end_date
      型: 文字列 YYYY-MM-DD
      指定日以前に公開された記事のみ返す。
      例: end_date=2026-06-03

    limit
      型: 整数  デフォルト: 100  最大: 1000
      返す件数の上限。
      例: limit=20

    offset
      型: 整数  デフォルト: 0
      ページネーション用。スキップする件数。
      例: offset=20（2ページ目、limit=20の場合）

### レスポンス構造

    {
      "total": 42,        フィルター後の総件数（ページネーション前）
      "offset": 0,
      "limit": 100,
      "results": [
        {
          "title":             記事タイトル
          "source":            フィード名
          "url":               元記事URL
          "published":         公開日時
          "cve":               CVE ID（なければ空文字）
          "severity":          critical / high / medium / low
          "affected_products": 影響製品のリスト
          "summary":           LLM生成の技術サマリー（1〜3文）
        },
        ...
      ]
    }

### 使用例

    # 直近48時間のcritical/high
    curl "http://localhost:8888/findings?severity=critical,high&hours=48"

    # WebLogic関連を全期間で
    curl "http://localhost:8888/findings?q=weblogic&hours=9999"

    # 特定CVEを探す
    curl "http://localhost:8888/findings?cve=CVE-2024-21182"

    # ThreatFoxからのhigh以上を全期間で
    curl "http://localhost:8888/findings?source=threatfox&severity=high&hours=9999"

    # ページネーション（1ページ20件、2ページ目）
    curl "http://localhost:8888/findings?limit=20&offset=20"

    # 日付範囲 + 脅威度
    curl "http://localhost:8888/findings?severity=critical&start_date=2026-06-01&end_date=2026-06-03"

---

## GET /findings/sources

findingsテーブルに存在するフィードソースとその件数を返します。

### パラメーター

    hours
      型: 整数  デフォルト: 26
      /findingsと同じ。何時間前まで遡るか。

### 使用例

    curl "http://localhost:8888/findings/sources"
    curl "http://localhost:8888/findings/sources?hours=168"

### レスポンス例

    {
      "sources": [
        {"source": "ThreatFox", "count": 24},
        {"source": "URLhaus", "count": 18},
        {"source": "BleepingComputer", "count": 8},
        ...
      ]
    }

---

## GET /search

ChromaDB RAG知識ベースを検索します。findingsテーブルと違い、過去に取り込まれた
すべてのドキュメント（5,000件超）が対象です。時間範囲の制限はデフォルトなし。

q か cve のどちらか一方が必須です。

### モード説明

    ベクトル検索モード（q を指定）
      自然言語のクエリをベクトル化して類似ドキュメントを探します。
      キーワードが一致しなくても概念的に近いものを見つけられます。

    CVEモード（cve を指定）
      ベクトル検索を一切使わず、メタデータのcveフィールドと完全一致するものだけを返します。
      特定のCVEに関するすべての記録を確実に取得したいときに使います。
      注意: 完全一致のみ。部分一致が必要なら /findings?cve= を使ってください。

### パラメーター

    q
      型: 文字列
      ベクトル検索クエリ（自然言語可）。cveと同時指定不可。
      例: q=botnet command and control infrastructure
      例: q=supply chain attack npm package

    cve
      型: 文字列
      CVEモード。完全なCVE IDを指定。qと同時指定不可。
      例: cve=CVE-2024-21182

    top
      型: 整数  デフォルト: 10  最大: 200
      返す件数の上限。内部では top×4 件を取得してからフィルタリングします。

    threshold
      型: 小数  範囲: 0.0〜2.0  デフォルト: なし（制限なし）
      ベクトル検索モードのみ有効。この距離以下の結果のみ返します。

      目安:
        0.0〜0.5   ほぼ同一（重複に近い）
        0.5〜0.8   強い類似（明確に同じトピック）
        0.8〜1.2   関連トピック（広めのマッチ）
        1.2以上    弱い関連（ノイズが多い）

      例: threshold=0.8 で高信頼度の結果のみに絞る

    start_date
      型: 文字列 YYYY-MM-DD または ISO datetime
      メタデータのdateフィールドがこの日以降のものだけ返す。
      例: start_date=2026-05-01

    end_date
      型: 文字列 YYYY-MM-DD または ISO datetime
      メタデータのdateフィールドがこの日以前のものだけ返す。
      例: end_date=2026-06-03

    source
      型: 文字列（部分一致・大文字小文字無視）
      例: source=mandiant

    severity
      型: 文字列（完全一致）
      注意: /findingsと違いカンマ区切り不可。1種類のみ指定。
      値: critical / high / medium / low
      例: severity=critical

### レスポンス構造

    {
      "mode": "semantic",     または "cve"
      "query": "weblogic",
      "total_returned": 10,
      "threshold": 0.8,       指定なしはnull
      "results": [
        {
          "distance":        類似度スコア（低いほど類似。CVEモードは常に0.0）
          "keyword_match":   クエリ文字列がテキストに含まれていた場合true
          "exact_cve_match": CVEモード使用時はtrue
          "metadata": {
            "source":   フィード名
            "url":      元記事URL
            "cve":      CVE ID
            "severity": 脅威度
            "date":     記事日付
          }
          "text": "記事タイトル\n\nLLMサマリーテキスト..."
        },
        ...
      ]
    }

### 使用例

    # Miraiボットネット関連をベクトル検索
    curl "http://localhost:8888/search?q=mirai+botnet+iot&top=10"

    # 高信頼度に絞る
    curl "http://localhost:8888/search?q=mirai+botnet+iot&top=10&threshold=0.8"

    # 特定CVEの全記録を取得（CVEモード）
    curl "http://localhost:8888/search?cve=CVE-2024-21182"

    # 過去1ヶ月のランサムウェア関連
    curl "http://localhost:8888/search?q=ransomware+encryption&start_date=2026-05-01&top=20"

    # Mandiantのcritical情報のみ
    curl "http://localhost:8888/search?q=apt+campaign&source=mandiant&severity=critical"

---

## /findings と /search の使い分け

    /findingsを使う場面:
      - 直近の新しい情報を確認したい（デフォルト26時間）
      - CVEの部分一致で絞りたい（例: 2024年のCVE全件）
      - ページネーションして全件処理したい
      - affected_productsなど構造化データが必要

    /searchを使う場面:
      - 過去の全履歴から探したい
      - キーワードではなく概念・文脈で検索したい
      - 特定CVEに関する全記録を完全に取得したい（CVEモード）
      - 「これと似た話題」を探したい

---

## 環境変数

.env に設定することで動作を変更できます。

    CTI_API_KEY      APIキー認証を有効にする。未設定なら認証なし。
    CTI_API_BASE     Web UIが参照するAPIのURL。デフォルト: http://localhost:8888
    CTI_UI_PORT      Web UIのポート番号。デフォルト: 8889
