# **AWS Security Hub MCP Server 開発指示書**

## **プロジェクトの目的**

AWS Security HubのFindings（検出結果）を柔軟に検索・抽出し、それらのステータスを更新することに特化した Model Context Protocol (MCP) サーバーを作成します。LLMがセキュリティアラートの分析と対応を自律的かつ対話的に行えるようにすることが目標です。 より柔軟なフィルタリングと共通フォーマット（OCSF）を活用するため、V2 API（`get_findings_v2` 等）を使用します。

## **技術スタック**

* **言語**: Python  
* **実行環境**: Python 3.11以上  
* **パッケージマネージャー**: uv (高速なPythonパッケージマネージャ)  
* **MCP SDK**: mcp / FastMCP を利用  
* **AWS SDK**: boto3  
* **データバリデーション**: Pydantic v2以上（必須）

## **提供するMCPツール（Tools）**

以下の2つのツールを実装してください。FastMCPの @mcp.tool() デコレータを使用して実装するのが望ましいです。

### **1. get_security_hub_findings**

Security HubのFindingsを柔軟な条件で抽出するツールです。boto3 securityhub クライアントの `get_findings_v2()` メソッドを使用します。
`GetFindingsInput`（Pydanticモデル）を入力として受け取り、内部で V2 API が要求する `CompositeFilters` 構造に変換します。

**入力スキーマ (Parameters):**

* `aws_region` (str, optional): AWSリージョン。未指定時は `AWS_DEFAULT_REGION` → `AWS_REGION` を参照し、どちらも未設定ならエラー  
* `severities` (list[str], optional): 重要度レベル（OCSF準拠：Fatal, Critical, High, Medium, Low, Informational）。複数指定時は OR 結合。  
* `aws_account_ids` (list[str], optional): 対象 AWS アカウント ID（12桁数字）。複数指定時は OR 結合。  
* `titles` (list[str], optional): Finding タイトルで前方一致検索。複数指定時は OR 結合。  
* `status_ids` (list[int], optional): リソース ステータス ID（整数）。これまでの `workflow_status` は廃止。  
* `max_results` (int, optional): 返却最大件数。デフォルト: 20、最小: 1、最大: 100。  
* `next_token` (str, optional): ページネーション用トークン（前回レスポンスから）。

**出力 (Returns):**

* `findings` (list[dict]): Finding オブジェクトの配列。以下を必ず含める：
  - `metadata_uid` (str): メタデータ UID（`batch_update_findings_v2` の `MetadataUids` で使用）  
  - `cloud_account_uid` (str): クラウド アカウント UID  
  - `finding_info_uid` (str): Finding 情報 UID  
  - `metadata_product_uid` (str): メタデータ プロダクト UID  
  これら3点識別子は `update_finding_status` で必要。
  - `title` (str): Finding タイトル  
  - `description` (str): 説明  
  - `severity` (str): 重要度（OCSF値）  
  - `status_id` (int): ステータス ID  
  - `created_at` (str): 作成日時（ISO 8601）  
  - `updated_at` (str): 更新日時（ISO 8601）  
  - `resource_type` (str): リソースタイプ  
  - `resource_id` (str): リソース ID  
  
* `next_token` (str, optional): 次ページが存在する場合は含める。  
* `count` (int): 返却 Finding 件数。

### **2. update_finding_status**

Finding のステータスを更新するツールです。boto3 securityhub クライアントの `batch_update_findings_v2()` メソッドを使用します。

**入力スキーマ (Parameters):**

* `aws_region` (str, optional): AWSリージョン。未指定時は `AWS_DEFAULT_REGION` → `AWS_REGION` を参照し、どちらも未設定ならエラー  
* `metadata_uids` (list[str], optional): メタデータ UID リスト（`get_security_hub_findings` から取得）。
  
  **排他条件**: `finding_identifiers` との同時指定不可。
  
* `finding_identifiers` (list[dict], optional): 3点識別子のリスト。各要素は以下を含む：
  ```
  {
    "cloud_account_uid": "str",
    "finding_info_uid": "str",
    "metadata_product_uid": "str"
  }
  ```
  **排他条件**: `metadata_uids` との同時指定不可。`metadata_uids` が非空なら省略。  
  
* `status_id` (int, required): 更新後のステータス ID（0-6, 99）。許容値は `batch_update_findings_v2` に準拠。  
* `comment` (str, optional): ステータス変更理由。  

**出力 (Returns):**

* `success` (bool): 全件成功時 True、一件でも失敗時 False。  
* `processed_count` (int): 正常に更新された Finding 件数。  
* `unprocessed_count` (int): 失敗した Finding 件数。  
* `unprocessed_findings` (list[dict], optional): 失敗の詳細（未処理 Finding があるとき）。各要素は：
  ```
  {
    "finding_identifier": "str (metadata_uid or 3-point)",
    "error_code": "str",
    "error_message": "str"
  }
  ```

## **実装のステップと要件**

1. **プロジェクトの初期化**:  
   * uv を使用したプロジェクト管理を前提とします。必要な依存関係 (mcp, boto3, pydantic) を定義した pyproject.toml を出力してください。  
   * 開発者が uv init や uv add を使って環境を構築しやすいように考慮してください。  
2. **入力のバリデーション（Pydantic v2 必須）**:  
   * Pydantic v2 の BaseModel を用いて、MCPツールごとに入力モデルを定義してください（例：`GetFindingsInput`, `UpdateFindingsV2Input`）。  
   * 以下の検証ルール：
     - `max_results`: 1 ≤ value ≤ 100
     - `aws_account_ids`: 各要素は 12 桁の数字。
     - `status_ids`: 値は 0-6, 99 のいずれか。
     - `severities`: 値は "Fatal", "Critical", "High", "Medium", "Low", "Informational" のいずれか。
     - 更新時 `metadata_uids` と `finding_identifiers` は排他（両方空でない場合エラー）。
     - 検索時のフィルタ条件（severities, account_ids等）が全て空の場合も許可（フィルタなし検索）。
   * バリデーション失敗時は、`ValidationError` を一度キャッチして、**HumanMessage形式で LLM が読みやすいエラー語を返すようにしてください**（何がダメで、何を修正すべきかが明確）。  
3. **AWS SDK (boto3) の呼び出し処理**:  
   * `get_security_hub_findings` 実行時、入力パラメータを `Filters` (V2 CompositeFilters) へマッピングしてください：
     * `Filters` は以下の構造：`{"CompositeFilters": [...], "CompositeOperator": "AND"}`  
      * 各 Finding フィルタ条件（severities, account_ids, titles, status_ids）を、それぞれ別の `CompositeFilter` へ変換。`StringFilters` / `NumberFilters` の各要素は boto3 公式の `Filter` ネスト形式を使用。  
     * CompositeFilter 内は、複数条件に対して同演算子の場合 OR 結合；異演算子の場合はバリデーションエラー。  
      * 例: severities=['Critical', 'High'] → `{"CompositeFilters": [{"StringFilters": [{"FieldName": "severity", "Filter": {"Value": "Critical", "Comparison": "EQUALS"}}, {"FieldName": "severity", "Filter": {"Value": "High", "Comparison": "EQUALS"}}], "Operator": "OR"}], "CompositeOperator": "AND"}`  
   * `batch_update_findings_v2` 呼び出し時：  
     * `MetadataUids` または `FindingIdentifiers` の一方を指定（排他指定は API エラー）。  
     * 更新値は `StatusId`, `Comment` を使用。  
   * 認証情報は boto3 標準（環境変数 `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`）で自動処理。  
4. **MCPサーバーの実装**:  
   * FastMCP インスタンスを作成し、`@mcp.tool()` デコレータで2つのツールを登録してください。  
  * ツール関数のシグネチャは Pydantic モデル直接受け（例: `def get_security_hub_findings(input_data: GetFindingsInput)`）としてください。  
   * ツール Docstring は、LLM が使用方法を理解できるよう、入出力スキーマを詳細に記述してください（パラメータ名、型、制約、デフォルト値、例）。  
   * メイン実行ブロック（`if __name__ == "__main__"`）で `mcp.run(transport='stdio')` を呼び出し、stdin/stdout で MCP クライアントと通信。  
5. **エラーハンドリング**:  
   * AWS APIの呼び出し失敗 (ClientErrorなど) や、バリデーションエラーが発生した場合は、例外をキャッチして分かりやすいエラーメッセージを返すようにしてください。

## **実装上の注意点**

1. **API契約の固定化**: `get_findings_v2` / `batch_update_findings_v2` のレスポンススキーマは AWS 仕様に従う。部分的なレスポンス欠落にも対応（`.get()` で安全に取得）。  
2. **エラーハンドリング**: `ClientError`, `ValidationError`, `ChannelError` 等を捕捉し、スタックトレースは避け、ユーザー向けメッセージを返す。  
3. **ページネーション**: `NextToken` を含むレスポンスは常に返却。LLM がそれを次呼び出しで再利用可能にする。  
4. **ログレベル**: `logging.INFO` で主要な操作（API呼び出し、フィルタ構築、更新結果）をログ。  
5. **テスト**: unit test は Pydantic バリデーション + boto3 Stubber を用いた契約テストを含む。統合テストは避ける（AWS credentials 環境依存）。  

## **出力成果物**

* `pyproject.toml`: 依存パッケージ定義  
* `src/aws_securityhub_mcp_server/server.py`: Pydantic モデル + FastMCP ツール + boto3 統合  
* `src/aws_securityhub_mcp_server/__init__.py`: パッケージ初期化  
* `tests/test_server.py`: 単体テスト（Pydantic + boto3 Stubber）  
* `README.md`: セットアップ・使用方法（ツール名・パラメータは本仕様と一致）