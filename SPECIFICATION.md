# **AWS Security Hub MCP Server 開発指示書**

## **プロジェクトの目的**

AWS Security HubのFindings（検出結果）を柔軟に検索・抽出し、それらのステータスを更新することに特化した Model Context Protocol (MCP) サーバーを作成します。LLMがセキュリティアラートの分析と対応を自律的かつ対話的に行えるようにすることが目標です。 より柔軟なフィルタリングと共通フォーマット（OCSF）を活用するため、V2 API（`get_findings_v2` 等）を使用します。

## **技術スタック**

* **言語**: Python  
* **実行環境**: Python 3.10以上  
* **パッケージマネージャー**: uv (高速なPythonパッケージマネージャ)  
* **MCP SDK**: mcp (FastMCPを利用)  
* **AWS SDK**: boto3  
* **データバリデーション**: pydantic

## **提供するMCPツール（Tools）**

以下の2つのツールを実装してください。FastMCPの @mcp.tool() デコレータを使用して実装するのが望ましいです。

### **1. get_security_hub_findings**

Security HubのFindingsを柔軟な条件で抽出するツールです。boto3の securityhub クライアントの get_findings_v2 メソッドを使用します。 LLMが扱いやすいように、よく使われるフィルター条件を直感的な引数として受け取り、内部で get_findings_v2 が要求する複雑な Filters 辞書（CompositeFilters や StringFilters 等の階層構造）に変換してください。

**入力スキーマ (Parameters):**

* aws_region (str, optional): AWSリージョン (デフォルトは環境変数または ap-northeast-1)  
* severities (list[str], optional): 重要度 (Fatal, Critical, High, Medium, Low, Informational などOCSF準拠の値)  
* aws_account_ids (list[str], optional): 対象のAWSアカウントID (cloud.account.uid へのマッピングを想定)  
* titles (list[str], optional): 検出結果のタイトル  
* workflow_statuses (list[str], optional): ワークフローステータス（例: NEW, NOTIFIED, RESOLVED, SUPPRESSED。API仕様に合わせて activity_name 等へマッピング）  
* max_results (int, optional): 取得する最大件数 (デフォルト: 20, 最大: 100)  
* next_token (str, optional): ページネーション用のトークン

**出力 (Returns):**

* 抽出されたFindingsのリスト（LLMが読みやすいように、OCSFフォーマットの主要なフィールドのみに絞るか、整形して返すこと。特に uid, title, severity, finding_info やステータス情報など、状況把握に必要な情報は必ず含める）。  
* 次のページがある場合は NextToken を含める。

### **2. update_finding_status**

抽出したFindingsのステータスを変更するツールです。boto3の securityhub クライアントのステータス更新API（batch_update_findings_v2、またはV2互換の更新メソッド）を使用します。

**入力スキーマ (Parameters):**

* aws_region (str, optional): AWSリージョン  
* finding_uids (list[str], required): 更新対象のFindingの識別子（UID）リスト。  
* workflow_status (str, required): 変更後のステータス (NEW, NOTIFIED, RESOLVED, SUPPRESSED など)  
* note (str, optional): ステータス変更の理由やメモ

**出力 (Returns):**

* 成功した件数と、失敗した件数およびその理由（ProcessedFindings と UnprocessedFindings の情報など）。

## **実装のステップと要件**

1. **プロジェクトの初期化**:  
   * uv を使用したプロジェクト管理を前提とします。必要な依存関係 (mcp, boto3, pydantic) を定義した pyproject.toml を出力してください。  
   * 開発者が uv init や uv add を使って環境を構築しやすいように考慮してください。  
2. **入力のバリデーション**:  
   * pydantic モデル、またはFastMCPによる型ヒントベースのバリデーションを利用して、MCPツールの入力パラメータのスキーマ定義と実行時の型チェックを行ってください。  
3. **AWS SDK (boto3) の呼び出し処理**:  
   * get_security_hub_findings 実行時、与えられた複数の引数を組み合わせて、boto3の get_findings_v2 用の Filters に正しくマッピングしてください。  
     * 例: severities が渡された場合、{"StringFilters": [{"FieldName": "severity", "Filter": {"Value": severity, "Comparison": "EQUALS"}} for severity in severities]} のような形を含めた CompositeFilters 構造を構築します。複数の条件はAND条件となるように構築してください。  
   * 認証情報は環境変数（AWS_PROFILE、または AWS_ACCESS_KEY_ID と AWS_SECRET_ACCESS_KEY）を自動的に読み込むように標準のboto3の仕組みを利用してください。  
4. **MCPサーバーの実装**:  
   * mcp.server.fastmcp.FastMCP クラスをインスタンス化し、@mcp.tool() デコレータを使って上記2つのツールを登録してください。  
   * ツールのDocstringに詳細な説明（LLMが使い方を理解するためのDescription）を記述してください。  
   * 標準入出力 (stdio) を使用して通信するメイン実行ブロック (if __name__ == "__main__": mcp.run(transport='stdio')) を実装してください。  
5. **エラーハンドリング**:  
   * AWS APIの呼び出し失敗 (ClientErrorなど) や、バリデーションエラーが発生した場合は、例外をキャッチして分かりやすいエラーメッセージを返すようにしてください。

## **出力してほしいもの**

* pyproject.toml  
* server.py (メインとなるMCPサーバーとAWS連携の実装コード)