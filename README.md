# AWS SecurityHub MCP Server

AWS SecurityHubと連携するModel Context Protocol (MCP)サーバーです。FastMCPフレームワークを使用して構築されています。

## 概要

このMCPサーバーは、Claude等のAIアシスタントがAWS SecurityHubを操作できるようにするためのツールを提供します。

## 要件

- Python 3.11以上
- uv (Pythonパッケージマネージャー)
- AWS認証情報

## セットアップ

### 1. 環境構築

```bash
# uvをインストール (まだの場合)
curl -LsSf https://astral.sh/uv/install.sh | sh

# プロジェクトディレクトリに移動
cd aws-securityhub-mcp-server

# 仮想環境を作成して依存関係をインストール
uv sync
```

### 2. AWS認証情報の設定

`.env` ファイルを作成し、AWS認証情報を設定します：

```env
AWS_PROFILE=your-profile
AWS_DEFAULT_REGION=ap-northeast-1
```

または、AWS CLIの設定ファイルを使用します。

## 開発

### 依存関係の追加

```bash
# 新しい依存関係を追加
uv pip install package-name

# 開発用の依存関係を追加
uv pip install --group dev package-name
```

### テストの実行

```bash
uv run pytest
```

### コードフォーマット

```bash
uv run black src tests
uv run ruff check --fix src tests
```

## ツール

このサーバーで利用可能なツール：

### `get_security_hub_findings`

AWS SecurityHubからFindingを検索・取得します（V2 API使用）。

**パラメータ：**
- `aws_region` (str, optional): AWSリージョン。デフォルト: `ap-northeast-1`
- `severities` (list[str], optional): 重要度フィルタ（Fatal, Critical, High, Medium, Low, Informational）
- `aws_account_ids` (list[str], optional): AWSアカウントIDリスト（12桁）
- `titles` (list[str], optional): Findingタイトル（前方一致）
- `status_ids` (list[int], optional): ステータスID（0-6, 99）
- `max_results` (int, optional): 返却件数（1-100、デフォルト: 20）
- `next_token` (str, optional): ページネーション用トークン

**戻り値：**
- `findings`: Finding配列
  - `metadata_uid`: メタデータUID（更新に必須）
  - `cloud_account_uid`: アカウントUID
  - `finding_info_uid`: Finding情報UID
  - `metadata_product_uid`: プロダクトUID
  - `title`: Finding名
  - `description`: 説明
  - `severity`: 重要度
  - `status_id`: ステータスID
  - `created_at`: 作成日時（ISO 8601）
  - `updated_at`: 更新日時（ISO 8601）
  - `resource_type`: リソースタイプ
  - `resource_id`: リソースID
- `next_token`: 次ページトークン（あれば）
- `count`: 返却件数

### `update_finding_status`

FindingのステータスをV2 APIで更新します。

**パラメータ：**
- `aws_region` (str, optional): AWSリージョン。デフォルト: `ap-northeast-1`
- `metadata_uids` (list[str], optional): メタデータUIDリスト。`finding_identifiers`と排他。
- `finding_identifiers` (list[dict], optional): 3点識別子リスト。以下を含む：
  - `cloud_account_uid` (str): アカウントUID
  - `finding_info_uid` (str): Finding情報UID
  - `metadata_product_uid` (str): プロダクトUID
  - `metadata_uids`と排他。
- `status_id` (int, required): 更新先ステータスID（0-6, 99）
- `comment` (str, optional): 変更理由

**戻り値：**
- `success` (bool): 全件成功時True
- `processed_count` (int): 成功件数
- `unprocessed_count` (int): 失敗件数
- `unprocessed_findings` (list[dict], optional): 失敗詳細
  - `finding_identifier`: 識別子
  - `error_code`: エラーコード
  - `error_message`: エラーメッセージ

## サーバーの実行

```bash
uv run python -m mcp_server.server
```

## プロジェクト構造

```
├── pyproject.toml           # プロジェクト設定
├── README.md                # このファイル
├── .gitignore               # Git無視設定
├── .env.example             # 環境変数のテンプレート
├── src/
│   └── mcp_server/
│       ├── __init__.py
│       └── server.py        # MCPサーバーのメイン処理
└── tests/
    └── test_server.py       # テスト
```

## ライセンス

MIT

## 参考資料

- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [AWS SecurityHub API](https://docs.aws.amazon.com/securityhub/)
- [uv Documentation](https://docs.astral.sh/uv/)
