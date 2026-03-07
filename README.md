# AWS Security Hub MCP Server
[![Test](https://github.com/kacchan822/aws-securityhub-mcp-server/actions/workflows/test.yml/badge.svg)](https://github.com/kacchan822/aws-securityhub-mcp-server/actions/workflows/test.yml)

> [!WARNING]
> このプロジェクトは現在開発中の不安定版です。仕様変更や破壊的変更が発生する可能性があります。
> 本番環境での利用は非推奨です。

AWS SecurityHubと連携するModel Context Protocol (MCP)サーバーです。FastMCPフレームワークを使用して構築されています。

## 概要

このMCPサーバーは、AIアシスタントがAWS Security Hubを操作できるようにするためのツールを提供します。

## 要件

- Python 3.11+
- uv
- 利用するツールに応じたSecurity Hubの権限を持つAWS認証情報
- AWS CLIが適切なプロファイルで設定されていること（オプション）

## セットアップ

### リモートリポジトリから直接取得して起動する場合

```json
{
 "mcpServers": {
    "aws-securityhub-mcp-server": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/kacchan822/aws-securityhub-mcp-server@main", "aws-securityhub-mcp-server"],
      "env": {
        "AWS_PROFILE": "your-aws-profile", // Optional - uses your local AWS configuration if not specified
        "AWS_REGION": "your-aws-region", // Optional - uses your local AWS configuration if not specified
        "LOG_LEVEL": "INFO" // Optional - controls logging level for both FastMCP and application
      }
    }
  }
}
```

### インストールしてから起動する場合

#### インストール

```bash
uv pip install git+https://github.com/kacchan822/aws-securityhub-mcp-server.git
```

#### 設定

```json
{
 "mcpServers": {
    "aws-securityhub-mcp-server": {
      "command": "uvx",
      "args": ["--from", "aws-securityhub-mcp-server", "aws-securityhub-mcp-server"],
      "env": {
        "AWS_PROFILE": "your-aws-profile", // Optional - uses your local AWS configuration if not specified
        "AWS_REGION": "your-aws-region", // Optional - uses your local AWS configuration if not specified
        "LOG_LEVEL": "INFO" // Optional - controls logging level for both FastMCP and application
      }
    }
  }
}
```

## 環境変数

| 環境変数 | デフォルト | 説明 |
|---------|----------|------|
| `AWS_PROFILE` | - | AWS CLIプロファイル（オプション） |
| `AWS_DEFAULT_REGION` / `AWS_REGION` | - | AWSリージョン（どちらか一方を指定） |
| `LOG_LEVEL` | `INFO` | ログレベル（DEBUG, INFO, WARNING, ERROR, CRITICAL） |

## ツール

### `get_security_hub_findings`

AWS SecurityHubからFindingを検索・取得します（V2 API使用）。

**入力（Pydanticモデル）：**
- `input_data` (`GetFindingsInput`):
  - `aws_region` (str, optional): AWSリージョン。未指定時は `AWS_DEFAULT_REGION`, `AWS_REGION` の順で参照し、未指定の場合はエラー
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

**入力（Pydanticモデル）：**
- `input_data` (`UpdateFindingsV2Input`):
  - `aws_region` (str, optional): AWSリージョン。未指定時は `AWS_DEFAULT_REGION` → `AWS_REGION` の順で参照し、どちらも未設定ならエラー
  - `metadata_uids` (list[str], optional): メタデータUIDリスト。`finding_identifiers`と排他。
  - `finding_identifiers` (list[dict], optional): 3点識別子リスト。以下を含む：
    - `cloud_account_uid` (str): アカウントUID
    - `finding_info_uid` (str): Finding情報UID
    - `metadata_product_uid` (str): プロダクトUID
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

## ライセンス

MIT

## 参考資料

- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [AWS SecurityHub API](https://docs.aws.amazon.com/securityhub/)
- [uv Documentation](https://docs.astral.sh/uv/)
