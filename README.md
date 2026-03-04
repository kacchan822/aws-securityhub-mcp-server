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
AWS_REGION=ap-northeast-1
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

### `get_findings`

AWS SecurityHubからファインディングを取得します。

**パラメータ：**
- `filter_criteria` (str): フィルター条件 (デフォルト: 'ACTIVE')
- `max_results` (int): 返す結果の最大数 (デフォルト: 100)

**戻り値：**
- ファインディングのリストとメタデータ

### `update_finding`

SecurityHubのファインディングステータスを更新します。

**パラメータ：**
- `finding_id` (str): 更新するファインディングのID
- `status` (str): 新しいステータス ('RESOLVED', 'SUPPRESSED' など)

**戻り値：**
- 更新されたファインディングの詳細

### `get_standards_compliance`

SecurityHubの標準適合情報を取得します。

**戻り値：**
- 標準とコンプライアンスステータスの情報

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
