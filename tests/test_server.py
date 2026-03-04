"""Tests for AWS SecurityHub MCP Server (V2 API)"""
from unittest.mock import Mock, patch
from pydantic import ValidationError
import pytest
from botocore.exceptions import ClientError

from mcp_server.server import (
    get_security_hub_findings,
    update_finding_status,
    build_composite_filters_v2,
    format_finding_for_response,
    get_securityhub_client,
    GetFindingsInput,
    UpdateFindingsV2Input,
    SeverityEnum,
)


# ============================================================================
# Pydantic Input Model Tests
# ============================================================================

class TestGetFindingsInput:
    """Test GetFindingsInput validation"""

    def test_valid_input_basic(self):
        """Test valid input with minimal parameters"""
        input_data = GetFindingsInput(
            severities=[SeverityEnum.CRITICAL, SeverityEnum.HIGH],
            max_results=50
        )
        assert len(input_data.severities) == 2
        assert input_data.max_results == 50

    def test_invalid_max_results_too_low(self):
        """Test max_results validation - too low"""
        with pytest.raises(ValidationError):
            GetFindingsInput(max_results=0)

    def test_invalid_max_results_too_high(self):
        """Test max_results validation - too high"""
        with pytest.raises(ValidationError):
            GetFindingsInput(max_results=101)

    def test_invalid_account_id_format(self):
        """Test AWS account ID validation - invalid format"""
        with pytest.raises(ValidationError):
            GetFindingsInput(aws_account_ids=["12345"])  # Too short

    def test_invalid_account_id_non_digit(self):
        """Test AWS account ID validation - non-digit"""
        with pytest.raises(ValidationError):
            GetFindingsInput(aws_account_ids=["12345678901a"])  # Contains letter

    def test_invalid_status_id(self):
        """Test status ID validation - out of range"""
        with pytest.raises(ValidationError):
            GetFindingsInput(status_ids=[7])  # Invalid ID (not 0-6, 99)

    def test_valid_status_ids(self):
        """Test valid status IDs"""
        input_data = GetFindingsInput(status_ids=[0, 1, 2, 3, 4, 5, 6, 99])
        assert len(input_data.status_ids) == 8

    def test_valid_account_ids(self):
        """Test valid AWS account IDs"""
        input_data = GetFindingsInput(
            aws_account_ids=["123456789012", "210987654321"]
        )
        assert len(input_data.aws_account_ids) == 2


class TestUpdateFindingsV2Input:
    """Test UpdateFindingsV2Input validation"""

    def test_valid_input_with_metadata_uids(self):
        """Test valid input with metadata_uids only"""
        input_data = UpdateFindingsV2Input(
            metadata_uids=["uid1", "uid2"],
            status_id=2
        )
        assert input_data.metadata_uids == ["uid1", "uid2"]
        assert input_data.status_id == 2

    def test_valid_input_with_finding_identifiers(self):
        """Test valid input with finding_identifiers only"""
        input_data = UpdateFindingsV2Input(
            finding_identifiers=[
                {
                    "cloud_account_uid": "123456789012",
                    "finding_info_uid": "finding-1",
                    "metadata_product_uid": "product-1"
                }
            ],
            status_id=2
        )
        assert len(input_data.finding_identifiers) == 1

    def test_exclusive_identifiers_both_specified(self):
        """Test that metadata_uids and finding_identifiers are mutually exclusive"""
        with pytest.raises(ValidationError) as exc_info:
            UpdateFindingsV2Input(
                metadata_uids=["uid1"],
                finding_identifiers=[
                    {
                        "cloud_account_uid": "123456789012",
                        "finding_info_uid": "finding-1",
                        "metadata_product_uid": "product-1"
                    }
                ],
                status_id=2
            )
        assert "mutually exclusive" in str(exc_info.value)

    def test_exclusive_identifiers_neither_specified(self):
        """Test error when neither metadata_uids nor finding_identifiers specified"""
        with pytest.raises(ValidationError) as exc_info:
            UpdateFindingsV2Input(status_id=2)
        assert "Either metadata_uids or finding_identifiers must be specified" in str(
            exc_info.value
        )

    def test_invalid_status_id(self):
        """Test status_id validation"""
        with pytest.raises(ValidationError):
            UpdateFindingsV2Input(
                metadata_uids=["uid1"],
                status_id=7  # Invalid (only 0-6, 99 valid)
            )


# ============================================================================
# CompositeFilters Building Tests
# ============================================================================

class TestBuildCompositeFiltersV2:
    """Test V2 CompositeFilters building"""

    def test_build_filters_with_severities(self):
        """Test building filters with severity parameter"""
        filters = build_composite_filters_v2(severities=["Critical", "High"])

        assert "CompositeFilters" in filters
        assert filters["CompositeOperator"] == "AND"
        assert len(filters["CompositeFilters"]) == 1

        composite_filter = filters["CompositeFilters"][0]
        assert "StringFilters" in composite_filter
        assert composite_filter["Operator"] == "OR"
        assert len(composite_filter["StringFilters"]) == 2
        assert composite_filter["StringFilters"][0]["FieldName"] == "severity"
        assert composite_filter["StringFilters"][0]["Comparison"] == "EQUALS"

    def test_build_filters_with_account_ids(self):
        """Test building filters with AWS account IDs"""
        filters = build_composite_filters_v2(
            aws_account_ids=["123456789012", "210987654321"]
        )

        assert len(filters["CompositeFilters"]) == 1
        composite_filter = filters["CompositeFilters"][0]
        assert composite_filter["StringFilters"][0]["FieldName"] == "cloud.account.uid"

    def test_build_filters_with_titles(self):
        """Test building filters with titles (prefix match)"""
        filters = build_composite_filters_v2(
            titles=["EC2 Security Group", "IAM Policy"]
        )

        composite_filter = filters["CompositeFilters"][0]
        assert composite_filter["StringFilters"][0]["FieldName"] == "finding_info.title"
        assert composite_filter["StringFilters"][0]["Comparison"] == "PREFIX"

    def test_build_filters_with_status_ids(self):
        """Test building filters with status IDs (NumberFilters)"""
        filters = build_composite_filters_v2(status_ids=[0, 2, 3])

        composite_filter = filters["CompositeFilters"][0]
        assert "NumberFilters" in composite_filter
        assert composite_filter["NumberFilters"][0]["FieldName"] == "status_id"
        assert composite_filter["NumberFilters"][0]["Comparison"] == "EQUALS"
        assert len(composite_filter["NumberFilters"]) == 3

    def test_build_filters_combined(self):
        """Test building filters with multiple parameters"""
        filters = build_composite_filters_v2(
            severities=["Critical"],
            aws_account_ids=["123456789012"],
            titles=["EC2 Issue"],
            status_ids=[2]
        )

        assert filters["CompositeOperator"] == "AND"
        assert len(filters["CompositeFilters"]) == 4  # Each parameter is a separate filter

    def test_build_filters_empty(self):
        """Test building filters with no parameters returns None"""
        filters = build_composite_filters_v2()
        assert filters is None


# ============================================================================
# Finding Format Tests
# ============================================================================

class TestFormatFindingForResponse:
    """Test finding formatting for response"""

    def test_format_finding_complete(self):
        """Test formatting with complete finding data"""
        raw_finding = {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/12345",
            "Title": "Test Finding",
            "Description": "Test description",
            "Severity": {"Label": "CRITICAL"},
            "AwsAccountId": "123456789012",
            "FindingInfoUid": "finding-uid-123",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "StatusId": 0,
            "Resources": [
                {
                    "Type": "AwsEc2Instance",
                    "Id": "i-1234567890abcdef0"
                }
            ],
            "CreatedAt": "2024-01-01T00:00:00.000Z",
            "UpdatedAt": "2024-01-02T00:00:00.000Z",
        }

        formatted = format_finding_for_response(raw_finding)

        assert formatted["metadata_uid"] == raw_finding["Id"]
        assert formatted["cloud_account_uid"] == "123456789012"
        assert formatted["finding_info_uid"] == "finding-uid-123"
        assert formatted["metadata_product_uid"] == raw_finding["ProductArn"]
        assert formatted["title"] == "Test Finding"
        assert formatted["severity"] == "CRITICAL"
        assert formatted["status_id"] == 0
        assert formatted["resource_type"] == "AwsEc2Instance"
        assert formatted["resource_id"] == "i-1234567890abcdef0"

    def test_format_finding_minimal(self):
        """Test formatting with minimal fields"""
        raw_finding = {
            "Id": "test-id",
            "Title": "Test",
            "AwsAccountId": "123456789012",
        }

        formatted = format_finding_for_response(raw_finding)

        assert formatted["metadata_uid"] == "test-id"
        assert formatted["title"] == "Test"
        assert formatted["cloud_account_uid"] == "123456789012"
        assert formatted["finding_info_uid"] == "test-id"  # Fallback to Id
        assert formatted["metadata_product_uid"] == ""  # Fallback to empty
        assert formatted["severity"] is None


# ============================================================================
# MCP Tool Tests
# ============================================================================

class TestGetSecurityHubFindings:
    """Test get_security_hub_findings tool"""

    @patch("mcp_server.server.get_securityhub_client")
    def test_get_findings_success(self, mock_get_client):
        """Test successful findings retrieval with V2 API"""
        mock_client = Mock()
        mock_client.get_findings_v2.return_value = {
            "Findings": [
                {
                    "Id": "finding-1",
                    "Title": "Test Finding 1",
                    "AwsAccountId": "123456789012",
                    "Severity": {"Label": "HIGH"},
                    "StatusId": 0,
                    "Resources": [{"Type": "AwsEc2Instance", "Id": "i-123"}],
                },
                {
                    "Id": "finding-2",
                    "Title": "Test Finding 2",
                    "AwsAccountId": "123456789012",
                    "Severity": {"Label": "CRITICAL"},
                    "StatusId": 1,
                    "Resources": [],
                },
            ],
            "NextToken": "next-page-token"
        }
        mock_get_client.return_value = mock_client

        result = get_security_hub_findings(
            severities=["High", "Critical"],
            max_results=20
        )

        assert result["count"] == 2
        assert len(result["findings"]) == 2
        assert result["next_token"] == "next-page-token"
        assert result["findings"][0]["metadata_uid"] == "finding-1"
        assert result["findings"][1]["severity"] == "CRITICAL"

        # Verify V2 API call
        mock_client.get_findings_v2.assert_called_once()
        call_kwargs = mock_client.get_findings_v2.call_args[1]
        assert call_kwargs["MaxResults"] == 20
        assert "Filters" in call_kwargs
        assert "CompositeFilters" in call_kwargs["Filters"]

    @patch("mcp_server.server.get_securityhub_client")
    def test_get_findings_pagination(self, mock_get_client):
        """Test findings retrieval with pagination token"""
        mock_client = Mock()
        mock_client.get_findings_v2.return_value = {"Findings": []}
        mock_get_client.return_value = mock_client

        get_security_hub_findings(next_token="previous-token", max_results=50)

        call_kwargs = mock_client.get_findings_v2.call_args[1]
        assert call_kwargs["NextToken"] == "previous-token"
        assert call_kwargs["MaxResults"] == 50

    def test_get_findings_validation_error(self):
        """Test validation error handling"""
        result = get_security_hub_findings(max_results=200)  # Invalid: > 100

        assert result["error"] == "ValidationError"
        assert "100" in result["message"]  # Check for "100" in message
        assert result["count"] == 0
        assert result["findings"] == []

    @patch("mcp_server.server.get_securityhub_client")
    def test_get_findings_client_error(self, mock_get_client):
        """Test AWS ClientError handling"""
        mock_client = Mock()
        mock_client.get_findings_v2.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "GetFindingsV2"
        )
        mock_get_client.return_value = mock_client

        result = get_security_hub_findings()

        assert result["error"] == "AccessDeniedException"
        assert result["message"] == "Access denied"
        assert result["count"] == 0


class TestUpdateFindingStatus:
    """Test update_finding_status tool"""

    @patch("mcp_server.server.get_securityhub_client")
    def test_update_status_with_metadata_uids(self, mock_get_client):
        """Test successful status update using metadata UIDs"""
        mock_client = Mock()
        mock_client.batch_update_findings_v2.return_value = {
            "ProcessedFindings": [{"MetadataUid": "uid-1"}, {"MetadataUid": "uid-2"}],
            "UnprocessedFindings": []
        }
        mock_get_client.return_value = mock_client

        result = update_finding_status(
            metadata_uids=["uid-1", "uid-2"],
            status_id=2,
            comment="Resolved"
        )

        assert result["success"] is True
        assert result["processed_count"] == 2
        assert result["unprocessed_count"] == 0

        # Verify V2 API call
        mock_client.batch_update_findings_v2.assert_called_once()
        call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
        assert call_kwargs["MetadataUids"] == ["uid-1", "uid-2"]
        assert call_kwargs["StatusId"] == 2
        assert call_kwargs["Comment"] == "Resolved"

    @patch("mcp_server.server.get_securityhub_client")
    def test_update_status_with_finding_identifiers(self, mock_get_client):
        """Test status update using 3-point finding identifiers"""
        mock_client = Mock()
        mock_client.batch_update_findings_v2.return_value = {
            "ProcessedFindings": [{"FindingIdentifier": {"CloudAccountUid": "123"}}],
            "UnprocessedFindings": []
        }
        mock_get_client.return_value = mock_client

        result = update_finding_status(
            finding_identifiers=[
                {
                    "cloud_account_uid": "123456789012",
                    "finding_info_uid": "finding-1",
                    "metadata_product_uid": "product-1"
                }
            ],
            status_id=2
        )

        assert result["success"] is True
        assert result["processed_count"] == 1

        call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
        assert "FindingIdentifiers" in call_kwargs
        assert len(call_kwargs["FindingIdentifiers"]) == 1
        assert call_kwargs["FindingIdentifiers"][0]["CloudAccountUid"] == "123456789012"

    @patch("mcp_server.server.get_securityhub_client")
    def test_update_status_partial_failure(self, mock_get_client):
        """Test partial failure in status update"""
        mock_client = Mock()
        mock_client.batch_update_findings_v2.return_value = {
            "ProcessedFindings": [{"MetadataUid": "uid-1"}],
            "UnprocessedFindings": [
                {
                    "FindingIdentifier": "uid-2",
                    "ErrorCode": "InvalidInput",
                    "ErrorMessage": "Finding not found"
                }
            ]
        }
        mock_get_client.return_value = mock_client

        result = update_finding_status(
            metadata_uids=["uid-1", "uid-2"],
            status_id=2
        )

        assert result["success"] is False
        assert result["processed_count"] == 1
        assert result["unprocessed_count"] == 1
        assert "unprocessed_findings" in result

    def test_update_status_validation_error_no_identifiers(self):
        """Test validation error when no identifiers specified"""
        result = update_finding_status(status_id=2)

        assert result["success"] is False
        assert result["error"] == "ValidationError"

    def test_update_status_validation_error_invalid_status_id(self):
        """Test validation error for invalid status ID"""
        result = update_finding_status(
            metadata_uids=["uid1"],
            status_id=50  # Invalid
        )

        assert result["success"] is False
        assert result["error"] == "ValidationError"


# ============================================================================
# Client Initialization Tests
# ============================================================================

class TestGetSecurityHubClient:
    """Test SecurityHub client initialization"""

    @patch("mcp_server.server.boto3.client")
    def test_client_with_default_region(self, mock_boto_client):
        """Test client initialization with default region"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        get_securityhub_client()

        mock_boto_client.assert_called_once_with("securityhub", region_name="ap-northeast-1")

    @patch("mcp_server.server.boto3.client")
    def test_client_with_custom_region(self, mock_boto_client):
        """Test client initialization with custom region"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        get_securityhub_client(region_name="us-west-2")

        mock_boto_client.assert_called_once_with("securityhub", region_name="us-west-2")

    @patch("mcp_server.server.boto3.client")
    @patch.dict("os.environ", {"AWS_DEFAULT_REGION": "eu-west-1"})
    def test_client_with_env_region(self, mock_boto_client):
        """Test client initialization with region from environment"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        get_securityhub_client()

        mock_boto_client.assert_called_once_with("securityhub", region_name="eu-west-1")

