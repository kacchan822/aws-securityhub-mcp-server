"""Tests for AWS SecurityHub MCP Server (V2 API)"""
from unittest.mock import Mock, patch
from pydantic import ValidationError
import pytest
from botocore.exceptions import ClientError

from aws_securityhub_mcp_server.server import (
    get_security_hub_findings,
    update_finding_status,
    build_composite_filters_v2,
    format_finding_for_response,
    resolve_region,
    get_securityhub_client,
    clear_securityhub_client_cache,
    GetFindingsInput,
    UpdateFindingsV2Input,
    FindingIdentifier,
    SeverityEnum,
)


@pytest.fixture(autouse=True)
def clear_client_cache_between_tests():
    """Clear cached clients to keep tests independent."""
    clear_securityhub_client_cache()
    yield
    clear_securityhub_client_cache()


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
        assert composite_filter["StringFilters"][0]["Filter"]["Comparison"] == "EQUALS"

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
        assert composite_filter["StringFilters"][0]["Filter"]["Comparison"] == "PREFIX"

    def test_build_filters_with_status_ids(self):
        """Test building filters with status IDs (NumberFilters)"""
        filters = build_composite_filters_v2(status_ids=[0, 2, 3])

        composite_filter = filters["CompositeFilters"][0]
        assert "NumberFilters" in composite_filter
        assert composite_filter["NumberFilters"][0]["FieldName"] == "status_id"
        assert composite_filter["NumberFilters"][0]["Filter"]["Eq"] == 0
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
        """Test formatting with complete finding data in OCSF format"""
        raw_finding = {
            "metadata": {
                "uid": "arn:aws:securityhub:us-east-1:123456789012:finding/12345",
                "product": {
                    "uid": "arn:aws:securityhub:us-east-1::product/aws/securityhub"
                }
            },
            "finding_info": {
                "uid": "finding-uid-123",
                "title": "Test Finding",
                "desc": "Test description",
                "created_time": 1704067200000,  # 2024-01-01T00:00:00Z in milliseconds
                "modified_time": 1704153600000  # 2024-01-02T00:00:00Z in milliseconds
            },
            "cloud": {
                "account": {
                    "uid": "123456789012"
                }
            },
            "severity": "Critical",
            "status_id": 0,
            "time": 1704067200000,  # Unix timestamp in milliseconds
            "resources": [
                {
                    "type": "AwsEc2Instance",
                    "uid": "i-1234567890abcdef0"
                }
            ]
        }

        formatted = format_finding_for_response(raw_finding)

        assert formatted["metadata_uid"] == "arn:aws:securityhub:us-east-1:123456789012:finding/12345"
        assert formatted["cloud_account_uid"] == "123456789012"
        assert formatted["finding_info_uid"] == "finding-uid-123"
        assert formatted["metadata_product_uid"] == "arn:aws:securityhub:us-east-1::product/aws/securityhub"
        assert formatted["title"] == "Test Finding"
        assert formatted["description"] == "Test description"
        assert formatted["severity"] == "Critical"
        assert formatted["status_id"] == 0
        # Timestamps should be converted to ISO 8601 format
        assert formatted["created_at"] == "2024-01-01T00:00:00Z"
        assert formatted["updated_at"] == "2024-01-02T00:00:00Z"
        assert formatted["resource_type"] == "AwsEc2Instance"
        assert formatted["resource_id"] == "i-1234567890abcdef0"

    def test_format_finding_minimal(self):
        """Test formatting with minimal fields in OCSF format"""
        raw_finding = {
            "metadata": {
                "uid": "test-id"
            },
            "finding_info": {
                "title": "Test"
            },
            "cloud": {
                "account": {
                    "uid": "123456789012"
                }
            }
        }

        formatted = format_finding_for_response(raw_finding)

        assert formatted["metadata_uid"] == "test-id"
        assert formatted["title"] == "Test"
        assert formatted["cloud_account_uid"] == "123456789012"
        assert formatted["finding_info_uid"] is None  # Not provided in minimal case
        assert formatted["metadata_product_uid"] is None  # None when product.uid not present
        assert formatted["severity"] is None

    def test_format_finding_no_null_values_for_complete_data(self):
        """Test that complete OCSF finding data returns no null values"""
        raw_finding = {
            "metadata": {
                "uid": "arn:aws:securityhub:us-west-2:987654321098:finding/test-finding",
                "product": {
                    "uid": "arn:aws:securityhub:us-west-2::product/aws/guardduty"
                }
            },
            "finding_info": {
                "uid": "test-finding-uid",
                "title": "Suspicious Activity Detected",
                "desc": "Detailed description of the security issue",
                "created_time": 1709289600000,  # 2024-03-01T10:00:00Z in milliseconds
                "modified_time": 1709636400000  # 2024-03-05T12:30:00Z in milliseconds
            },
            "cloud": {
                "account": {
                    "uid": "987654321098"
                }
            },
            "severity": "Medium",
            "status_id": 3,
            "time": 1709289600000,  # Unix timestamp in milliseconds
            "resources": [
                {
                    "type": "AwsEc2SecurityGroup",
                    "uid": "sg-0123456789abcdef0"
                }
            ]
        }

        formatted = format_finding_for_response(raw_finding)

        # Verify none of the key fields are null
        assert formatted["metadata_uid"] is not None
        assert formatted["cloud_account_uid"] is not None
        assert formatted["finding_info_uid"] is not None
        assert formatted["metadata_product_uid"] is not None
        assert formatted["title"] is not None
        assert formatted["description"] is not None
        assert formatted["severity"] is not None
        assert formatted["status_id"] is not None
        assert formatted["created_at"] is not None
        assert formatted["updated_at"] is not None
        assert formatted["resource_type"] is not None
        assert formatted["resource_id"] is not None

    def test_format_finding_multiple_resources(self):
        """Test formatting with multiple resources (only first is extracted)"""
        raw_finding = {
            "metadata": {"uid": "test-id"},
            "finding_info": {"title": "Multi Resource Finding"},
            "cloud": {"account": {"uid": "111111111111"}},
            "resources": [
                {"type": "AwsEc2Instance", "uid": "i-first"},
                {"type": "AwsS3Bucket", "uid": "bucket-second"},
                {"type": "AwsIamRole", "uid": "role-third"}
            ]
        }

        formatted = format_finding_for_response(raw_finding)

        # Should extract only the first resource
        assert formatted["resource_type"] == "AwsEc2Instance"
        assert formatted["resource_id"] == "i-first"

    def test_format_finding_empty_nested_objects(self):
        """Test formatting handles empty nested objects gracefully"""
        raw_finding = {
            "metadata": {},
            "finding_info": {},
            "cloud": {},
            "resources": []
        }

        formatted = format_finding_for_response(raw_finding)

        # All fields should be None when nested objects are empty
        assert formatted["metadata_uid"] is None
        assert formatted["cloud_account_uid"] is None
        assert formatted["finding_info_uid"] is None
        assert formatted["metadata_product_uid"] is None
        assert formatted["title"] is None
        assert formatted["description"] is None
        assert formatted["resource_type"] is None
        assert formatted["resource_id"] is None


# ============================================================================
# MCP Tool Tests
# ============================================================================

class TestGetSecurityHubFindings:
    """Test get_security_hub_findings tool"""

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
    def test_get_findings_success(self, mock_get_client):
        """Test successful findings retrieval with V2 API in OCSF format"""
        mock_client = Mock()
        mock_client.get_findings_v2.return_value = {
            "Findings": [
                {
                    "metadata": {
                        "uid": "arn:aws:securityhub:us-east-1:123456789012:finding/finding-1",
                        "product": {
                            "uid": "arn:aws:securityhub:us-east-1::product/aws/securityhub"
                        }
                    },
                    "finding_info": {
                        "uid": "finding-1",
                        "title": "Test Finding 1",
                        "desc": "Description 1",
                        "created_time": 1704067200000,
                        "modified_time": 1704153600000
                    },
                    "cloud": {
                        "account": {
                            "uid": "123456789012"
                        }
                    },
                    "severity": "High",
                    "status_id": 0,
                    "time": 1704067200000,
                    "resources": [{"type": "AwsEc2Instance", "uid": "i-123"}],
                },
                {
                    "metadata": {
                        "uid": "arn:aws:securityhub:us-east-1:123456789012:finding/finding-2",
                        "product": {
                            "uid": "arn:aws:securityhub:us-east-1::product/aws/securityhub"
                        }
                    },
                    "finding_info": {
                        "uid": "finding-2",
                        "title": "Test Finding 2",
                        "desc": "Description 2",
                        "created_time": 1704240000000,
                        "modified_time": 1704326400000
                    },
                    "cloud": {
                        "account": {
                            "uid": "123456789012"
                        }
                    },
                    "severity": "Critical",
                    "status_id": 1,
                    "time": 1704240000000,
                    "resources": [],
                },
            ],
            "NextToken": "next-page-token"
        }
        mock_get_client.return_value = mock_client

        result = get_security_hub_findings(
            GetFindingsInput(
                severities=[SeverityEnum.HIGH, SeverityEnum.CRITICAL],
                max_results=20,
            )
        )

        assert result["count"] == 2
        assert len(result["findings"]) == 2
        assert result["next_token"] == "next-page-token"
        assert result["findings"][0]["metadata_uid"] == "arn:aws:securityhub:us-east-1:123456789012:finding/finding-1"
        assert result["findings"][0]["finding_info_uid"] == "finding-1"
        assert result["findings"][0]["title"] == "Test Finding 1"
        assert result["findings"][0]["severity"] == "High"
        assert result["findings"][1]["severity"] == "Critical"
        assert result["findings"][1]["title"] == "Test Finding 2"

        # Verify V2 API call
        mock_client.get_findings_v2.assert_called_once()
        call_kwargs = mock_client.get_findings_v2.call_args[1]
        assert call_kwargs["MaxResults"] == 20
        assert "Filters" in call_kwargs
        assert "CompositeFilters" in call_kwargs["Filters"]

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
    def test_get_findings_pagination(self, mock_get_client):
        """Test findings retrieval with pagination token"""
        mock_client = Mock()
        mock_client.get_findings_v2.return_value = {"Findings": []}
        mock_get_client.return_value = mock_client

        get_security_hub_findings(GetFindingsInput(next_token="previous-token", max_results=50))

        call_kwargs = mock_client.get_findings_v2.call_args[1]
        assert call_kwargs["NextToken"] == "previous-token"
        assert call_kwargs["MaxResults"] == 50

    def test_get_findings_validation_error(self):
        """Test validation error handling"""
        result = get_security_hub_findings({"max_results": 200})  # Invalid: > 100

        assert result["error"] == "ValidationError"
        assert "100" in result["message"]  # Check for "100" in message
        assert result["count"] == 0
        assert result["findings"] == []

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
    def test_get_findings_client_error(self, mock_get_client):
        """Test AWS ClientError handling"""
        mock_client = Mock()
        mock_client.get_findings_v2.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "GetFindingsV2"
        )
        mock_get_client.return_value = mock_client

        result = get_security_hub_findings(GetFindingsInput())

        assert result["error"] == "AccessDeniedException"
        assert result["message"] == "Access denied"
        assert result["count"] == 0


class TestUpdateFindingStatus:
    """Test update_finding_status tool"""

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
    def test_update_status_with_metadata_uids(self, mock_get_client):
        """Test successful status update using metadata UIDs"""
        mock_client = Mock()
        mock_client.batch_update_findings_v2.return_value = {
            "ProcessedFindings": [{"MetadataUid": "uid-1"}, {"MetadataUid": "uid-2"}],
            "UnprocessedFindings": []
        }
        mock_get_client.return_value = mock_client

        result = update_finding_status(
            UpdateFindingsV2Input(
                metadata_uids=["uid-1", "uid-2"],
                status_id=2,
                comment="Resolved",
            )
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

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
    def test_update_status_with_finding_identifiers(self, mock_get_client):
        """Test status update using 3-point finding identifiers"""
        mock_client = Mock()
        mock_client.batch_update_findings_v2.return_value = {
            "ProcessedFindings": [{"FindingIdentifier": {"CloudAccountUid": "123"}}],
            "UnprocessedFindings": []
        }
        mock_get_client.return_value = mock_client

        result = update_finding_status(
            UpdateFindingsV2Input(
                finding_identifiers=[
                    {
                        "cloud_account_uid": "123456789012",
                        "finding_info_uid": "finding-1",
                        "metadata_product_uid": "product-1"
                    }
                ],
                status_id=2,
            )
        )

        assert result["success"] is True
        assert result["processed_count"] == 1

        call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
        assert "FindingIdentifiers" in call_kwargs
        assert len(call_kwargs["FindingIdentifiers"]) == 1
        assert call_kwargs["FindingIdentifiers"][0]["CloudAccountUid"] == "123456789012"

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
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
            UpdateFindingsV2Input(
                metadata_uids=["uid-1", "uid-2"],
                status_id=2,
            )
        )

        assert result["success"] is False
        assert result["processed_count"] == 1
        assert result["unprocessed_count"] == 1
        assert "unprocessed_findings" in result

    def test_update_status_validation_error_no_identifiers(self):
        """Test validation error when no identifiers specified"""
        result = update_finding_status({"status_id": 2})

        assert result["success"] is False
        assert result["error"] == "ValidationError"

    def test_update_status_validation_error_invalid_status_id(self):
        """Test validation error for invalid status ID"""
        result = update_finding_status(
            {"metadata_uids": ["uid1"], "status_id": 50}  # Invalid
        )

        assert result["success"] is False
        assert result["error"] == "ValidationError"

    def test_finding_identifier_invalid_account_uid_format(self):
        """Test FindingIdentifier validation rejects invalid AWS account ID format"""
        # Account ID must be 12 digits
        with pytest.raises(ValidationError) as exc_info:
            FindingIdentifier(
                cloud_account_uid="12345",  # Too short
                finding_info_uid="finding-1",
                metadata_product_uid="product-1"
            )
        assert "cloud_account_uid must be 12-digit" in str(exc_info.value)

    def test_finding_identifier_account_uid_with_non_digits(self):
        """Test FindingIdentifier validation rejects non-numeric account ID"""
        with pytest.raises(ValidationError) as exc_info:
            FindingIdentifier(
                cloud_account_uid="1234567890ab",  # Non-numeric
                finding_info_uid="finding-1",
                metadata_product_uid="product-1"
            )
        assert "cloud_account_uid must be 12-digit" in str(exc_info.value)

    def test_finding_identifier_empty_finding_info_uid(self):
        """Test FindingIdentifier validation rejects empty finding_info_uid"""
        with pytest.raises(ValidationError) as exc_info:
            FindingIdentifier(
                cloud_account_uid="123456789012",
                finding_info_uid="",  # Empty
                metadata_product_uid="product-1"
            )
        assert "at least 1 character" in str(exc_info.value).lower()

    def test_finding_identifier_empty_product_uid_string(self):
        """Test FindingIdentifier validation rejects empty string for metadata_product_uid"""
        with pytest.raises(ValidationError) as exc_info:
            FindingIdentifier(
                cloud_account_uid="123456789012",
                finding_info_uid="finding-1",
                metadata_product_uid=""  # Empty string not allowed
            )
        assert "cannot be empty string" in str(exc_info.value)

    def test_finding_identifier_with_none_product_uid(self):
        """Test FindingIdentifier accepts None for metadata_product_uid"""
        identifier = FindingIdentifier(
            cloud_account_uid="123456789012",
            finding_info_uid="finding-1",
            metadata_product_uid=None  # None is acceptable
        )
        assert identifier.metadata_product_uid is None
        assert identifier.cloud_account_uid == "123456789012"

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
    def test_update_status_unprocessed_findings_string_identifier(self, mock_get_client):
        """Test UnprocessedFindings parsing when FindingIdentifier is a string"""
        mock_client = Mock()
        mock_client.batch_update_findings_v2.return_value = {
            "ProcessedFindings": [],
            "UnprocessedFindings": [
                {
                    "FindingIdentifier": "arn:aws:securityhub:us-east-1:123456789012:finding/abc123",
                    "ErrorCode": "NotFound",
                    "ErrorMessage": "Finding not found"
                }
            ]
        }
        mock_get_client.return_value = mock_client

        result = update_finding_status(
            UpdateFindingsV2Input(
                metadata_uids=["arn:aws:securityhub:us-east-1:123456789012:finding/abc123"],
                status_id=2,
            )
        )

        assert result["success"] is False
        assert result["unprocessed_count"] == 1
        assert len(result["unprocessed_findings"]) == 1
        # String identifier should be returned as-is (normalized)
        assert isinstance(result["unprocessed_findings"][0]["finding_identifier"], str)
        assert "arn:aws:securityhub" in result["unprocessed_findings"][0]["finding_identifier"]

    @patch("aws_securityhub_mcp_server.server.get_securityhub_client")
    def test_update_status_unprocessed_findings_dict_identifier(self, mock_get_client):
        """Test UnprocessedFindings parsing when FindingIdentifier is a dict (3-point ID)"""
        mock_client = Mock()
        mock_client.batch_update_findings_v2.return_value = {
            "ProcessedFindings": [],
            "UnprocessedFindings": [
                {
                    "FindingIdentifier": {
                        "CloudAccountUid": "123456789012",
                        "FindingInfoUid": "finding-1",
                        "MetadataProductUid": "arn:aws:securityhub:us-east-1::product/aws/securityhub"
                    },
                    "ErrorCode": "InvalidParameter",
                    "ErrorMessage": "Invalid status transition"
                }
            ]
        }
        mock_get_client.return_value = mock_client

        result = update_finding_status(
            UpdateFindingsV2Input(
                finding_identifiers=[
                    {
                        "cloud_account_uid": "123456789012",
                        "finding_info_uid": "finding-1",
                        "metadata_product_uid": "arn:aws:securityhub:us-east-1::product/aws/securityhub"
                    }
                ],
                status_id=2,
            )
        )

        assert result["success"] is False
        assert result["unprocessed_count"] == 1
        unprocessed = result["unprocessed_findings"][0]
        # Dict identifier should be normalized to slash-separated format
        assert "/" in unprocessed["finding_identifier"]
        assert "123456789012" in unprocessed["finding_identifier"]
        assert "finding-1" in unprocessed["finding_identifier"]


# ============================================================================
# Client Initialization Tests
# ============================================================================

class TestResolveRegion:
    """Test AWS region resolution and validation."""

    def test_resolve_region_with_explicit_value(self):
        """Returns explicit region when provided."""
        assert resolve_region("us-west-2") == "us-west-2"

    @patch.dict("os.environ", {"AWS_DEFAULT_REGION": "ap-northeast-1"}, clear=True)
    def test_resolve_region_empty_explicit_value_raises(self):
        """Empty explicit region should not silently fall back to environment."""
        with pytest.raises(ValueError) as exc_info:
            resolve_region("   ")
        assert "aws_region was provided but is empty" in str(exc_info.value)

    @patch.dict("os.environ", {"AWS_DEFAULT_REGION": "eu-west-1"}, clear=True)
    def test_resolve_region_falls_back_to_default_region_env(self):
        """Resolves region from AWS_DEFAULT_REGION when explicit value is absent."""
        assert resolve_region() == "eu-west-1"

    @patch.dict("os.environ", {}, clear=True)
    def test_resolve_region_rejects_non_basic_region_format(self):
        """Rejects non-basic partition region names not covered by this server."""
        with pytest.raises(ValueError) as exc_info:
            resolve_region("us-iso-east-1")
        assert "Invalid AWS region format" in str(exc_info.value)


class TestGetSecurityHubClient:
    """Test SecurityHub client initialization"""

    @patch("aws_securityhub_mcp_server.server.boto3.client")
    @patch.dict("os.environ", {"AWS_DEFAULT_REGION": "ap-southeast-2"}, clear=True)
    def test_client_with_default_region_env(self, mock_boto_client):
        """Test client initialization with AWS_DEFAULT_REGION"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        get_securityhub_client()

        mock_boto_client.assert_called_once_with("securityhub", region_name="ap-southeast-2")

    @patch("aws_securityhub_mcp_server.server.boto3.client")
    def test_client_with_custom_region(self, mock_boto_client):
        """Test client initialization with custom region"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        get_securityhub_client(region_name="us-west-2")

        mock_boto_client.assert_called_once_with("securityhub", region_name="us-west-2")

    @patch("aws_securityhub_mcp_server.server.boto3.client")
    @patch.dict("os.environ", {"AWS_REGION": "eu-west-1"}, clear=True)
    def test_client_with_aws_region_fallback(self, mock_boto_client):
        """Test client initialization with fallback region from AWS_REGION"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        get_securityhub_client()

        mock_boto_client.assert_called_once_with("securityhub", region_name="eu-west-1")

    @patch.dict("os.environ", {}, clear=True)
    def test_client_without_region_raises_validation_error(self):
        """Test client initialization fails if no region is provided."""
        with pytest.raises(ValueError):
            get_securityhub_client()

    @patch("aws_securityhub_mcp_server.server.boto3.client")
    @patch.dict("os.environ", {"AWS_DEFAULT_REGION": "eu-west-1"}, clear=True)
    def test_client_cache_reuses_same_region_client(self, mock_boto_client):
        """Test client cache reuse for the same region."""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        get_securityhub_client()
        get_securityhub_client()

        mock_boto_client.assert_called_once_with("securityhub", region_name="eu-west-1")

