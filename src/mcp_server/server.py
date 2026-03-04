"""AWS SecurityHub MCP Server with V2 API"""
import logging
import os
from typing import Optional, Dict, Any, List
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator
import boto3
from botocore.exceptions import ClientError
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("aws-securityhub-server")


# ============================================================================
# Pydantic Models for Input Validation
# ============================================================================

class SeverityEnum(str, Enum):
    """Valid severity levels per OCSF"""
    FATAL = "Fatal"
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class GetFindingsInput(BaseModel):
    """Input schema for get_security_hub_findings"""
    aws_region: Optional[str] = Field(
        default=None,
        description="AWS region (default: AWS_DEFAULT_REGION or ap-northeast-1)"
    )
    severities: Optional[List[SeverityEnum]] = Field(
        default=None,
        description="Filter by severity levels"
    )
    aws_account_ids: Optional[List[str]] = Field(
        default=None,
        description="Filter by AWS account IDs (12-digit format)"
    )
    titles: Optional[List[str]] = Field(
        default=None,
        description="Filter by Finding titles (prefix match)"
    )
    status_ids: Optional[List[int]] = Field(
        default=None,
        description="Filter by status IDs (0-6, 99)"
    )
    max_results: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum results (1-100)"
    )
    next_token: Optional[str] = Field(
        default=None,
        description="Pagination token"
    )

    @field_validator("aws_account_ids")
    @classmethod
    def validate_account_ids(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate AWS account IDs are 12 digits"""
        if v is None:
            return v
        for account_id in v:
            if not account_id.isdigit() or len(account_id) != 12:
                raise ValueError(f"Account ID must be 12 digits, got: {account_id}")
        return v

    @field_validator("status_ids")
    @classmethod
    def validate_status_ids(cls, v: Optional[List[int]]) -> Optional[List[int]]:
        """Validate status IDs are in valid range"""
        if v is None:
            return v
        valid_ids = {0, 1, 2, 3, 4, 5, 6, 99}
        for status_id in v:
            if status_id not in valid_ids:
                raise ValueError(f"Status ID must be one of {valid_ids}, got: {status_id}")
        return v


class FindingIdentifier(BaseModel):
    """3-point identifier for batch_update_findings_v2"""
    cloud_account_uid: str = Field(description="Cloud account UID")
    finding_info_uid: str = Field(description="Finding info UID")
    metadata_product_uid: str = Field(description="Metadata product UID")


class UpdateFindingsV2Input(BaseModel):
    """Input schema for update_finding_status"""
    aws_region: Optional[str] = Field(
        default=None,
        description="AWS region (default: AWS_DEFAULT_REGION or ap-northeast-1)"
    )
    metadata_uids: Optional[List[str]] = Field(
        default=None,
        description="Metadata UID list (mutually exclusive with finding_identifiers)"
    )
    finding_identifiers: Optional[List[FindingIdentifier]] = Field(
        default=None,
        description="3-point identifier list (mutually exclusive with metadata_uids)"
    )
    status_id: int = Field(
        description="Target status ID (0-6, 99)"
    )
    comment: Optional[str] = Field(
        default=None,
        description="Status change reason"
    )

    @field_validator("status_id")
    @classmethod
    def validate_status_id(cls, v: int) -> int:
        """Validate status ID is in valid range"""
        valid_ids = {0, 1, 2, 3, 4, 5, 6, 99}
        if v not in valid_ids:
            raise ValueError(f"Status ID must be one of {valid_ids}, got: {v}")
        return v

    @model_validator(mode="after")
    def validate_identifiers_exclusive(self) -> "UpdateFindingsV2Input":
        """Ensure metadata_uids and finding_identifiers are mutually exclusive"""
        if self.metadata_uids and self.finding_identifiers:
            raise ValueError(
                "metadata_uids and finding_identifiers are mutually exclusive; "
                "specify only one"
            )
        if not self.metadata_uids and not self.finding_identifiers:
            raise ValueError(
                "Either metadata_uids or finding_identifiers must be specified"
            )
        return self


# ============================================================================
# AWS SecurityHub Client & Helper Functions
# ============================================================================

def get_securityhub_client(region_name: Optional[str] = None):
    """Initialize and return a SecurityHub boto3 client (V2 API)"""
    if region_name is None:
        region_name = os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1")
    
    try:
        client = boto3.client("securityhub", region_name=region_name)
        logger.info(f"Initialized SecurityHub client for region: {region_name}")
        return client
    except Exception as e:
        logger.error(f"Failed to initialize SecurityHub client: {e}")
        raise


def build_composite_filters_v2(
    severities: Optional[List[str]] = None,
    aws_account_ids: Optional[List[str]] = None,
    titles: Optional[List[str]] = None,
    status_ids: Optional[List[int]] = None
) -> Optional[Dict[str, Any]]:
    """
    Build V2 CompositeFilters structure from simple parameters.
    
    Returns Filters dict with CompositeFilters array and CompositeOperator.
    Each parameter becomes a separate CompositeFilter with OR operator within.
    All CompositeFilters combined with AND (CompositeOperator).
    """
    composite_filters = []
    
    # Severity filter
    if severities:
        composite_filters.append({
            "StringFilters": [
                {"FieldName": "severity", "Value": sev, "Comparison": "EQUALS"}
                for sev in severities
            ],
            "Operator": "OR"
        })
    
    # AWS account ID filter
    if aws_account_ids:
        composite_filters.append({
            "StringFilters": [
                {"FieldName": "cloud.account.uid", "Value": acc_id, "Comparison": "EQUALS"}
                for acc_id in aws_account_ids
            ],
            "Operator": "OR"
        })
    
    # Title filter (prefix match)
    if titles:
        composite_filters.append({
            "StringFilters": [
                {"FieldName": "finding_info.title", "Value": title, "Comparison": "PREFIX"}
                for title in titles
            ],
            "Operator": "OR"
        })
    
    # Status ID filter (NumberFilters for integer comparison)
    if status_ids:
        composite_filters.append({
            "NumberFilters": [
                {"FieldName": "status_id", "Value": int(sid), "Comparison": "EQUALS"}
                for sid in status_ids
            ],
            "Operator": "OR"
        })
    
    if not composite_filters:
        return None
    
    return {
        "CompositeFilters": composite_filters,
        "CompositeOperator": "AND"
    }


def format_finding_for_response(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Format Finding from get_findings_v2 for LLM consumption"""
    resources = finding.get("Resources", [])
    resource = resources[0] if resources else {}
    
    return {
        "metadata_uid": finding.get("Id"),  # Full ARN-like ID
        "cloud_account_uid": finding.get("AwsAccountId"),
        "finding_info_uid": finding.get("FindingInfoUid", finding.get("Id")),  # Fallback to Id
        "metadata_product_uid": finding.get("ProductArn", ""),
        "title": finding.get("Title"),
        "description": finding.get("Description"),
        "severity": finding.get("Severity", {}).get("Label"),
        "status_id": finding.get("StatusId"),  # Integer status
        "created_at": finding.get("CreatedAt"),
        "updated_at": finding.get("UpdatedAt"),
        "resource_type": resource.get("Type"),
        "resource_id": resource.get("Id"),
    }


# ============================================================================
# MCP Tools
# ============================================================================

@mcp.tool()
def get_security_hub_findings(
    aws_region: Optional[str] = None,
    severities: Optional[List[str]] = None,
    aws_account_ids: Optional[List[str]] = None,
    titles: Optional[List[str]] = None,
    status_ids: Optional[List[int]] = None,
    max_results: int = 20,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve Security Hub Findings using V2 API with flexible filtering.
    
    This tool enables LLMs to search and analyze security findings from AWS Security Hub
    using the get_findings_v2 API with CompositeFilters for flexible filtering.
    
    Args:
        aws_region: AWS region to query (default: ap-northeast-1)
        severities: List of severity levels (Fatal, Critical, High, Medium, Low, Informational)
        aws_account_ids: List of AWS account IDs to filter (12-digit format)
        titles: List of Finding titles (prefix match)
        status_ids: List of status IDs to filter (0-6, 99)
        max_results: Maximum Findings to return (1-100, default: 20)
        next_token: Pagination token from previous response
    
    Returns:
        Dictionary containing:
        - findings: List of Finding objects with all required identifiers
        - next_token: Pagination token (if more results exist)
        - count: Number of Findings returned
        
    Example:
        # Get all Critical findings
        get_security_hub_findings(
            severities=['Critical'],
            max_results=50
        )
    """
    try:
        # Validate input
        input_data = GetFindingsInput(
            aws_region=aws_region,
            severities=severities,
            aws_account_ids=aws_account_ids,
            titles=titles,
            status_ids=status_ids,
            max_results=max_results,
            next_token=next_token
        )
        
        # Get client
        client = get_securityhub_client(input_data.aws_region)
        
        # Build filters
        filters = build_composite_filters_v2(
            severities=[s.value for s in input_data.severities] if input_data.severities else None,
            aws_account_ids=input_data.aws_account_ids,
            titles=input_data.titles,
            status_ids=input_data.status_ids
        )
        
        # Prepare API parameters
        params = {"MaxResults": input_data.max_results}
        if filters:
            params["Filters"] = filters
        if input_data.next_token:
            params["NextToken"] = input_data.next_token
        
        logger.info(f"Calling get_findings_v2 with max_results={input_data.max_results}")
        response = client.get_findings_v2(**params)
        
        # Format findings
        formatted_findings = [
            format_finding_for_response(f)
            for f in response.get("Findings", [])
        ]
        
        result = {
            "findings": formatted_findings,
            "count": len(formatted_findings)
        }
        
        if "NextToken" in response:
            result["next_token"] = response["NextToken"]
        
        logger.info(f"Retrieved {len(formatted_findings)} findings")
        return result
        
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            "error": "ValidationError",
            "message": str(e),
            "findings": [],
            "count": 0
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS ClientError: {error_code} - {error_message}")
        return {
            "error": error_code,
            "message": error_message,
            "findings": [],
            "count": 0
        }
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            "error": "UnexpectedError",
            "message": str(e),
            "findings": [],
            "count": 0
        }


@mcp.tool()
def update_finding_status(
    metadata_uids: Optional[List[str]] = None,
    finding_identifiers: Optional[List[Dict[str, str]]] = None,
    status_id: int = None,
    aws_region: Optional[str] = None,
    comment: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update Finding status using batch_update_findings_v2.
    
    This tool allows LLMs to update the status of security findings after analysis.
    Uses either metadata_uids OR finding_identifiers (mutually exclusive).
    
    Args:
        metadata_uids: List of metadata UIDs (from get_security_hub_findings)
                      Mutually exclusive with finding_identifiers
        finding_identifiers: List of 3-point identifiers (from get_security_hub_findings)
                            Each dict contains: cloud_account_uid, finding_info_uid, metadata_product_uid
                            Mutually exclusive with metadata_uids
        status_id: Target status ID (0-6, 99) - REQUIRED
        aws_region: AWS region (default: ap-northeast-1)
        comment: Reason for status change
    
    Returns:
        Dictionary containing:
        - success: Boolean indicating if all updates succeeded
        - processed_count: Number of successfully updated Findings
        - unprocessed_count: Number of failed updates
        - unprocessed_findings: List of failures (if any)
        
    Example:
        # Update using metadata UIDs
        update_finding_status(
            metadata_uids=['arn:aws:securityhub:...'],
            status_id=2,
            comment='Resolved by patching'
        )
    """
    try:
        # Validate input
        input_data = UpdateFindingsV2Input(
            aws_region=aws_region,
            metadata_uids=metadata_uids,
            finding_identifiers=[
                FindingIdentifier(**f) for f in (finding_identifiers or [])
            ] if finding_identifiers else None,
            status_id=status_id,
            comment=comment
        )
        
        # Get client
        client = get_securityhub_client(input_data.aws_region)
        
        # Prepare update parameters
        update_params = {"StatusId": input_data.status_id}
        
        if input_data.metadata_uids:
            update_params["MetadataUids"] = input_data.metadata_uids
            logger.info(f"Updating {len(input_data.metadata_uids)} findings by metadata_uids")
        else:
            update_params["FindingIdentifiers"] = [
                {
                    "CloudAccountUid": fi.cloud_account_uid,
                    "FindingInfoUid": fi.finding_info_uid,
                    "MetadataProductUid": fi.metadata_product_uid
                }
                for fi in input_data.finding_identifiers
            ]
            logger.info(f"Updating {len(input_data.finding_identifiers)} findings by identifiers")
        
        if input_data.comment:
            update_params["Comment"] = input_data.comment
        
        # Call batch_update_findings_v2
        response = client.batch_update_findings_v2(**update_params)
        
        processed_count = len(response.get("ProcessedFindings", []))
        unprocessed = response.get("UnprocessedFindings", [])
        unprocessed_count = len(unprocessed)
        
        result = {
            "success": unprocessed_count == 0,
            "processed_count": processed_count,
            "unprocessed_count": unprocessed_count
        }
        
        if unprocessed:
            result["unprocessed_findings"] = [
                {
                    "finding_identifier": item.get("FindingIdentifier", {}),
                    "error_code": item.get("ErrorCode"),
                    "error_message": item.get("ErrorMessage")
                }
                for item in unprocessed
            ]
        
        logger.info(f"Update complete: {processed_count} succeeded, {unprocessed_count} failed")
        return result
        
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            "success": False,
            "error": "ValidationError",
            "message": str(e),
            "processed_count": 0,
            "unprocessed_count": 0
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS ClientError: {error_code} - {error_message}")
        return {
            "success": False,
            "error": error_code,
            "message": error_message,
            "processed_count": 0,
            "unprocessed_count": 0
        }
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            "success": False,
            "error": "UnexpectedError",
            "message": str(e),
            "processed_count": 0,
            "unprocessed_count": 0
        }


def run():
    """Run the MCP server with stdio transport"""
    logger.info("Starting AWS SecurityHub MCP Server (V2 API)")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
