"""Main MCP Server for AWS SecurityHub - V2 API Implementation"""
import logging
import os
from typing import Optional, Dict, Any, List
import boto3
from botocore.exceptions import ClientError
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("aws-securityhub-server")


def get_securityhub_client(region_name: Optional[str] = None):
    """
    Initialize and return a SecurityHub boto3 client.
    
    Uses standard AWS authentication from environment variables:
    - AWS_PROFILE
    - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
    - AWS_SESSION_TOKEN (if using temporary credentials)
    
    Args:
        region_name: AWS region (defaults to ap-northeast-1 if not specified)
        
    Returns:
        boto3 SecurityHub client
    """
    if region_name is None:
        region_name = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-1')
    
    try:
        client = boto3.client('securityhub', region_name=region_name)
        logger.info(f"Initialized SecurityHub client for region: {region_name}")
        return client
    except Exception as e:
        logger.error(f"Failed to initialize SecurityHub client: {e}")
        raise


def build_filters_v2(
    severities: Optional[List[str]] = None,
    aws_account_ids: Optional[List[str]] = None,
    titles: Optional[List[str]] = None,
    workflow_statuses: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Build V2 API Filters structure from simple parameters.
    
    Converts user-friendly parameters into the complex CompositeFilters structure
    required by get_findings_v2 API. Multiple conditions are combined with AND logic.
    
    Args:
        severities: List of severity levels (e.g., ['Critical', 'High'])
        aws_account_ids: List of AWS account IDs
        titles: List of finding titles to match
        workflow_statuses: List of workflow statuses (e.g., ['NEW', 'NOTIFIED'])
        
    Returns:
        Filters dictionary for get_findings_v2, or None if no filters provided
    """
    filters = {}
    
    # OCSF field mapping for severities
    if severities:
        filters['SeverityLabel'] = {
            'StringFilters': [
                {'Value': severity, 'Comparison': 'EQUALS'}
                for severity in severities
            ]
        }
    
    # OCSF field mapping for AWS account IDs
    if aws_account_ids:
        filters['AwsAccountId'] = {
            'StringFilters': [
                {'Value': account_id, 'Comparison': 'EQUALS'}
                for account_id in aws_account_ids
            ]
        }
    
    # Title matching
    if titles:
        filters['Title'] = {
            'StringFilters': [
                {'Value': title, 'Comparison': 'EQUALS'}
                for title in titles
            ]
        }
    
    # Workflow status mapping
    if workflow_statuses:
        filters['WorkflowStatus'] = {
            'StringFilters': [
                {'Value': status, 'Comparison': 'EQUALS'}
                for status in workflow_statuses
            ]
        }
    
    return filters if filters else None


def format_finding_for_llm(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and format key OCSF fields from a finding for LLM consumption.
    
    Args:
        finding: Raw finding dictionary from get_findings_v2
        
    Returns:
        Simplified finding dictionary with essential fields
    """
    return {
        'uid': finding.get('Id'),
        'title': finding.get('Title'),
        'description': finding.get('Description'),
        'severity': finding.get('Severity', {}).get('Label'),
        'aws_account_id': finding.get('AwsAccountId'),
        'resource': {
            'type': finding.get('Resources', [{}])[0].get('Type') if finding.get('Resources') else None,
            'id': finding.get('Resources', [{}])[0].get('Id') if finding.get('Resources') else None,
        },
        'workflow_status': finding.get('Workflow', {}).get('Status'),
        'compliance_status': finding.get('Compliance', {}).get('Status'),
        'created_at': finding.get('CreatedAt'),
        'updated_at': finding.get('UpdatedAt'),
        'product_name': finding.get('ProductName'),
        'types': finding.get('Types', []),
    }


@mcp.tool()
def get_security_hub_findings(
    aws_region: Optional[str] = None,
    severities: Optional[List[str]] = None,
    aws_account_ids: Optional[List[str]] = None,
    titles: Optional[List[str]] = None,
    workflow_statuses: Optional[List[str]] = None,
    max_results: int = 20,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve Security Hub findings using flexible filtering (V2 API).
    
    This tool enables LLMs to search and analyze security alerts from AWS Security Hub.
    It uses the get_findings_v2 API which supports OCSF (Open Cybersecurity Schema Framework)
    format and provides more flexible filtering capabilities.
    
    Common use cases:
    - Find all Critical and High severity findings
    - Search for findings in specific AWS accounts
    - Filter by workflow status (NEW, NOTIFIED, RESOLVED, SUPPRESSED)
    - Retrieve findings with specific titles
    
    Args:
        aws_region: AWS region to query (default: ap-northeast-1)
        severities: Filter by severity levels. Valid values: 
                   Fatal, Critical, High, Medium, Low, Informational
        aws_account_ids: Filter by AWS account IDs (e.g., ['123456789012'])
        titles: Filter by exact finding titles
        workflow_statuses: Filter by workflow status. Valid values:
                          NEW, NOTIFIED, RESOLVED, SUPPRESSED
        max_results: Maximum findings to return (default: 20, max: 100)
        next_token: Pagination token from a previous response
        
    Returns:
        Dictionary containing:
        - findings: List of simplified finding objects with OCSF fields
        - next_token: Token for retrieving the next page (if available)
        - count: Number of findings returned
        
    Raises:
        ClientError: If AWS API call fails (e.g., permissions, invalid region)
        ValueError: If parameters are invalid (e.g., max_results > 100)
    
    Example:
        # Get all Critical findings that are not yet resolved
        get_security_hub_findings(
            severities=['Critical'],
            workflow_statuses=['NEW', 'NOTIFIED'],
            max_results=50
        )
    """
    try:
        # Validate max_results
        if max_results < 1 or max_results > 100:
            raise ValueError("max_results must be between 1 and 100")
        
        # Initialize SecurityHub client
        client = get_securityhub_client(aws_region)
        
        # Build filters
        filters = build_filters_v2(
            severities=severities,
            aws_account_ids=aws_account_ids,
            titles=titles,
            workflow_statuses=workflow_statuses
        )
        
        # Prepare API call parameters
        params = {'MaxResults': max_results}
        if filters:
            params['Filters'] = filters
        if next_token:
            params['NextToken'] = next_token
        
        # Call get_findings_v2
        logger.info(f"Calling get_findings_v2 with params: {params}")
        response = client.get_findings(**params)
        
        # Format findings for LLM
        formatted_findings = [
            format_finding_for_llm(finding)
            for finding in response.get('Findings', [])
        ]
        
        result = {
            'findings': formatted_findings,
            'count': len(formatted_findings),
        }
        
        # Include next token if available
        if 'NextToken' in response:
            result['next_token'] = response['NextToken']
        
        logger.info(f"Successfully retrieved {len(formatted_findings)} findings")
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"AWS ClientError: {error_code} - {error_message}")
        return {
            'error': error_code,
            'message': error_message,
            'findings': [],
            'count': 0
        }
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            'error': 'ValidationError',
            'message': str(e),
            'findings': [],
            'count': 0
        }
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'error': 'UnexpectedError',
            'message': str(e),
            'findings': [],
            'count': 0
        }


@mcp.tool()
def update_finding_status(
    finding_uids: List[str],
    workflow_status: str,
    aws_region: Optional[str] = None,
    note: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update the workflow status of Security Hub findings (V2 API).
    
    This tool allows LLMs to update the status of security findings after analysis
    or remediation. It uses batch operations to efficiently update multiple findings.
    
    Common use cases:
    - Mark findings as RESOLVED after remediation
    - Suppress false positives with SUPPRESSED status
    - Mark findings as NOTIFIED after alerting relevant teams
    
    Args:
        finding_uids: List of finding IDs (UIDs) to update. These are the 'uid' or 'Id'
                     fields returned by get_security_hub_findings.
        workflow_status: New workflow status. Valid values:
                        NEW, NOTIFIED, RESOLVED, SUPPRESSED
        aws_region: AWS region (default: ap-northeast-1)
        note: Optional note explaining the status change (e.g., reason for suppression)
        
    Returns:
        Dictionary containing:
        - processed_count: Number of successfully updated findings
        - unprocessed_count: Number of failed updates
        - unprocessed_findings: List of findings that failed with error details
        - success: Boolean indicating if all updates succeeded
        
    Raises:
        ClientError: If AWS API call fails
        ValueError: If parameters are invalid
        
    Example:
        # Mark findings as resolved with a note
        update_finding_status(
            finding_uids=['arn:aws:securityhub:...'],
            workflow_status='RESOLVED',
            note='Fixed by applying security patch KB2023-001'
        )
    """
    try:
        # Validate inputs
        if not finding_uids:
            raise ValueError("finding_uids cannot be empty")
        
        valid_statuses = ['NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED']
        if workflow_status not in valid_statuses:
            raise ValueError(f"workflow_status must be one of: {', '.join(valid_statuses)}")
        
        # Initialize SecurityHub client
        client = get_securityhub_client(aws_region)
        
        # Prepare update parameters
        update_params = {
            'FindingIdentifiers': [
                {'Id': uid} for uid in finding_uids
            ],
            'Workflow': {'Status': workflow_status}
        }
        
        # Add note if provided
        if note:
            update_params['Note'] = {
                'Text': note,
                'UpdatedBy': 'mcp-securityhub-server'
            }
        
        # Call batch_update_findings
        logger.info(f"Updating {len(finding_uids)} findings to status: {workflow_status}")
        response = client.batch_update_findings(**update_params)
        
        processed_count = len(response.get('ProcessedFindings', []))
        unprocessed = response.get('UnprocessedFindings', [])
        unprocessed_count = len(unprocessed)
        
        result = {
            'success': unprocessed_count == 0,
            'processed_count': processed_count,
            'unprocessed_count': unprocessed_count,
        }
        
        # Include error details for failed updates
        if unprocessed:
            result['unprocessed_findings'] = [
                {
                    'finding_id': item['FindingIdentifier']['Id'],
                    'error_code': item['ErrorCode'],
                    'error_message': item['ErrorMessage']
                }
                for item in unprocessed
            ]
        
        logger.info(f"Update complete: {processed_count} succeeded, {unprocessed_count} failed")
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"AWS ClientError: {error_code} - {error_message}")
        return {
            'success': False,
            'error': error_code,
            'message': error_message,
            'processed_count': 0,
            'unprocessed_count': len(finding_uids)
        }
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            'success': False,
            'error': 'ValidationError',
            'message': str(e),
            'processed_count': 0,
            'unprocessed_count': len(finding_uids) if finding_uids else 0
        }
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'success': False,
            'error': 'UnexpectedError',
            'message': str(e),
            'processed_count': 0,
            'unprocessed_count': len(finding_uids) if finding_uids else 0
        }


def run():
    """Run the MCP server with stdio transport"""
    logger.info("Starting AWS SecurityHub MCP Server (V2 API)")
    mcp.run(transport='stdio')


if __name__ == "__main__":
    run()
