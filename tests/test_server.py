"""Tests for AWS SecurityHub MCP Server"""
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from mcp_server.server import (
    get_security_hub_findings,
    update_finding_status,
    build_filters_v2,
    format_finding_for_llm,
    get_securityhub_client
)


class TestBuildFiltersV2:
    """Test filter building logic"""
    
    def test_build_filters_with_severities(self):
        """Test building filters with severity parameter"""
        filters = build_filters_v2(severities=['Critical', 'High'])
        
        assert 'SeverityLabel' in filters
        assert len(filters['SeverityLabel']['StringFilters']) == 2
        assert filters['SeverityLabel']['StringFilters'][0]['Value'] == 'Critical'
        assert filters['SeverityLabel']['StringFilters'][0]['Comparison'] == 'EQUALS'
    
    def test_build_filters_with_account_ids(self):
        """Test building filters with AWS account IDs"""
        filters = build_filters_v2(aws_account_ids=['123456789012', '210987654321'])
        
        assert 'AwsAccountId' in filters
        assert len(filters['AwsAccountId']['StringFilters']) == 2
    
    def test_build_filters_with_titles(self):
        """Test building filters with titles"""
        filters = build_filters_v2(titles=['EC2 Security Group allows unrestricted access'])
        
        assert 'Title' in filters
        assert len(filters['Title']['StringFilters']) == 1
    
    def test_build_filters_with_workflow_statuses(self):
        """Test building filters with workflow statuses"""
        filters = build_filters_v2(workflow_statuses=['NEW', 'NOTIFIED'])
        
        assert 'WorkflowStatus' in filters
        assert len(filters['WorkflowStatus']['StringFilters']) == 2
    
    def test_build_filters_combined(self):
        """Test building filters with multiple parameters"""
        filters = build_filters_v2(
            severities=['Critical'],
            workflow_statuses=['NEW'],
            aws_account_ids=['123456789012']
        )
        
        assert 'SeverityLabel' in filters
        assert 'WorkflowStatus' in filters
        assert 'AwsAccountId' in filters
    
    def test_build_filters_empty(self):
        """Test building filters with no parameters returns None"""
        filters = build_filters_v2()
        assert filters is None


class TestFormatFindingForLLM:
    """Test finding formatting logic"""
    
    def test_format_finding_basic(self):
        """Test basic finding formatting"""
        raw_finding = {
            'Id': 'arn:aws:securityhub:us-east-1:123456789012:finding/12345',
            'Title': 'Test Finding',
            'Description': 'Test description',
            'Severity': {'Label': 'CRITICAL'},
            'AwsAccountId': '123456789012',
            'Resources': [
                {
                    'Type': 'AwsEc2Instance',
                    'Id': 'i-1234567890abcdef0'
                }
            ],
            'Workflow': {'Status': 'NEW'},
            'Compliance': {'Status': 'FAILED'},
            'CreatedAt': '2024-01-01T00:00:00.000Z',
            'UpdatedAt': '2024-01-02T00:00:00.000Z',
            'ProductName': 'Security Hub',
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE']
        }
        
        formatted = format_finding_for_llm(raw_finding)
        
        assert formatted['uid'] == 'arn:aws:securityhub:us-east-1:123456789012:finding/12345'
        assert formatted['title'] == 'Test Finding'
        assert formatted['severity'] == 'CRITICAL'
        assert formatted['workflow_status'] == 'NEW'
        assert formatted['resource']['type'] == 'AwsEc2Instance'
    
    def test_format_finding_minimal(self):
        """Test formatting with minimal fields"""
        raw_finding = {
            'Id': 'test-id',
            'Title': 'Test'
        }
        
        formatted = format_finding_for_llm(raw_finding)
        
        assert formatted['uid'] == 'test-id'
        assert formatted['title'] == 'Test'
        assert formatted['severity'] is None


class TestGetSecurityHubFindings:
    """Test get_security_hub_findings tool"""
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_get_findings_success(self, mock_get_client):
        """Test successful findings retrieval"""
        # Mock boto3 client
        mock_client = Mock()
        mock_client.get_findings.return_value = {
            'Findings': [
                {
                    'Id': 'finding-1',
                    'Title': 'Test Finding 1',
                    'Severity': {'Label': 'HIGH'},
                    'AwsAccountId': '123456789012',
                    'Resources': [],
                    'Workflow': {'Status': 'NEW'}
                },
                {
                    'Id': 'finding-2',
                    'Title': 'Test Finding 2',
                    'Severity': {'Label': 'CRITICAL'},
                    'AwsAccountId': '123456789012',
                    'Resources': [],
                    'Workflow': {'Status': 'NEW'}
                }
            ],
            'NextToken': 'next-page-token'
        }
        mock_get_client.return_value = mock_client
        
        # Call the tool
        result = get_security_hub_findings(
            severities=['HIGH', 'CRITICAL'],
            max_results=20
        )
        
        # Verify results
        assert result['count'] == 2
        assert len(result['findings']) == 2
        assert result['next_token'] == 'next-page-token'
        assert result['findings'][0]['uid'] == 'finding-1'
        assert result['findings'][1]['severity'] == 'CRITICAL'
        
        # Verify boto3 client was called correctly
        mock_client.get_findings.assert_called_once()
        call_args = mock_client.get_findings.call_args[1]
        assert call_args['MaxResults'] == 20
        assert 'Filters' in call_args
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_get_findings_with_pagination(self, mock_get_client):
        """Test findings retrieval with pagination token"""
        mock_client = Mock()
        mock_client.get_findings.return_value = {
            'Findings': [],
        }
        mock_get_client.return_value = mock_client
        
        get_security_hub_findings(
            next_token='previous-token',
            max_results=50
        )
        
        call_args = mock_client.get_findings.call_args[1]
        assert call_args['NextToken'] == 'previous-token'
        assert call_args['MaxResults'] == 50
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_get_findings_invalid_max_results(self, mock_get_client):
        """Test error handling for invalid max_results"""
        result = get_security_hub_findings(max_results=200)
        
        assert result['error'] == 'ValidationError'
        assert 'must be between 1 and 100' in result['message']
        assert result['count'] == 0
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_get_findings_client_error(self, mock_get_client):
        """Test error handling for AWS ClientError"""
        mock_client = Mock()
        mock_client.get_findings.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'Access denied'}},
            'GetFindings'
        )
        mock_get_client.return_value = mock_client
        
        result = get_security_hub_findings()
        
        assert result['error'] == 'AccessDeniedException'
        assert result['message'] == 'Access denied'
        assert result['count'] == 0


class TestUpdateFindingStatus:
    """Test update_finding_status tool"""
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_update_status_success(self, mock_get_client):
        """Test successful status update"""
        mock_client = Mock()
        mock_client.batch_update_findings.return_value = {
            'ProcessedFindings': [
                {'Id': 'finding-1'},
                {'Id': 'finding-2'}
            ],
            'UnprocessedFindings': []
        }
        mock_get_client.return_value = mock_client
        
        result = update_finding_status(
            finding_uids=['finding-1', 'finding-2'],
            workflow_status='RESOLVED',
            note='Fixed the issue'
        )
        
        assert result['success'] is True
        assert result['processed_count'] == 2
        assert result['unprocessed_count'] == 0
        
        # Verify boto3 client call
        mock_client.batch_update_findings.assert_called_once()
        call_args = mock_client.batch_update_findings.call_args[1]
        assert call_args['Workflow']['Status'] == 'RESOLVED'
        assert call_args['Note']['Text'] == 'Fixed the issue'
        assert len(call_args['FindingIdentifiers']) == 2
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_update_status_partial_failure(self, mock_get_client):
        """Test partial failure in status update"""
        mock_client = Mock()
        mock_client.batch_update_findings.return_value = {
            'ProcessedFindings': [{'Id': 'finding-1'}],
            'UnprocessedFindings': [
                {
                    'FindingIdentifier': {'Id': 'finding-2'},
                    'ErrorCode': 'InvalidInput',
                    'ErrorMessage': 'Finding not found'
                }
            ]
        }
        mock_get_client.return_value = mock_client
        
        result = update_finding_status(
            finding_uids=['finding-1', 'finding-2'],
            workflow_status='RESOLVED'
        )
        
        assert result['success'] is False
        assert result['processed_count'] == 1
        assert result['unprocessed_count'] == 1
        assert 'unprocessed_findings' in result
        assert result['unprocessed_findings'][0]['error_code'] == 'InvalidInput'
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_update_status_invalid_workflow_status(self, mock_get_client):
        """Test validation error for invalid workflow status"""
        result = update_finding_status(
            finding_uids=['finding-1'],
            workflow_status='INVALID_STATUS'
        )
        
        assert result['success'] is False
        assert result['error'] == 'ValidationError'
        assert 'must be one of' in result['message']
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_update_status_empty_finding_uids(self, mock_get_client):
        """Test validation error for empty finding_uids"""
        result = update_finding_status(
            finding_uids=[],
            workflow_status='RESOLVED'
        )
        
        assert result['success'] is False
        assert result['error'] == 'ValidationError'
        assert 'cannot be empty' in result['message']
    
    @patch('mcp_server.server.get_securityhub_client')
    def test_update_status_client_error(self, mock_get_client):
        """Test error handling for AWS ClientError"""
        mock_client = Mock()
        mock_client.batch_update_findings.side_effect = ClientError(
            {'Error': {'Code': 'ThrottlingException', 'Message': 'Rate exceeded'}},
            'BatchUpdateFindings'
        )
        mock_get_client.return_value = mock_client
        
        result = update_finding_status(
            finding_uids=['finding-1'],
            workflow_status='RESOLVED'
        )
        
        assert result['success'] is False
        assert result['error'] == 'ThrottlingException'
        assert result['processed_count'] == 0


class TestGetSecurityHubClient:
    """Test SecurityHub client initialization"""
    
    @patch('mcp_server.server.boto3.client')
    def test_client_with_default_region(self, mock_boto_client):
        """Test client initialization with default region"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        get_securityhub_client()
        
        mock_boto_client.assert_called_once_with('securityhub', region_name='ap-northeast-1')
    
    @patch('mcp_server.server.boto3.client')
    def test_client_with_custom_region(self, mock_boto_client):
        """Test client initialization with custom region"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        get_securityhub_client(region_name='us-west-2')
        
        mock_boto_client.assert_called_once_with('securityhub', region_name='us-west-2')
    
    @patch('mcp_server.server.boto3.client')
    @patch.dict('os.environ', {'AWS_DEFAULT_REGION': 'eu-west-1'})
    def test_client_with_env_region(self, mock_boto_client):
        """Test client initialization with region from environment"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        get_securityhub_client()
        
        mock_boto_client.assert_called_once_with('securityhub', region_name='eu-west-1')
