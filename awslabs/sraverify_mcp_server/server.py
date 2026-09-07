# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""awslabs sraverify MCP Server implementation."""

import sys
import warnings
import logging

# CRITICAL: Suppress all warnings and configure logging BEFORE any other imports
warnings.filterwarnings('ignore')

# Configure Python logging to be quiet
logging.basicConfig(level=logging.CRITICAL, stream=sys.stderr)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('sraverify').setLevel(logging.CRITICAL)

# Import loguru and configure it
from loguru import logger
logger.remove()  # Remove default handler
logger.add(sys.stderr, level="ERROR")  # Only log errors to stderr

# Import MCP and other dependencies
from mcp.server.fastmcp import FastMCP
from typing import Dict, Any, Optional
import boto3
from sraverify import SRAVerify

# CRITICAL: Reconfigure sraverify logger AFTER import to suppress all output
# The sraverify logger is configured at import time, so we need to override it
sraverify_logger = logging.getLogger('sraverify')
sraverify_logger.setLevel(logging.CRITICAL)
# Remove all handlers and add a null handler to completely silence it
sraverify_logger.handlers.clear()
sraverify_logger.addHandler(logging.NullHandler())
sraverify_logger.propagate = False

# Global instance for read-only operations (listing checks, services, etc.)
_default_sra = SRAVerify(debug=False)

def _get_sra_instance(
    role_arn: Optional[str] = None,
    region: Optional[str] = None,
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
    max_attempts: int | None = None,
    max_pool_connections: int | None = None,
) -> SRAVerify:
    """Create an SRAVerify instance with optional role assumption and region.

    Args:
        role_arn: Optional IAM role ARN to assume
        region: Optional AWS region to use
        connect_timeout: Optional boto3 connect timeout (seconds) forwarded to
            ``SRAVerify``. ``None`` uses the library's default Client_Config.
        read_timeout: Optional boto3 read timeout (seconds) forwarded to
            ``SRAVerify``. ``None`` uses the library's default Client_Config.
        max_attempts: Optional boto3 retry max attempts forwarded to
            ``SRAVerify``. ``None`` uses the library's default Client_Config.
        max_pool_connections: Optional boto3 max pool connections forwarded to
            ``SRAVerify``. ``None`` uses the library's default Client_Config.

    Returns:
        SRAVerify instance configured with the specified credentials, region,
        and optional Client_Config overrides.
    """
    timeout_kwargs = {
        'connect_timeout': connect_timeout,
        'read_timeout': read_timeout,
        'max_attempts': max_attempts,
        'max_pool_connections': max_pool_connections,
    }
    has_timeout_overrides = any(v is not None for v in timeout_kwargs.values())

    if not role_arn and not region and not has_timeout_overrides:
        return _default_sra

    # Create session with assumed role if specified
    if role_arn:
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='sraverify-mcp-session'
        )
        credentials = assumed_role['Credentials']

        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
    elif region:
        session = boto3.Session(region_name=region)
    else:
        session = boto3.Session()

    # Create SRAVerify instance with the session
    regions_list = [region] if region else None
    return SRAVerify(
        session=session,
        regions=regions_list,
        debug=False,
        **timeout_kwargs,
    )

mcp = FastMCP(
    'awslabs.sraverify-mcp-server',
    instructions=(
        'SRAVerify MCP server for AWS Security Reference Architecture compliance checks. '
        'This server provides tools to discover and RUN security checks directly via MCP tools. '
        'Available tools: '
        '1. list_checks_by_account_type(account_type) - List checks by account type (application, audit, log-archive, management, or all). '
        '2. list_services() - Get all AWS services supported by SRA Verify. '
        '3. list_checks_by_service(service) - List checks for a specific service (e.g., "GuardDuty", "Organizations"). '
        '4. describe_check(check_id) - Get detailed information about a specific check including requirements. '
        '5. run_check(check_id, audit_accounts, log_archive_accounts, role_arn, region) - EXECUTE a security check and return results. '
        'CRITICAL USAGE RULES: '
        '- When a user asks to verify or check something, ALWAYS use the run_check tool to execute the check directly. '
        '- NEVER suggest CLI commands like "sra-verify" or "sraverify" - those are NOT available in this context. '
        '- NEVER provide bash/shell commands - you have direct MCP tool access to run checks. '
        '- If you need information (like audit_accounts), ask the user, then immediately call run_check with that information. '
        '- The run_check tool will return actual findings - present those results to the user. '
        '- audit_accounts and log_archive_accounts must be provided as lists of strings: ["123456789012"]. '
        '- You can optionally specify role_arn to assume a role and region to target a specific region.'
    ),
    dependencies=['pydantic', 'loguru', 'boto3'],
)

@mcp.tool(name='list_checks_by_account_type')
async def list_checks_by_account_type(account_type: str = 'all') -> Dict[str, Dict[str, str]]:
    """Get all checks filtered by account type.

    Args:
        account_type: Filter by account type ('application', 'audit', 'log-archive', 'management', 'all')

    Returns:
        Dictionary mapping check IDs to check information
    """
    checks = _default_sra.get_available_checks(account_type)
    return checks

@mcp.tool(name='list_services')
async def list_services() -> Dict[str, Any]:
    """Get all services supported by SRA Verify.

    Returns:
        Dictionary containing the list of supported services.
    """
    services = _default_sra.get_available_services()
    return {"services": services}

@mcp.tool(name='list_checks_by_service')
async def list_checks_by_service(service: str) -> Dict[str, Dict[str, str]]:
    """Get all checks filtered by service.

    Args:
        service: Filter by service name (e.g., 'GuardDuty', 'CloudTrail', 'IAM')

    Returns:
        Dictionary mapping check IDs to check information for the specified service
    """
    # Get all checks
    all_checks = _default_sra.get_available_checks('all')

    # Filter by service if specified
    if service and service.lower() != 'all':
        filtered_checks = {
            check_id: check_info
            for check_id, check_info in all_checks.items()
            if check_info.get('service', '').lower() == service.lower()
        }
        return filtered_checks

    return all_checks

@mcp.tool(name='describe_check')
async def describe_check(check_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific check.

    Args:
        check_id: The check ID (e.g., 'SRA-GUARDDUTY-01')

    Returns:
        Dictionary with check details including name, service, account_type, description, severity
    """
    all_checks = _default_sra.get_available_checks('all')
    check_info = all_checks.get(check_id)

    if not check_info:
        return {
            'error': f'Check {check_id} not found',
            'available_checks_count': len(all_checks)
        }

    return {
        'check_id': check_id,
        **check_info
    }

@mcp.tool(name='run_check')
async def run_check(
    check_id: str,
    audit_accounts: list[str] | None = None,
    log_archive_accounts: list[str] | None = None,
    role_arn: str | None = None,
    region: str | None = None,
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
    max_attempts: int | None = None,
    max_pool_connections: int | None = None,
) -> dict[str, Any]:
    """Run a security check and return results.

    Args:
        check_id: The check ID to run (e.g., 'SRA-GUARDDUTY-01')
        audit_accounts: List of AWS accounts used for Audit/Security Tooling (required for some checks)
        log_archive_accounts: List of AWS accounts used for Logging (required for some checks)
        role_arn: Optional IAM role ARN to assume for running the check
        region: Optional AWS region to target (if not specified, checks all regions)
        connect_timeout: Optional boto3 connect timeout in seconds. When omitted,
            the library's default Client_Config value is used.
        read_timeout: Optional boto3 read timeout in seconds. When omitted, the
            library's default Client_Config value is used.
        max_attempts: Optional boto3 retry max attempts. When omitted, the
            library's default Client_Config value is used.
        max_pool_connections: Optional boto3 max pool connections. When omitted,
            the library's default Client_Config value is used.

    Returns:
        Dict with findings and summary, or error if check fails.
    """
    # Get check info to provide better error messages
    check_info = _default_sra.get_available_checks('all').get(check_id)
    if not check_info:
        return {
            'status': 'failed',
            'check_id': check_id,
            'error': f'Check {check_id} not found. Use list_checks_by_account_type or list_checks_by_service to see available checks.',
        }

    # Check if this is an audit or log-archive account type check that might need account IDs
    account_type = check_info.get('account_type', '')
    if account_type == 'audit' and not audit_accounts:
        return {
            'status': 'failed',
            'check_id': check_id,
            'error': f'This check ({check_id}) requires audit_accounts parameter. Please ask the user for their audit account ID(s) and retry with audit_accounts=["account-id"].',
            'check_info': check_info,
        }

    if account_type == 'log-archive' and not log_archive_accounts:
        return {
            'status': 'failed',
            'check_id': check_id,
            'error': f'This check ({check_id}) requires log_archive_accounts parameter. Please ask the user for their log archive account ID(s) and retry with log_archive_accounts=["account-id"].',
            'check_info': check_info,
        }

    try:
        # Get SRAVerify instance with optional role, region, and Client_Config overrides.
        # Per-scan isolation is now provided by ScanContext, so cache clearing is
        # no longer required between invocations.
        sra_instance = _get_sra_instance(
            role_arn=role_arn,
            region=region,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            max_attempts=max_attempts,
            max_pool_connections=max_pool_connections,
        )

        findings = sra_instance.run_checks(
            check_id=check_id,
            audit_accounts=audit_accounts,
            log_archive_accounts=log_archive_accounts,
        )

        total = len(findings)
        passed = sum(1 for f in findings if f.get('Status') == 'PASS')
        failed = sum(1 for f in findings if f.get('Status') == 'FAIL')
        errors = sum(1 for f in findings if f.get('Status') == 'ERROR')

        return {
            'status': 'completed',
            'check_id': check_id,
            'findings': findings,
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'errors': errors,
            },
            'role_arn': role_arn,
            'region': region,
        }

    except Exception as e:
        logger.error(f'Check {check_id} failed: {e}')
        return {
            'status': 'failed',
            'check_id': check_id,
            'error': str(e),
            'role_arn': role_arn,
            'region': region,
        }


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == '__main__':
    main()
