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

import anyio
import boto3
import functools
import logging
import sys
import warnings
from awslabs.sraverify_mcp_server import __version__
from loguru import logger
from mcp.server.mcpserver import MCPServer
from sraverify import SRAVerify
from sraverify.core.errors import (
    NoChecksSelectedError,
    PartitionUndeterminedError,
    SRAVerifyError,
    UnknownCheckError,
)
from sraverify.core.regions import resolve_scan_region
from typing import Any, Dict


# stdout carries the MCP stdio protocol; everything else goes to stderr, and only
# when it matters. This runs before MCPServer is constructed, so the root logger
# already has a handler when the SDK is set up.
warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.CRITICAL, stream=sys.stderr)
for _name in ('boto3', 'botocore', 'urllib3', 'sraverify'):
    logging.getLogger(_name).setLevel(logging.CRITICAL)
logger.remove()
logger.add(sys.stderr, level='ERROR')

# Inventory only (listing checks, services, metadata, check selection). These calls
# read class metadata and make no AWS call. Scans never use this instance: every
# scan builds a fresh boto3 session and SRAVerify in _scan.
_default_sra = SRAVerify()

# Session name for AssumeRole; keeps agent-driven scans distinct in CloudTrail from
# CLI scans ('sraverify-session').
_ROLE_SESSION_NAME = 'sraverify-mcp-session'

_VALID_ACCOUNT_TYPES = ['application', 'audit', 'log-archive', 'management', 'all']
_VALID_STATUSES = ('PASS', 'FAIL', 'ERROR')

# Static scan of sraverify 0.3.3 check sources (which checks read the account lists);
# replace with CheckMeta fields once upstream adds them. A check needs the list when
# its account type matches OR it is in the set (see _needs_audit_accounts).
_READS_AUDIT_ACCOUNTS = frozenset(
    {
        'SRA-ACCESSANALYZER-03',
        'SRA-AUDITMANAGER-02',
        'SRA-CLOUDTRAIL-13',
        'SRA-CONFIG-08',
        'SRA-FIREWALLMANAGER-01',
        'SRA-GUARDDUTY-14',
        'SRA-IAM-04',
        'SRA-INSPECTOR-06',
        'SRA-INSPECTOR-07',
        'SRA-MACIE-06',
        'SRA-MACIE-07',
        'SRA-ORGANIZATIONS-08',
        'SRA-SECURITYHUB-07',
        'SRA-SECURITYHUB-08',
        'SRA-SECURITYHUB-15',
        'SRA-SECURITYINCIDENTRESPONSE-01',
        'SRA-SECURITYLAKE-16',
        'SRA-SECURITYLAKE-17',
    }
)
_READS_LOG_ARCHIVE_ACCOUNTS = frozenset(
    {
        'SRA-CLOUDTRAIL-11',
        'SRA-CONFIG-06',
        'SRA-MACIE-03',
        'SRA-ORGANIZATIONS-09',
        'SRA-SECURITYLAKE-15',
    }
)


def _needs_audit_accounts(check_id: str, account_type: str) -> bool:
    """Whether a check needs the audit_accounts input.

    Args:
        check_id: The check ID.
        account_type: The check's account type ('application', 'audit', ...).

    Returns:
        True for audit account-type checks and for checks that read the audit list.
    """
    return account_type == 'audit' or check_id in _READS_AUDIT_ACCOUNTS


def _needs_log_archive_accounts(check_id: str, account_type: str) -> bool:
    """Whether a check needs the log_archive_accounts input.

    Args:
        check_id: The check ID.
        account_type: The check's account type ('application', 'audit', ...).

    Returns:
        True for log-archive account-type checks and for checks that read the list.
    """
    return account_type == 'log-archive' or check_id in _READS_LOG_ARCHIVE_ACCOUNTS


def _partition_error_message(exc: PartitionUndeterminedError) -> str:
    """Explain a PartitionUndeterminedError in MCP tool terms (never CLI flags).

    Args:
        exc: The error raised by sraverify when it cannot resolve the scan Region.

    Returns:
        A message telling the agent which tool argument or server setting to provide.
    """
    if exc.reason == 'invalid':
        return (
            f'{exc.bad_value!r} is not an AWS Region name. '
            'Pass a Region name such as "us-east-1" as the region argument '
            '(or as the first value of regions).'
        )
    return (
        'No AWS Region could be determined, so the AWS partition is unknown. '
        'Pass the region argument (for example region="us-east-1") or a regions list, '
        "or set AWS_DEFAULT_REGION in the MCP server's env (or region = in the AWS "
        'profile it uses).'
    )


def _unknown_service_response(wanted: str) -> dict[str, Any]:
    """Build the response for a service name that matches no check.

    Args:
        wanted: The service name as supplied (stripped).

    Returns:
        A dict with 'error' and 'available_services', plus a 'hint' for the
        pre-0.3.2 'SecurityHub' name.
    """
    response: dict[str, Any] = {
        'error': f"No checks found for service '{wanted}'.",
        'available_services': _default_sra.get_available_services(),
    }
    if wanted.replace(' ', '').lower() == 'securityhub':
        response['hint'] = (
            "SRA Verify 0.3.2 split SecurityHub into 'Security Hub' and "
            "'Security Hub CSPM'. Call list_checks_by_service for each."
        )
    return response


def _no_checks_message(account_type: str, service: str | None) -> str:
    """Explain a NoChecksSelectedError in MCP tool terms (never CLI flags).

    Args:
        account_type: The account_type filter as applied.
        service: The service filter as applied, or None.

    Returns:
        A sentence naming the tool arguments that matched nothing.
    """
    parts = [f'account_type={account_type!r}']
    if service is not None:
        parts.append(f'service={service!r}')
    return (
        f'No checks matched {", ".join(parts)}. Use list_services and '
        'list_checks_by_account_type to see valid values.'
    )


def _failure(exc: Exception, base: dict[str, Any]) -> dict[str, Any]:
    """Map a scan exception to the tools' failed response shape.

    Args:
        exc: The exception raised while preparing or running the scan.
        base: The request-echo keys (check_id or service/account_type, role_arn,
            region, regions) to include in the response.

    Returns:
        ``{'status': 'failed', **base, 'error': ...}`` plus 'suggestions' for an
        unknown check ID.
    """
    result: dict[str, Any] = {'status': 'failed', **base}
    if isinstance(exc, PartitionUndeterminedError):
        result['error'] = _partition_error_message(exc)
    elif isinstance(exc, UnknownCheckError):
        result['error'] = str(exc)
        result['suggestions'] = exc.suggestions
    elif isinstance(exc, NoChecksSelectedError):
        account_type, service = (list(exc.args) + [None, None])[:2]
        result['error'] = _no_checks_message(str(account_type or 'all'), service)
    elif isinstance(exc, SRAVerifyError):
        result['error'] = str(exc)
    else:
        target = base.get('check_id') or f'service={base.get("service")!r}'
        logger.error(f'Check {target} failed: {exc}')
        result['error'] = str(exc)
    return result


def _normalize_regions(region: str | None, regions: list[str] | None) -> list[str] | None:
    """Merge the region and regions tool arguments into SRAVerify's regions list.

    Args:
        region: A single Region, 'all', or None.
        regions: A list of Regions, or None.

    Returns:
        The stripped, de-duplicated Regions in order, or None (all enabled Regions)
        when nothing is given or any value is 'all'.
    """
    values = ([region] if region is not None else []) + list(regions or [])
    result: list[str] = []
    for value in values:
        value = value.strip()
        if not value:
            continue
        if value.lower() == 'all':
            return None
        if value not in result:
            result.append(value)
    return result or None


def _build_session(role_arn: str | None, regions: list[str] | None) -> boto3.Session:
    """Build a fresh boto3 session, assuming role_arn in the scan's partition.

    Args:
        role_arn: Optional IAM role ARN to assume.
        regions: The normalized Regions list, or None.

    Returns:
        The base session, or a session with the assumed role's credentials whose
        Region is the Region STS was called in.

    Raises:
        PartitionUndeterminedError: role_arn was given and no Region is known.
            Raised before any STS call.
    """
    base = boto3.Session(region_name=regions[0] if regions else None)
    if not role_arn:
        return base

    # Same rule sraverify applies: the first explicit Region, else the session's.
    sts_region = resolve_scan_region(regions, base)
    credentials = base.client('sts', region_name=sts_region).assume_role(
        RoleArn=role_arn, RoleSessionName=_ROLE_SESSION_NAME
    )['Credentials']
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=sts_region,
    )


def _scan(
    *,
    role_arn: str | None,
    regions: list[str] | None,
    timeouts: dict[str, Any],
    audit_accounts: list[str] | None,
    log_archive_accounts: list[str] | None,
    account_type: str = 'all',
    service: str | None = None,
    check_id: str | None = None,
) -> tuple[str, list[dict[str, str]]]:
    """Run a scan synchronously. Called in a worker thread so the event loop stays free.

    Args:
        role_arn: Optional IAM role ARN to assume.
        regions: The normalized Regions list, or None for all enabled Regions.
        timeouts: connect_timeout/read_timeout/max_attempts/max_pool_connections
            overrides forwarded to SRAVerify (None keeps the library default).
        audit_accounts: Audit account IDs.
        log_archive_accounts: Log archive account IDs.
        account_type: Account type filter.
        service: Service filter.
        check_id: Check ID filter.

    Returns:
        The scan Region and the findings as rows.
    """
    session = _build_session(role_arn, regions)
    sra = SRAVerify(session=session, regions=regions, **timeouts)
    # Preflight: refuse an undetermined partition before any AWS call.
    scan_region = sra.resolve_scan_region()
    # to_row() keeps the wire format at the 16 CamelCase keys of Finding.FIELDS.
    rows = [
        f.to_row()
        for f in sra.run_checks(
            account_type=account_type,
            service=service,
            check_id=check_id,
            audit_accounts=audit_accounts,
            log_archive_accounts=log_archive_accounts,
        )
    ]
    return scan_region, rows


def _summarize(rows: list[dict[str, str]]) -> dict[str, int]:
    """Count findings by status.

    Args:
        rows: Findings as rows.

    Returns:
        total, passed, failed and errors counts.
    """
    return {
        'total': len(rows),
        'passed': sum(1 for r in rows if r.get('Status') == 'PASS'),
        'failed': sum(1 for r in rows if r.get('Status') == 'FAIL'),
        'errors': sum(1 for r in rows if r.get('Status') == 'ERROR'),
    }


_SERVICES = ', '.join(f'"{s}"' for s in _default_sra.get_available_services())

mcp = MCPServer(
    'awslabs.sraverify-mcp-server',
    # MCP SDK 2.x reports an empty serverInfo.version unless one is passed (1.x fell
    # back to the SDK's own version).
    version=__version__,
    instructions=(
        'SRAVerify MCP server for AWS Security Reference Architecture compliance checks. '
        'This server provides tools to discover and RUN security checks directly via MCP tools. '
        'Available tools: '
        '1. list_checks_by_account_type(account_type) - List checks by account type (application, audit, log-archive, management, or all). '
        '2. list_services() - Get all AWS services supported by SRA Verify. '
        '3. list_checks_by_service(service) - List checks for a specific service. '
        '4. describe_check(check_id) - Get detailed information about a check: logic, remediation, SRA references, '
        'and requires_audit_accounts / requires_log_archive_accounts, which say which account lists run_check needs. '
        '5. run_check(check_id, audit_accounts, log_archive_accounts, role_arn, region, regions) - EXECUTE one security check and return results. '
        '6. run_checks(service, account_type, audit_accounts, log_archive_accounts, role_arn, region, regions, include_status, max_findings) - '
        'EXECUTE every check for a service and/or account type in one scan; the preferred way to run a whole service or account type. '
        'It returns a summary, per-check counts, and FAIL/ERROR findings by default (include_status, max_findings). '
        'REGIONS: omitting region, or region="all", scans all enabled Regions, and works only when the MCP server env sets '
        'AWS_DEFAULT_REGION or the AWS profile sets a region. Otherwise pass region (one Region) or regions (a list; '
        'the first value sets the partition). On a "No AWS Region could be determined" error, ask the user for a Region and retry. '
        f'SERVICES (exact names for service): {_SERVICES}. '
        'SecurityHub is now two services: "Security Hub" and "Security Hub CSPM". '
        'CLI FLAGS IN FINDINGS: findings and remediation text may name sraverify CLI flags; map them to tool arguments: '
        '--regions -> region/regions, --audit-account -> audit_accounts, --log-archive-account -> log_archive_accounts, '
        '--role -> role_arn, --check -> check_id, --service/--account-type -> run_checks service/account_type, '
        "--profile -> the AWS_PROFILE env in the user's MCP config. "
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
    return {'services': services}


@mcp.tool(name='list_checks_by_service')
async def list_checks_by_service(service: str) -> dict[str, Any]:
    """Get all checks filtered by service.

    Args:
        service: Filter by service name (e.g., 'GuardDuty', 'CloudTrail', 'IAM'), or 'all'

    Returns:
        Dictionary mapping check IDs to check information for the specified service,
        or an error with available_services when no check matches.
    """
    all_checks = _default_sra.get_available_checks('all')

    wanted = (service or '').strip()
    if not wanted or wanted.lower() == 'all':
        return all_checks

    filtered_checks = {
        check_id: check_info
        for check_id, check_info in all_checks.items()
        if check_info.get('service', '').lower() == wanted.lower()
    }
    if not filtered_checks:
        return _unknown_service_response(wanted)
    return filtered_checks


@mcp.tool(name='describe_check')
async def describe_check(check_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific check.

    Args:
        check_id: The check ID (e.g., 'SRA-GUARDDUTY-01')

    Returns:
        Dictionary with check details including name, service, account_type, description,
        severity, check_logic, resource_type, remediation, sra_sections, additional_urls,
        requires_audit_accounts and requires_log_archive_accounts
    """
    check_id = check_id.strip()
    all_checks = _default_sra.get_available_checks('all')
    try:
        check_class = _default_sra.select_checks(check_id=check_id)[check_id]
    except UnknownCheckError as e:
        return {
            'error': f'Check {check_id} not found',
            'available_checks_count': len(all_checks),
            'suggestions': e.suggestions,
        }

    check_info = all_checks[check_id]
    meta = check_class.meta
    return {
        'check_id': check_id,
        **check_info,
        'check_logic': meta.check_logic,
        'resource_type': meta.resource_type,
        'remediation': {
            'text': meta.remediation.text,
            'cli': meta.remediation.cli,
            'console': meta.remediation.console,
        },
        'sra_sections': list(meta.sra_sections),
        'additional_urls': list(meta.additional_urls),
        'requires_audit_accounts': _needs_audit_accounts(check_id, check_info['account_type']),
        'requires_log_archive_accounts': _needs_log_archive_accounts(
            check_id, check_info['account_type']
        ),
    }


@mcp.tool(name='run_check')
async def run_check(
    check_id: str,
    audit_accounts: list[str] | None = None,
    log_archive_accounts: list[str] | None = None,
    role_arn: str | None = None,
    region: str | None = None,
    regions: list[str] | None = None,
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
        region: Optional AWS Region to target. Omitted or 'all' scans all enabled Regions,
            which needs AWS_DEFAULT_REGION in the server env or a region in the AWS profile.
        regions: Optional list of AWS Regions to target; merged with region. The first
            value sets the partition (and the Region the role is assumed in).
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
    check_id = check_id.strip()
    # Get check info to provide better error messages
    try:
        _default_sra.select_checks(check_id=check_id)
    except UnknownCheckError as e:
        return {
            'status': 'failed',
            'check_id': check_id,
            'error': f'Check {check_id} not found. Use list_checks_by_account_type or list_checks_by_service to see available checks.',
            'suggestions': e.suggestions,
        }
    check_info = _default_sra.get_available_checks('all')[check_id]

    # Ask for the account lists the check needs before scanning
    account_type = check_info.get('account_type', '')
    if _needs_audit_accounts(check_id, account_type) and not audit_accounts:
        return {
            'status': 'failed',
            'check_id': check_id,
            'error': f'This check ({check_id}) requires audit_accounts parameter. Please ask the user for their audit account ID(s) and retry with audit_accounts=["account-id"].',
            'check_info': check_info,
        }

    if _needs_log_archive_accounts(check_id, account_type) and not log_archive_accounts:
        return {
            'status': 'failed',
            'check_id': check_id,
            'error': f'This check ({check_id}) requires log_archive_accounts parameter. Please ask the user for their log archive account ID(s) and retry with log_archive_accounts=["account-id"].',
            'check_info': check_info,
        }

    normalized = _normalize_regions(region, regions)
    base: dict[str, Any] = {
        'check_id': check_id,
        'role_arn': role_arn,
        'region': region,
        'regions': normalized,
    }
    try:
        scan_region, findings = await anyio.to_thread.run_sync(
            functools.partial(
                _scan,
                role_arn=role_arn,
                regions=normalized,
                timeouts={
                    'connect_timeout': connect_timeout,
                    'read_timeout': read_timeout,
                    'max_attempts': max_attempts,
                    'max_pool_connections': max_pool_connections,
                },
                audit_accounts=audit_accounts,
                log_archive_accounts=log_archive_accounts,
                check_id=check_id,
            )
        )
    except Exception as e:
        return _failure(e, base)

    return {
        'status': 'completed',
        'check_id': check_id,
        'findings': findings,
        'summary': _summarize(findings),
        'role_arn': role_arn,
        'region': region,
        'regions': normalized,
        'scan_region': scan_region,
    }


@mcp.tool(name='run_checks')
async def run_checks(
    service: str | None = None,
    account_type: str = 'all',
    audit_accounts: list[str] | None = None,
    log_archive_accounts: list[str] | None = None,
    role_arn: str | None = None,
    region: str | None = None,
    regions: list[str] | None = None,
    include_status: list[str] | None = None,
    max_findings: int = 50,
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
    max_attempts: int | None = None,
    max_pool_connections: int | None = None,
) -> dict[str, Any]:
    """Run every check for a service and/or account type in one scan.

    Args:
        service: Service name (see list_services). Omitted or 'all' runs every service.
        account_type: 'application', 'audit', 'log-archive', 'management' or 'all'.
        audit_accounts: List of AWS accounts used for Audit/Security Tooling (required
            when any selected check needs it)
        log_archive_accounts: List of AWS accounts used for Logging (required when any
            selected check needs it)
        role_arn: Optional IAM role ARN to assume for running the checks
        region: Optional AWS Region to target. Omitted or 'all' scans all enabled Regions,
            which needs AWS_DEFAULT_REGION in the server env or a region in the AWS profile.
        regions: Optional list of AWS Regions to target; merged with region. The first
            value sets the partition (and the Region the role is assumed in).
        include_status: Finding statuses to return (PASS, FAIL, ERROR). Defaults to
            FAIL and ERROR. Summary counts always cover every finding.
        max_findings: Maximum number of findings to return (>= 0). Defaults to 50.
        connect_timeout: Optional boto3 connect timeout in seconds.
        read_timeout: Optional boto3 read timeout in seconds.
        max_attempts: Optional boto3 retry max attempts.
        max_pool_connections: Optional boto3 max pool connections.

    Returns:
        Dict with summary, per-check counts and filtered findings, or an error.
    """
    wanted = (service or '').strip()
    service_filter = None if not wanted or wanted.lower() == 'all' else wanted
    account_type = (account_type or 'all').strip().lower()
    normalized = _normalize_regions(region, regions)
    base: dict[str, Any] = {
        'service': service_filter,
        'account_type': account_type,
        'role_arn': role_arn,
        'region': region,
        'regions': normalized,
    }

    statuses = (
        ['FAIL', 'ERROR']
        if include_status is None
        else [s.strip().upper() for s in include_status]
    )
    invalid = [s for s in statuses if s not in _VALID_STATUSES]
    if invalid:
        return {
            'status': 'failed',
            **base,
            'error': f'Invalid include_status value(s) {invalid}. Use any of {list(_VALID_STATUSES)}.',
        }
    if max_findings < 0:
        return {
            'status': 'failed',
            **base,
            'error': f'max_findings must be 0 or greater, got {max_findings}.',
        }

    try:
        selected = _default_sra.select_checks(account_type=account_type, service=service_filter)
    except NoChecksSelectedError:
        known = {s.lower() for s in _default_sra.get_available_services()}
        if service_filter is not None and service_filter.lower() not in known:
            details = _unknown_service_response(service_filter)
        else:
            details = {
                'error': _no_checks_message(account_type, service_filter),
                'available_services': _default_sra.get_available_services(),
            }
        return {
            'status': 'failed',
            **base,
            **details,
            'valid_account_types': _VALID_ACCOUNT_TYPES,
        }

    need_audit = sorted(
        cid
        for cid, cls in selected.items()
        if _needs_audit_accounts(cid, cls.meta.account_type.value)
    )
    need_log = sorted(
        cid
        for cid, cls in selected.items()
        if _needs_log_archive_accounts(cid, cls.meta.account_type.value)
    )
    missing: list[str] = []
    gate: dict[str, Any] = {}
    if need_audit and not audit_accounts:
        missing.append('audit_accounts')
        gate['checks_requiring_audit_accounts'] = need_audit
    if need_log and not log_archive_accounts:
        missing.append('log_archive_accounts')
        gate['checks_requiring_log_archive_accounts'] = need_log
    if missing:
        asks = {
            'audit_accounts': 'audit account ID(s)',
            'log_archive_accounts': 'log archive account ID(s)',
        }
        return {
            'status': 'failed',
            **base,
            'error': (
                f'The selected checks require {" and ".join(missing)}. Please ask the user for '
                f'their {" and ".join(asks[m] for m in missing)} and retry with '
                + ', '.join(f'{m}=["account-id"]' for m in missing)
                + '.'
            ),
            **gate,
        }

    try:
        scan_region, rows = await anyio.to_thread.run_sync(
            functools.partial(
                _scan,
                role_arn=role_arn,
                regions=normalized,
                timeouts={
                    'connect_timeout': connect_timeout,
                    'read_timeout': read_timeout,
                    'max_attempts': max_attempts,
                    'max_pool_connections': max_pool_connections,
                },
                audit_accounts=audit_accounts,
                log_archive_accounts=log_archive_accounts,
                account_type=account_type,
                service=service_filter,
            )
        )
    except Exception as e:
        return _failure(e, base)

    checks_run = sorted(selected)
    matched = [r for r in rows if r.get('Status') in statuses]
    returned = matched[:max_findings]
    return {
        'status': 'completed',
        'service': service_filter,
        'account_type': account_type,
        'checks_run': checks_run,
        'summary': {'checks': len(checks_run), **_summarize(rows)},
        'per_check': {
            cid: _summarize([r for r in rows if r.get('CheckId') == cid]) for cid in checks_run
        },
        'findings': returned,
        'findings_filter': {
            'include_status': statuses,
            'max_findings': max_findings,
            'matched': len(matched),
            'returned': len(returned),
            'truncated': len(returned) < len(matched),
        },
        'role_arn': role_arn,
        'region': region,
        'regions': normalized,
        'scan_region': scan_region,
    }


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == '__main__':
    main()
