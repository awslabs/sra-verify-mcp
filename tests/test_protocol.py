"""Protocol tests: the tools as an MCP client sees them, in memory and over real stdio."""

import anyio
import json
import pytest
import sys
from awslabs.sraverify_mcp_server import __version__, server
from conftest import isolated_env
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters
from sraverify.core.finding import Finding


pytestmark = pytest.mark.anyio

TOOLS = {
    'list_checks_by_account_type',
    'list_services',
    'list_checks_by_service',
    'describe_check',
    'run_check',
    'run_checks',
}

# Parameters (and required lists) of the 5 tools as released before 0.1.0.
LEGACY_PARAMETERS = {
    'list_checks_by_account_type': ({'account_type'}, set()),
    'list_services': (set(), set()),
    'list_checks_by_service': ({'service'}, {'service'}),
    'describe_check': ({'check_id'}, {'check_id'}),
    'run_check': (
        {
            'check_id',
            'audit_accounts',
            'log_archive_accounts',
            'role_arn',
            'region',
            'connect_timeout',
            'read_timeout',
            'max_attempts',
            'max_pool_connections',
        },
        {'check_id'},
    ),
}

AUDIT = ['111122223333']
LOG_ARCHIVE = ['444455556666']

CALLS = [
    ('list_checks_by_account_type', {'account_type': 'audit'}),
    ('list_services', {}),
    ('list_checks_by_service', {'service': 'GuardDuty'}),
    ('list_checks_by_service', {'service': 'SecurityHub'}),
    ('describe_check', {'check_id': 'SRA-GUARDDUTY-01'}),
    ('describe_check', {'check_id': 'SRA-GUARDUTY-01'}),
    ('run_check', {'check_id': 'SRA-GUARDDUTY-01', 'region': 'us-east-1'}),
    ('run_check', {'check_id': 'SRA-GUARDDUTY-01'}),
    (
        'run_checks',
        {
            'service': 'GuardDuty',
            'audit_accounts': AUDIT,
            'log_archive_accounts': LOG_ARCHIVE,
            'regions': ['us-east-1', 'us-west-2'],
            'include_status': ['PASS', 'FAIL', 'ERROR'],
        },
    ),
    ('run_checks', {'service': 'Nope', 'region': 'us-east-1'}),
]


def _text(result) -> str:
    return ''.join(getattr(c, 'text', '') for c in result.content)


async def test_tool_list_keeps_legacy_parameters():
    async with Client(server.mcp) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}

    assert set(tools) == TOOLS
    for name, (params, required) in LEGACY_PARAMETERS.items():
        schema = tools[name].input_schema
        assert params <= set(schema.get('properties', {})), name
        assert set(schema.get('required', [])) == required, name

    assert 'regions' in tools['run_check'].input_schema['properties']
    run_checks = tools['run_checks'].input_schema
    assert {'service', 'account_type', 'include_status', 'max_findings'} <= set(
        run_checks['properties']
    )
    assert run_checks.get('required', []) == []


async def test_every_tool_round_trips(fake_run_checks, make_finding):
    fake_run_checks.returns = [
        make_finding('SRA-GUARDDUTY-01', 'PASS'),
        make_finding('SRA-GUARDDUTY-01', 'FAIL', region='us-west-2'),
        make_finding('SRA-GUARDDUTY-02', 'ERROR'),
    ]
    called = set()
    parsed = {}
    async with Client(server.mcp) as client:
        for name, args in CALLS:
            result = await client.call_tool(name, args)
            assert not result.is_error, (name, args, _text(result))
            parsed[(name, json.dumps(args, sort_keys=True))] = json.loads(_text(result))
            called.add(name)

    assert called == TOOLS

    def get(name, **args):
        return parsed[(name, json.dumps(args, sort_keys=True))]

    assert 'hint' in get('list_checks_by_service', service='SecurityHub')
    assert 'SRA-GUARDDUTY-01' in get('describe_check', check_id='SRA-GUARDUTY-01')['suggestions']

    run_check = get('run_check', check_id='SRA-GUARDDUTY-01', region='us-east-1')
    assert run_check['status'] == 'completed'
    assert run_check['findings']
    assert all(tuple(f) == Finding.FIELDS for f in run_check['findings'])

    assert get('run_check', check_id='SRA-GUARDDUTY-01')['status'] == 'failed'

    run_checks = get(
        'run_checks',
        service='GuardDuty',
        audit_accounts=AUDIT,
        log_archive_accounts=LOG_ARCHIVE,
        regions=['us-east-1', 'us-west-2'],
        include_status=['PASS', 'FAIL', 'ERROR'],
    )
    assert run_checks['status'] == 'completed'
    assert run_checks['findings_filter']['returned'] == 3
    assert all(tuple(f) == Finding.FIELDS for f in run_checks['findings'])
    assert get('run_checks', service='Nope', region='us-east-1')['status'] == 'failed'


async def test_stdio_server_starts_and_answers():
    params = StdioServerParameters(
        command=sys.executable,
        args=['-m', 'awslabs.sraverify_mcp_server.server'],
        env=isolated_env(),
    )
    with anyio.fail_after(60):
        async with Client(params) as client:
            info = client.server_info
            assert info is not None
            assert (info.name, info.version) == ('awslabs.sraverify-mcp-server', __version__)
            tools = (await client.list_tools()).tools
            assert {t.name for t in tools} == TOOLS
            result = await client.call_tool('list_services', {})

    assert not result.is_error, _text(result)
    assert 'Security Hub CSPM' in json.loads(_text(result))['services']
