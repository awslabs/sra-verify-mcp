"""Tool tests: call the tool coroutines directly, with scans faked and AWS refused."""

import anyio
import boto3
import datetime
import json
import pytest
import subprocess
import sys
import threading
from awslabs.sraverify_mcp_server import server
from botocore.stub import Stubber
from conftest import isolated_env
from sraverify.core.errors import NoChecksSelectedError, PartitionUndeterminedError
from sraverify.core.finding import Finding


pytestmark = pytest.mark.anyio

ROLE_ARN = 'arn:aws-us-gov:iam::111122223333:role/SRAMemberMCPRole'
AUDIT = ['111122223333']
LOG_ARCHIVE = ['444455556666']


def _assert_partition_error(result):
    assert result['status'] == 'failed'
    assert 'region' in result['error']
    assert 'AWS_DEFAULT_REGION' in result['error']
    assert '--regions' not in result['error']


def test_network_guard_refuses_aws_calls(_no_aws_calls):
    client = boto3.client(
        'sts',
        region_name='us-east-1',
        aws_access_key_id='AKIAEXAMPLEEXAMPLE00',
        aws_secret_access_key='example-secret-access-key',
    )
    with pytest.raises(AssertionError, match='offline'):
        client.get_caller_identity()
    assert len(_no_aws_calls) == 1
    _no_aws_calls.clear()  # the attempt was this test's point; don't fail teardown


# Inventory


async def test_list_checks_by_account_type_all_matches_inventory():
    everything = await server.list_checks_by_account_type('all')
    assert everything == server._default_sra.get_available_checks('all')

    by_type = {}
    for account_type in ('application', 'audit', 'log-archive', 'management'):
        by_type.update(await server.list_checks_by_account_type(account_type))
    assert by_type == everything


async def test_every_listed_check_describes():
    for check_id in await server.list_checks_by_account_type('all'):
        result = await server.describe_check(check_id)
        assert 'error' not in result, check_id


async def test_list_services_includes_renamed_services():
    services = (await server.list_services())['services']
    for name in ('Security Hub', 'Security Hub CSPM', 'Route 53 Resolver'):
        assert name in services


# B4: list_checks_by_service


async def test_list_checks_by_service_strips_and_ignores_case():
    exact = await server.list_checks_by_service('GuardDuty')
    assert exact
    assert all(info['service'] == 'GuardDuty' for info in exact.values())
    assert await server.list_checks_by_service(' GuardDuty ') == exact
    assert await server.list_checks_by_service('guardduty') == exact


async def test_list_checks_by_service_legacy_securityhub_hint():
    result = await server.list_checks_by_service('SecurityHub')
    assert 'error' in result
    assert result['available_services'] == server._default_sra.get_available_services()
    assert "'Security Hub'" in result['hint']
    assert "'Security Hub CSPM'" in result['hint']


async def test_list_checks_by_service_unknown():
    result = await server.list_checks_by_service('Nope')
    assert result['error'] == "No checks found for service 'Nope'."
    assert 'available_services' in result
    assert 'hint' not in result


async def test_list_checks_by_service_all():
    everything = server._default_sra.get_available_checks('all')
    assert await server.list_checks_by_service('all') == everything
    assert await server.list_checks_by_service('') == everything


# B3: describe_check


async def test_describe_check_keeps_legacy_keys_and_adds_metadata():
    result = await server.describe_check('SRA-GUARDDUTY-01')
    legacy = server._default_sra.get_available_checks('all')['SRA-GUARDDUTY-01']
    assert result['check_id'] == 'SRA-GUARDDUTY-01'
    assert {k: result[k] for k in legacy} == legacy
    for key in ('check_logic', 'resource_type'):
        assert isinstance(result[key], str) and result[key]
    assert set(result['remediation']) == {'text', 'cli', 'console'}
    assert isinstance(result['sra_sections'], list)
    assert isinstance(result['additional_urls'], list)
    assert result['requires_audit_accounts'] is False
    assert result['requires_log_archive_accounts'] is False
    json.dumps(result)


async def test_describe_check_reports_required_account_lists():
    assert (await server.describe_check('SRA-GUARDDUTY-14'))['requires_audit_accounts'] is True
    config06 = await server.describe_check('SRA-CONFIG-06')
    assert config06['requires_log_archive_accounts'] is True


async def test_describe_check_typo_suggests():
    result = await server.describe_check(' SRA-GUARDUTY-01 ')
    assert result['error'] == 'Check SRA-GUARDUTY-01 not found'
    assert result['available_checks_count'] == len(server._default_sra.get_available_checks())
    assert 'SRA-GUARDDUTY-01' in result['suggestions']


# A4: run_check findings at the boundary


async def test_run_check_summary_and_camelcase_rows(fake_run_checks, make_finding):
    fake_run_checks.returns = [
        make_finding('SRA-GUARDDUTY-01', status) for status in ('PASS', 'FAIL', 'ERROR')
    ]
    result = await server.run_check('SRA-GUARDDUTY-01', region='us-east-1')
    assert result['status'] == 'completed'
    assert result['summary'] == {'total': 3, 'passed': 1, 'failed': 1, 'errors': 1}
    assert all(tuple(f) == Finding.FIELDS for f in result['findings'])
    assert result['scan_region'] == 'us-east-1'
    assert fake_run_checks.calls[0]['check_id'] == 'SRA-GUARDDUTY-01'
    json.dumps(result)


# A5: error mapping


async def test_run_check_without_region_returns_partition_error(fake_run_checks):
    result = await server.run_check('SRA-GUARDDUTY-01')
    _assert_partition_error(result)
    assert fake_run_checks.calls == []


def test_invalid_region_message_names_tool_arguments():
    # Not reachable through the tools (they strip values and drop empty ones), but
    # _failure maps any PartitionUndeterminedError through this message.
    message = server._partition_error_message(PartitionUndeterminedError(' us-east-1'))
    assert message.startswith("' us-east-1' is not an AWS Region name.")
    assert 'region argument' in message
    assert '--regions' not in message


async def test_run_check_unknown_id_suggests(fake_run_checks):
    result = await server.run_check('SRA-GUARDUTY-01', region='us-east-1')
    assert result['status'] == 'failed'
    assert result['error'].startswith('Check SRA-GUARDUTY-01 not found.')
    assert 'SRA-GUARDDUTY-01' in result['suggestions']
    assert fake_run_checks.calls == []


async def test_run_check_no_checks_selected_in_tool_terms(fake_run_checks):
    fake_run_checks.returns = NoChecksSelectedError('all', None, 'X')
    result = await server.run_check('SRA-GUARDDUTY-01', region='us-east-1')
    assert result['status'] == 'failed'
    # Explained in tool arguments, not str(e)'s CLI flags (FEAT-002 deviation 3).
    assert result['error'] == server._no_checks_message('all', None)
    assert '--' not in result['error']
    assert result['regions'] == ['us-east-1']


# B8: account-list gate


@pytest.mark.parametrize('check_id', ['SRA-GUARDDUTY-14', 'SRA-GUARDDUTY-15'])
async def test_audit_gate(fake_run_checks, check_id):
    prompt = await server.run_check(check_id, region='us-east-1')
    assert prompt['status'] == 'failed'
    assert 'requires audit_accounts' in prompt['error']
    assert 'check_info' in prompt
    assert fake_run_checks.calls == []

    result = await server.run_check(check_id, audit_accounts=AUDIT, region='us-east-1')
    assert result['status'] == 'completed'
    assert fake_run_checks.calls[0]['audit_accounts'] == AUDIT


@pytest.mark.parametrize('check_id', ['SRA-CONFIG-06', 'SRA-SECURITYLAKE-01'])
async def test_log_archive_gate(fake_run_checks, check_id):
    prompt = await server.run_check(check_id, audit_accounts=AUDIT, region='us-east-1')
    assert prompt['status'] == 'failed'
    assert 'requires log_archive_accounts' in prompt['error']
    assert fake_run_checks.calls == []


def test_static_reader_sets_name_real_checks():
    catalog = server._default_sra.get_available_checks('all')
    assert len(server._READS_AUDIT_ACCOUNTS) == 18
    assert len(server._READS_LOG_ARCHIVE_ACCOUNTS) == 5
    assert server._READS_AUDIT_ACCOUNTS <= set(catalog)
    assert server._READS_LOG_ARCHIVE_ACCOUNTS <= set(catalog)


# B1: Region input


@pytest.mark.parametrize(
    ('kwargs', 'expected'),
    [
        ({'region': ' us-east-1'}, ['us-east-1']),
        ({'regions': ['us-west-2', ' eu-west-1 ']}, ['us-west-2', 'eu-west-1']),
        (
            {'region': 'us-west-2', 'regions': ['eu-west-1', ' us-west-2 ', '']},
            ['us-west-2', 'eu-west-1'],
        ),
        ({'region': 'us-east-1', 'regions': ['ALL']}, None),
    ],
)
async def test_region_normalization(fake_run_checks, monkeypatch, kwargs, expected):
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')
    result = await server.run_check('SRA-GUARDDUTY-01', **kwargs)
    assert result['status'] == 'completed'
    assert fake_run_checks.calls[0]['regions'] == expected
    assert result['regions'] == expected
    assert result['region'] == kwargs.get('region')


@pytest.mark.parametrize('region', ['all', ''])
async def test_all_regions_with_default_region(fake_run_checks, monkeypatch, region):
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')
    result = await server.run_check('SRA-GUARDDUTY-01', region=region)
    assert result['status'] == 'completed'
    assert result['scan_region'] == 'us-east-1'
    assert fake_run_checks.calls[0]['regions'] is None


@pytest.mark.parametrize('region', ['all', ''])
async def test_all_regions_without_default_region(fake_run_checks, region):
    result = await server.run_check('SRA-GUARDDUTY-01', region=region)
    _assert_partition_error(result)
    assert fake_run_checks.calls == []


# B2: partition-correct AssumeRole


@pytest.fixture
def sts_stub(monkeypatch):
    """Stub STS AssumeRole on every client a boto3 Session builds; record each client."""
    real_client = boto3.session.Session.client
    built: list[tuple[str, str]] = []
    stubbers: list[Stubber] = []

    def _client(self, *args, **kwargs):
        client = real_client(self, *args, **kwargs)
        service_name = args[0] if args else kwargs['service_name']
        built.append((service_name, client.meta.region_name))
        if service_name == 'sts':
            stubber = Stubber(client)
            stubber.add_response(
                'assume_role',
                {
                    'Credentials': {
                        'AccessKeyId': 'ASIAEXAMPLEEXAMPLE00',
                        'SecretAccessKey': 'example-secret-access-key',
                        'SessionToken': 'example-session-token',
                        'Expiration': datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
                    },
                    'AssumedRoleUser': {
                        'AssumedRoleId': 'AROAEXAMPLEEXAMPLE00:sraverify-mcp-session',
                        'Arn': 'arn:aws-us-gov:sts::111122223333:assumed-role/'
                        'SRAMemberMCPRole/sraverify-mcp-session',
                    },
                },
                {'RoleArn': ROLE_ARN, 'RoleSessionName': 'sraverify-mcp-session'},
            )
            stubber.activate()
            stubbers.append(stubber)
        return client

    monkeypatch.setattr(boto3.session.Session, 'client', _client)
    yield built
    for stubber in stubbers:
        stubber.assert_no_pending_responses()


async def test_assume_role_in_scan_partition(fake_run_checks, sts_stub):
    result = await server.run_check('SRA-GUARDDUTY-01', role_arn=ROLE_ARN, region='us-gov-west-1')
    assert result['status'] == 'completed', result
    assert sts_stub == [('sts', 'us-gov-west-1')]
    session = fake_run_checks.calls[0]['session']
    assert session.region_name == 'us-gov-west-1'
    assert session.get_credentials().access_key == 'ASIAEXAMPLEEXAMPLE00'
    assert result['role_arn'] == ROLE_ARN


async def test_assume_role_without_region_fails_before_sts(fake_run_checks, sts_stub):
    result = await server.run_check('SRA-GUARDDUTY-01', role_arn=ROLE_ARN)
    _assert_partition_error(result)
    assert result['role_arn'] == ROLE_ARN
    assert sts_stub == []
    assert fake_run_checks.calls == []


# B5: run_checks


@pytest.fixture
def guardduty_findings(fake_run_checks, make_finding):
    fake_run_checks.returns = [
        make_finding('SRA-GUARDDUTY-01', 'PASS'),
        make_finding('SRA-GUARDDUTY-01', 'FAIL', region='us-west-2'),
        make_finding('SRA-GUARDDUTY-02', 'ERROR'),
        make_finding('SRA-GUARDDUTY-02', 'PASS', region='us-west-2'),
    ]
    return fake_run_checks


async def _run_guardduty(**kwargs):
    return await server.run_checks(
        service=' GuardDuty ',
        audit_accounts=AUDIT,
        log_archive_accounts=LOG_ARCHIVE,
        region='us-east-1',
        **kwargs,
    )


async def test_run_checks_default_filter_and_per_check(guardduty_findings):
    result = await _run_guardduty()
    assert result['status'] == 'completed', result
    assert result['service'] == 'GuardDuty'
    assert result['account_type'] == 'all'
    expected_ids = sorted(server._default_sra.select_checks(service='GuardDuty'))
    assert result['checks_run'] == expected_ids
    assert set(result['per_check']) == set(expected_ids)
    assert result['per_check']['SRA-GUARDDUTY-01'] == {
        'total': 2,
        'passed': 1,
        'failed': 1,
        'errors': 0,
    }
    assert result['per_check']['SRA-GUARDDUTY-02'] == {
        'total': 2,
        'passed': 1,
        'failed': 0,
        'errors': 1,
    }
    assert result['per_check']['SRA-GUARDDUTY-03']['total'] == 0
    assert result['summary'] == {
        'checks': len(expected_ids),
        'total': 4,
        'passed': 2,
        'failed': 1,
        'errors': 1,
    }
    assert [f['Status'] for f in result['findings']] == ['FAIL', 'ERROR']
    assert result['findings_filter'] == {
        'include_status': ['FAIL', 'ERROR'],
        'max_findings': 50,
        'matched': 2,
        'returned': 2,
        'truncated': False,
    }
    assert result['scan_region'] == 'us-east-1'
    call = guardduty_findings.calls[0]
    assert (call['service'], call['account_type'], call['check_id']) == ('GuardDuty', 'all', None)
    json.dumps(result)


async def test_run_checks_truncates(guardduty_findings):
    result = await _run_guardduty(max_findings=1)
    assert len(result['findings']) == 1
    assert result['findings_filter']['matched'] == 2
    assert result['findings_filter']['truncated'] is True


async def test_run_checks_include_status_is_case_insensitive(guardduty_findings):
    result = await _run_guardduty(include_status=['pass'])
    assert result['status'] == 'completed'
    assert result['findings_filter']['include_status'] == ['PASS']
    assert [f['Status'] for f in result['findings']] == ['PASS', 'PASS']


async def test_run_checks_rejects_bad_include_status(guardduty_findings):
    result = await _run_guardduty(include_status=['BOGUS'])
    assert result['status'] == 'failed'
    assert 'BOGUS' in result['error']
    assert guardduty_findings.calls == []


async def test_run_checks_rejects_negative_max_findings(guardduty_findings):
    result = await _run_guardduty(max_findings=-1)
    assert result['status'] == 'failed'
    assert 'max_findings' in result['error']
    assert guardduty_findings.calls == []


async def test_run_checks_unknown_service(fake_run_checks):
    result = await server.run_checks(service='Nope', region='us-east-1')
    assert result['status'] == 'failed'
    assert result['error'] == "No checks found for service 'Nope'."
    assert result['available_services'] == server._default_sra.get_available_services()
    assert 'valid_account_types' in result
    assert fake_run_checks.calls == []


async def test_run_checks_legacy_securityhub_hint(fake_run_checks):
    result = await server.run_checks(service='SecurityHub', region='us-east-1')
    assert result['status'] == 'failed'
    assert 'hint' in result


async def test_run_checks_audit_gate(fake_run_checks):
    result = await server.run_checks(service='GuardDuty', account_type='audit', region='us-east-1')
    assert result['status'] == 'failed'
    assert 'audit_accounts' in result['error']
    need = result['checks_requiring_audit_accounts']
    assert need
    assert set(need) <= set(server._default_sra.select_checks('audit', 'GuardDuty'))
    assert 'checks_requiring_log_archive_accounts' not in result
    assert fake_run_checks.calls == []


async def test_run_checks_without_region_returns_partition_error(guardduty_findings):
    result = await server.run_checks(
        service='GuardDuty', audit_accounts=AUDIT, log_archive_accounts=LOG_ARCHIVE
    )
    _assert_partition_error(result)
    assert result['service'] == 'GuardDuty'
    assert guardduty_findings.calls == []


# B6: scans run off the event loop, each on a fresh session


async def test_concurrent_scans_run_in_parallel_threads(fake_run_checks):
    barrier = threading.Barrier(2, timeout=5)

    def _wait(sra, kwargs):
        barrier.wait()  # breaks (BrokenBarrierError) if the two scans run serially
        return []

    fake_run_checks.returns = _wait
    results = []

    async def _one():
        results.append(await server.run_check('SRA-GUARDDUTY-01', region='us-east-1'))

    async with anyio.create_task_group() as tg:
        tg.start_soon(_one)
        tg.start_soon(_one)

    assert [r['status'] for r in results] == ['completed', 'completed'], results
    first, second = (call['session'] for call in fake_run_checks.calls)
    assert first is not second
    assert first is not server._default_sra.session
    assert second is not server._default_sra.session
    assert all(call['sra'] is not server._default_sra for call in fake_run_checks.calls)


# B7: server instructions


def test_instructions_cover_tools_regions_and_cli_flags():
    text = server.mcp.instructions
    assert text
    for needle in (
        'list_checks_by_account_type',
        'list_services',
        'list_checks_by_service',
        'describe_check',
        'run_check(',
        'run_checks(',
        'AWS_DEFAULT_REGION',
        '--regions',
        '--audit-account',
        '--log-archive-account',
        '--profile',
        'Security Hub CSPM',
        'Route 53 Resolver',
        'requires_audit_accounts',
    ):
        assert needle in text, needle


# B9: stdout stays clean for the stdio protocol


def test_import_writes_nothing_to_stdout():
    proc = subprocess.run(
        [sys.executable, '-c', 'import awslabs.sraverify_mcp_server.server'],
        env=isolated_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ''
