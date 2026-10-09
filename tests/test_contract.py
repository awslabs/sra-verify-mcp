"""Contract tests: the parts of the sraverify and MCP SDK APIs the server relies on.

Each assertion pins one assumption server.py makes about a dependency, so an
upstream change fails here with a clear message instead of at a user's first
tool call (the way 0.3.x and MCP 2.x broke the server).
"""

import dataclasses
import inspect
import tomllib
from importlib.metadata import version
from packaging.requirements import Requirement
from pathlib import Path
from sraverify import SRAVerify
from sraverify.core.errors import (
    NoChecksSelectedError,
    PartitionUndeterminedError,
    SRAVerifyError,
    UnknownCheckError,
)
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.registry import all_checks


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_sraverify_init_accepts_the_arguments_the_server_passes():
    params = inspect.signature(SRAVerify.__init__).parameters
    for name in (
        'session',
        'regions',
        'connect_timeout',
        'read_timeout',
        'max_attempts',
        'max_pool_connections',
    ):
        assert name in params, name
    assert 'debug' not in params


def test_run_checks_accepts_the_filters_the_server_passes():
    params = inspect.signature(SRAVerify.run_checks).parameters
    for name in ('account_type', 'service', 'check_id', 'audit_accounts', 'log_archive_accounts'):
        assert name in params, name


def test_selection_and_region_api_exist():
    assert 'check_id' in inspect.signature(SRAVerify.select_checks).parameters
    assert 'account_type' in inspect.signature(SRAVerify.select_checks).parameters
    assert 'service' in inspect.signature(SRAVerify.select_checks).parameters
    assert callable(SRAVerify.resolve_scan_region)


def test_inventory_shape():
    checks = SRAVerify().get_available_checks('all')
    assert checks
    for check_id, info in checks.items():
        assert set(info) == {'name', 'service', 'account_type', 'description', 'severity'}, (
            check_id
        )


def test_registry_account_type_matches_inventory():
    # run_checks' gate reads cls.meta.account_type.value; the inventory reports it too.
    checks = SRAVerify().get_available_checks('all')
    registry = all_checks()
    assert set(registry) == set(checks)
    for check_id, cls in registry.items():
        assert cls.meta.account_type.value == checks[check_id]['account_type'], check_id


def test_check_meta_carries_the_fields_describe_check_reads():
    meta_fields = {f.name for f in dataclasses.fields(CheckMeta)}
    assert {
        'check_id',
        'title',
        'description',
        'check_logic',
        'severity',
        'account_type',
        'service',
        'resource_type',
        'remediation',
        'sra_sections',
        'additional_urls',
    } <= meta_fields
    assert {'text', 'cli', 'console'} <= {f.name for f in dataclasses.fields(Remediation)}


def test_finding_row_keys_are_the_csv_contract(make_finding):
    row = make_finding('SRA-GUARDDUTY-01', 'PASS').to_row()
    assert Finding.FIELDS == tuple(row)
    assert all(isinstance(v, str) for v in row.values())


def test_error_classes():
    unknown = UnknownCheckError('SRA-X', ['SRA-Y'])
    assert unknown.suggestions == ['SRA-Y']
    assert isinstance(unknown, SRAVerifyError)

    absent = PartitionUndeterminedError()
    assert absent.reason == 'absent'
    assert absent.bad_value is None
    invalid = PartitionUndeterminedError('nowhere-1')
    assert invalid.reason == 'invalid'
    assert invalid.bad_value == 'nowhere-1'

    no_checks = NoChecksSelectedError('audit', 'GuardDuty', None)
    assert no_checks.args == ('audit', 'GuardDuty', None)
    assert isinstance(no_checks, SRAVerifyError)


def test_select_checks_raises_typed_errors():
    sra = SRAVerify()
    try:
        sra.select_checks(check_id='SRA-GUARDUTY-01')
    except UnknownCheckError as e:
        assert 'SRA-GUARDDUTY-01' in e.suggestions
    else:
        raise AssertionError('select_checks accepted an unknown check ID')
    try:
        sra.select_checks(service='Nope')
    except NoChecksSelectedError:
        pass
    else:
        raise AssertionError('select_checks matched an unknown service')


def test_installed_versions_satisfy_pyproject_pins():
    pyproject = tomllib.loads((REPO_ROOT / 'pyproject.toml').read_text())
    requirements = {
        req.name: req for req in map(Requirement, pyproject['project']['dependencies'])
    }
    for name in ('sraverify', 'mcp'):
        installed = version(name)
        assert requirements[name].specifier.contains(installed, prereleases=True), (
            f'{name} {installed} does not satisfy {requirements[name]}'
        )


def test_server_uses_mcp_v2_server_class():
    from awslabs.sraverify_mcp_server import server
    from mcp.server.mcpserver import MCPServer

    assert isinstance(server.mcp, MCPServer)
