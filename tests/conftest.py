"""Pytest configuration for the sraverify MCP server test suite.

Two jobs: keep the suite offline, and give tests fake scan results.

The AWS environment is isolated at import time, before any test module imports
the server: the server builds a boto3 session at import (``_default_sra``), so the
isolation has to be in place first.
"""

import os
import pytest
from dataclasses import dataclass, field
from typing import Any


_ISOLATED_AWS_ENV = {
    'AWS_CONFIG_FILE': os.devnull,
    'AWS_SHARED_CREDENTIALS_FILE': os.devnull,
    'AWS_EC2_METADATA_DISABLED': 'true',
}

_REMOVED_AWS_ENV = (
    'AWS_PROFILE',
    'AWS_DEFAULT_PROFILE',
    'AWS_DEFAULT_REGION',
    'AWS_REGION',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_SECURITY_TOKEN',
    'AWS_ROLE_ARN',
    'AWS_WEB_IDENTITY_TOKEN_FILE',
    'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
    'AWS_CONTAINER_CREDENTIALS_FULL_URI',
    'AWS_CONTAINER_AUTHORIZATION_TOKEN',
)

os.environ.update(_ISOLATED_AWS_ENV)
for _name in _REMOVED_AWS_ENV:
    os.environ.pop(_name, None)


def isolated_env() -> dict[str, str]:
    """Return the environment for subprocesses: HOME, PATH and the AWS isolation only."""
    return {
        'HOME': os.environ.get('HOME', ''),
        'PATH': os.environ.get('PATH', ''),
        'PYTHONDONTWRITEBYTECODE': '1',
        **_ISOLATED_AWS_ENV,
    }


_OFFLINE_MESSAGE = (
    'the sraverify-mcp test suite is offline: a test attempted an HTTP request to '
    '{url!r}. No test may issue an AWS call.'
)


@pytest.fixture(autouse=True)
def _no_aws_calls(monkeypatch):
    """Refuse every outbound botocore HTTP request, and fail the test if one was tried.

    The tools catch every exception and return it as a failed result, so the
    AssertionError raised here could be swallowed. Recording the attempt and
    asserting at teardown makes the attempt fail the test regardless.

    Only ``send`` is patched: client construction and Stubber-backed calls stay
    functional and touch no network.
    """
    import botocore.httpsession

    attempts: list[str] = []

    def _refuse(self, request):
        url = getattr(request, 'url', '<unknown>')
        attempts.append(url)
        raise AssertionError(_OFFLINE_MESSAGE.format(url=url))

    monkeypatch.setattr(botocore.httpsession.URLLib3Session, 'send', _refuse)
    yield attempts
    assert attempts == [], f'tests attempted AWS HTTP requests: {attempts}'


@pytest.fixture
def anyio_backend():
    """Run anyio-marked tests on asyncio only."""
    return 'asyncio'


@pytest.fixture
def make_finding():
    """Return a factory building a valid Finding for a real check ID."""
    from sraverify.core.finding import Finding
    from sraverify.core.registry import all_checks

    def _make(check_id: str, status: str, region: str = 'us-east-1') -> Finding:
        meta = all_checks()[check_id].meta
        return Finding(
            check_id=check_id,
            status=status,  # Finding coerces the string to Status
            region=region,
            severity=meta.severity,
            title=f'{check_id} {meta.title}',
            description=meta.description,
            resource_id=None,
            resource_type=meta.resource_type,
            account_id='111122223333',
            account_name='Example',
            checked_value='',
            actual_value='',
            remediation=meta.remediation.text,
            service=meta.service,
            check_logic=meta.check_logic,
            account_type=meta.account_type,
        )

    return _make


@dataclass
class RunChecksRecorder:
    """Stand-in for SRAVerify.run_checks.

    Attributes:
        returns: What each call returns: a list of Findings, an exception
            instance to raise, or a callable ``(sra, kwargs) -> list``.
        calls: One dict per call with the instance's ``regions`` and ``session``,
            the instance itself and the keyword arguments.
    """

    returns: Any = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)


@pytest.fixture
def fake_run_checks(monkeypatch):
    """Patch SRAVerify.run_checks with a recorder; no check runs, no AWS call."""
    from sraverify import SRAVerify

    recorder = RunChecksRecorder()

    def _run_checks(
        self,
        account_type='all',
        service=None,
        check_id=None,
        audit_accounts=None,
        log_archive_accounts=None,
    ):
        kwargs = {
            'account_type': account_type,
            'service': service,
            'check_id': check_id,
            'audit_accounts': audit_accounts,
            'log_archive_accounts': log_archive_accounts,
        }
        recorder.calls.append(
            {'sra': self, 'regions': self.regions, 'session': self.session, **kwargs}
        )
        if isinstance(recorder.returns, BaseException):
            raise recorder.returns
        if callable(recorder.returns):
            return recorder.returns(self, kwargs)
        return list(recorder.returns)

    monkeypatch.setattr(SRAVerify, 'run_checks', _run_checks)
    return recorder
