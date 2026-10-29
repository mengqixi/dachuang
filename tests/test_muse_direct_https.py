import importlib.util
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

scripts = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(scripts))
spec = importlib.util.spec_from_file_location('muse_direct_https', scripts / 'muse_direct_https.py')
direct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(direct)


def test_certificate_expiry_uses_utc(monkeypatch):
    monkeypatch.setattr(direct.subprocess, 'check_output', lambda *_args, **_kwargs: b'notAfter=Nov  5 00:45:00 2026 GMT\n')
    assert direct.expiry_epoch() == datetime(2026, 11, 5, 0, 45, tzinfo=timezone.utc).timestamp()


def test_missing_certificate_fails_before_listening(tmp_path, monkeypatch):
    monkeypatch.setattr(direct, 'CERT', tmp_path / 'missing.pem')
    with pytest.raises(FileNotFoundError):
        direct.DirectTLSGateway(port=0)


def test_renewal_uses_only_project_paths_and_alpn(tmp_path, monkeypatch):
    key = tmp_path / 'test.key'
    key.write_text('unit-test-only')
    monkeypatch.setattr(direct, 'ROOT', tmp_path)
    monkeypatch.setattr(direct, 'KEY', key)
    monkeypatch.setattr(direct, 'STATE_DIR', tmp_path)
    received = []

    def run(command, **kwargs):
        received.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(direct.subprocess, 'run', run)
    direct.renew_certificate(logging.getLogger('test-muse-direct'))
    command, kwargs = received[0]
    assert '--alpn' in command and '--force' in command
    assert '--certificate-profile' in command and 'shortlived' in command
    assert '--http' not in command and '--install' not in command
    assert kwargs['timeout'] == 180
    assert kwargs['cwd'] == str(tmp_path)
