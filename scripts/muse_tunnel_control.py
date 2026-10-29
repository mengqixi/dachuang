"""Project-scoped start/status/stop for the temporary Muse connection.

Download and verify the official cloudflared binary separately into bin-local.
No system services, firewall changes, admin credentials or broad process kills.
"""
import http.client
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / 'data/muse_tunnel'
STATE = STATE_DIR / 'state.json'
TOKEN_PATH = ROOT / 'data/keys/muse_readonly.token'
BINARY = ROOT / 'bin-local/cloudflared'
GATEWAY = ROOT / 'scripts/muse_readonly_gateway.py'
PREFIX = '/api/integrations/muse/v1/'


def read_state():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def process_args(pid):
    try:
        cwd = Path('/proc/%d/cwd' % int(pid)).resolve()
        args = [os.fsdecode(x) for x in Path('/proc/%d/cmdline' % int(pid)).read_bytes().split(b'\0') if x]
        if cwd != ROOT:
            raise RuntimeError('Process is outside this project; refusing operation')
        return args
    except FileNotFoundError:
        return []


def stop_owned(pid, expected):
    if not pid:
        return
    args = process_args(pid)
    if not args:
        return
    if not any(str((ROOT / arg).resolve()) == str(expected) for arg in args[:3]):
        raise RuntimeError('Process command does not match this project component')
    os.kill(int(pid), signal.SIGTERM)
    for _ in range(40):
        if not Path('/proc/%d' % int(pid)).exists():
            return
        time.sleep(.1)
    raise RuntimeError('Project process did not exit; no forced kill attempted')


def status_code(port, token=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        headers = {'Authorization': 'Bearer ' + token} if token else {}
        connection.request('GET', PREFIX + 'overview', headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def wait_local(port, expected, token=None):
    for _ in range(30):
        try:
            if status_code(port, token) == expected:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.25)
    raise RuntimeError('Project listener did not become ready')


def launch(args, log_name, env=None):
    with open(str(STATE_DIR / log_name), 'ab') as log:
        return subprocess.Popen(args, cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=log, start_new_session=True)


def enable_application(token):
    pid_path = ROOT / 'data/app.pid'
    pid = int(pid_path.read_text().strip())
    args = process_args(pid)
    if len(args) != 2 or args[1] != 'app.py':
        raise RuntimeError('Not the recorded project application')
    env = {}
    for item in Path('/proc/%d/environ' % pid).read_bytes().split(b'\0'):
        if b'=' in item:
            key, value = item.split(b'=', 1)
            env[os.fsdecode(key)] = os.fsdecode(value)
    if env.get('MUSE_READONLY_ENABLED') == 'true' and env.get('MUSE_READONLY_TOKEN') == token:
        return pid
    with closing(sqlite3.connect((ROOT / 'data/system.db').as_uri() + '?mode=ro', uri=True, timeout=1)) as conn:
        active = conn.execute("SELECT count(*) FROM training_jobs WHERE status IN ('queued','running')").fetchone()[0]
    if active:
        raise RuntimeError('Training is active; refusing application restart')
    env.update(MUSE_READONLY_ENABLED='true', MUSE_READONLY_TOKEN=token)
    stop_owned(pid, ROOT / 'app.py')
    child = launch([args[0], 'app.py'], 'application.log', env=env)
    pid_path.write_text(str(child.pid) + '\n')
    wait_local(5001, 200, token)
    return child.pid


def start():
    state = read_state()
    if state.get('tunnel_pid') and process_args(state['tunnel_pid']):
        if str(BINARY) not in process_args(state['tunnel_pid']):
            raise RuntimeError('Saved PID belongs to another component')
        print(json.dumps(state))
        return
    if state.get('gateway_pid'):
        stop_owned(state['gateway_pid'], GATEWAY)
    if not BINARY.is_file() or BINARY.is_symlink():
        raise RuntimeError('Verified project-local cloudflared binary is required')
    if TOKEN_PATH.exists():
        if TOKEN_PATH.is_symlink():
            raise RuntimeError('Refusing symlink credential file')
        token = TOKEN_PATH.read_text().strip()
    else:
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        token = secrets.token_urlsafe(32)
        fd = os.open(str(TOKEN_PATH), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(token + '\n')
    if not 43 <= len(token) <= 256:
        raise RuntimeError('Invalid independent credential')
    os.chmod(str(TOKEN_PATH), 0o600)
    gateway = launch([sys.executable, str(GATEWAY)], 'gateway.log')
    state = {'gateway_pid': gateway.pid, 'temporary': True, 'read_only': True}
    STATE.write_text(json.dumps(state))
    try:
        wait_local(18561, 401)
        # No cloudflared account login, system service or inbound port changes.
        log_path = STATE_DIR / 'tunnel.log'
        log_start = log_path.stat().st_size if log_path.exists() else 0
        tunnel = launch([str(BINARY), '--no-autoupdate', 'tunnel', '--protocol', 'http2',
                         '--url', 'http://127.0.0.1:18561', '--metrics', '127.0.0.1:18562'], 'tunnel.log')
        state['tunnel_pid'] = tunnel.pid
        STATE.write_text(json.dumps(state))
        for _ in range(120):
            if tunnel.poll() is not None:
                raise RuntimeError('Temporary tunnel exited; inspect project tunnel.log')
            with open(str(log_path), 'r', errors='replace') as stream:
                stream.seek(log_start)
                log = stream.read(32768)
            urls = re.findall(r'https://[a-z0-9-]+\.trycloudflare\.com', log)
            if urls and 'Registered tunnel connection' in log:
                state['base_url'] = urls[-1] + PREFIX
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Temporary tunnel did not establish within 30 seconds')
        state['app_pid'] = enable_application(token)
        wait_local(18561, 200, token)
        state['started_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        STATE.write_text(json.dumps(state))
        print(json.dumps(state))
    except Exception:
        for key, executable in (('tunnel_pid', BINARY), ('gateway_pid', GATEWAY)):
            stop_owned(state.get(key), executable)
        state['stopped'] = True
        STATE.write_text(json.dumps(state))
        raise


def stop():
    state = read_state()
    for key, executable in (('tunnel_pid', BINARY), ('gateway_pid', GATEWAY)):
        stop_owned(state.get(key), executable)
        state.pop(key, None)
    state['stopped'] = True
    STATE.write_text(json.dumps(state))
    print(json.dumps({'stopped': True, 'scope': 'this project tunnel and gateway only'}))


if __name__ == '__main__':
    if os.name != 'posix':
        raise SystemExit('This operational script is for the Linux deployment host only')
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    if action == 'start':
        start()
    elif action == 'stop':
        stop()
    elif action == 'status':
        print(json.dumps(read_state()))
    else:
        raise SystemExit('Usage: python3 scripts/muse_tunnel_control.py start|status|stop')
