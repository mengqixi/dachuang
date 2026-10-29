"""Project-only domain HTTPS gateway with bounded certificate renewal.

No Baota, Apache, Nginx, firewall or system service configuration changes.
Only the existing six read-only routes are exposed; credentials stay upstream.
"""
import json
import logging
import os
import signal
import ssl
import sys
import subprocess
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from muse_readonly_gateway import ReadOnlyGateway

ROOT = Path(__file__).resolve().parents[1]
HOSTNAME = 'dachuang-muse.duckdns.org'
CERT_DIR = ROOT / 'data/keys/muse_https' / HOSTNAME
CERT = CERT_DIR / 'fullchain.cer'
KEY = CERT_DIR / (HOSTNAME + '.key')
STATE_DIR = ROOT / 'data/muse_https'
STOP = threading.Event()


class DirectTLSGateway(ReadOnlyGateway):
    def __init__(self, port=443):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if hasattr(ssl, 'PROTOCOL_TLS_SERVER') else ssl.PROTOCOL_TLS)
        if hasattr(ssl, 'TLSVersion'):
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            for option in ('OP_NO_SSLv2', 'OP_NO_SSLv3', 'OP_NO_TLSv1', 'OP_NO_TLSv1_1'):
                self.context.options |= getattr(ssl, option, 0)
        self.context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES:!aNULL:!MD5:!DSS')
        self.context.load_cert_chain(str(CERT), str(KEY))
        super().__init__(port=port, bind_host='0.0.0.0')

    def get_request(self):
        connection, address = super().get_request()
        try:
            connection = self.context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
            return connection, address
        except Exception as error:
            logging.getLogger('muse.direct_https').warning('TLS socket setup failed: %s', type(error).__name__)
            connection.close()
            raise

    def handle_error(self, connection, address):
        error = sys.exc_info()[1]
        reason = str(getattr(error, 'reason', '') or '')
        reason = ''.join(c for c in reason if c.isupper() or c.isdigit() or c == '_')[:80]
        # No peer IP, hostname, HTTP headers, request path or secret values.
        logging.getLogger('muse.direct_https').warning('TLS/request failed: %s %s', type(error).__name__, reason)

    def reject_connection(self, connection):
        # Reject without a TLS handshake on the accept thread when saturated.
        pass


def expiry_epoch():
    result = subprocess.check_output(['openssl', 'x509', '-in', str(CERT), '-noout', '-enddate']).decode().strip()
    expires = datetime.strptime(result.split('=', 1)[1], '%b %d %H:%M:%S %Y %Z')
    return expires.replace(tzinfo=timezone.utc).timestamp()


def write_state():
    data = {'base_url': 'https://' + HOSTNAME + '/api/integrations/muse/v1/',
            'pid': os.getpid(), 'certificate_not_after_utc': datetime.fromtimestamp(expiry_epoch(), timezone.utc).isoformat(),
            'renewal': 'check every 6 hours; renew with less than 48 hours remaining',
            'read_only': True, 'transport': 'direct_https'}
    temp = STATE_DIR / 'state.json.tmp'
    temp.write_text(json.dumps(data))
    os.replace(str(temp), str(STATE_DIR / 'state.json'))


def renew_certificate(logger):
    command = ['sh', str(ROOT / 'bin-local/acme.sh'),
               '--home', str(ROOT / 'bin-local/acme-home'),
               '--config-home', str(ROOT / 'data/keys/muse_acme_production'),
               '--cert-home', str(ROOT / 'data/keys/muse_https'),
               '--server', 'https://acme-v02.api.letsencrypt.org/directory',
               '--certificate-profile', 'shortlived', '--alpn', '--keylength', '2048',
               '-d', HOSTNAME, '--renew', '--force']
    with open(str(STATE_DIR / 'acme_renew.log'), 'wb') as output:
        result = subprocess.run(command, cwd=str(ROOT), stdout=output, stderr=output, timeout=180)
    if result.returncode:
        logger.error('Certificate renewal failed; existing certificate remains in use; inspect project acme_renew.log')
    else:
        os.chmod(str(KEY), 0o600)
        logger.info('Certificate renewed successfully')


def run():
    if os.name != 'posix':
        raise SystemExit('Run this service on the Linux deployment host')
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger('muse.direct_https')
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(str(STATE_DIR / 'service.log'), maxBytes=1024 * 1024, backupCount=1)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(handler)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_args: STOP.set())
    next_check = time.monotonic()
    while not STOP.is_set():
        server = DirectTLSGateway()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        write_state()
        logger.info('Direct HTTPS listening on project-owned port 443')
        try:
            while not STOP.wait(1):
                if time.monotonic() >= next_check:
                    next_check = time.monotonic() + 6 * 3600
                    if expiry_epoch() - time.time() < 48 * 3600:
                        break
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        if STOP.is_set():
            break
        # Release only this listener for TLS-ALPN-01, never stop another service.
        try:
            renew_certificate(logger)
        except Exception as error:
            logger.error('Certificate renewal interrupted: %s', type(error).__name__)
    logger.info('Direct HTTPS gateway stopped')


if __name__ == '__main__':
    run()
