"""Real RSA/AES messaging over HTTP locally or HTTPS through Cloudflare."""
import base64
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlparse
from urllib.request import Request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encode(value):
    return base64.b64encode(value).decode('ascii')


def decode(value):
    return base64.b64decode(value, validate=True)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fingerprint(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def fetch(url, body=None, headers=None):
    request = Request(url, data=body, headers=headers or {})
    # Deliberately do not follow redirects with authentication headers.
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    with urllib.request.build_opener(NoRedirect).open(request, timeout=12) as response:
        return json.load(response)


def validate_url(url):
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Use a receiver base URL without credentials, query or fragment')
    if parsed.scheme != 'https' and not (
        parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost')):
        raise ValueError('Use HTTPS for another PC; HTTP is allowed only on localhost')
    if not parsed.hostname:
        raise ValueError('Receiver URL is missing a hostname')
    return url.rstrip('/')


def pairing_code(session, client_nonce, receiver_fingerprint):
    digest = hashlib.sha256(canonical([session, client_nonce, receiver_fingerprint])).hexdigest()[:8].upper()
    return digest[:4] + '-' + digest[4:]


def begin_pairing(url):
    url = validate_url(url)
    nonce = secrets.token_urlsafe(32)
    response = fetch(url + '/pair/start', canonical({'client_nonce': nonce}),
                     {'Content-Type': 'application/json'})
    code = pairing_code(response['session'], nonce, response['fingerprint'])
    if not hmac.compare_digest(code, response['code']):
        raise ValueError('Pairing verification failed')
    return dict(response, url=url, code=code)


def finish_pairing(pair):
    response = fetch(pair['url'] + '/pair/claim', canonical({'session': pair['session']}),
        {'Content-Type': 'application/json', 'Authorization': 'Pair ' + pair['claim']})
    if response['status'] == 'approved':
        config = response['config']
        if not hmac.compare_digest(config['fingerprint'], pair['fingerprint']):
            raise ValueError('Receiver identity changed during pairing')
        config['url'] = pair['url']
        return config
    if response['status'] != 'pending':
        raise ValueError('Pairing expired or was rejected. Connect again.')
    return None


def prepare(message, config):
    url = validate_url(config['url'])
    public = fetch(url + '/public-key')
    key = serialization.load_pem_public_key(public['pem'].encode())
    if not hmac.compare_digest(fingerprint(key), config['fingerprint']):
        raise ValueError('Receiver public-key fingerprint does not match saved connection')
    samples = [secrets.randbelow(4096) for _ in range(220)]
    sample_bytes = ','.join(map(str, samples)).encode('ascii')
    session_key = hashlib.sha256(sample_bytes).digest()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, message['text'].encode(), None)
    wrapped = key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    packet = {'id': message['id'], 'nonce': encode(nonce),
              'ciphertext': encode(ciphertext), 'wrapped_key': encode(wrapped)}
    trace = (f"SIMULATED input: 220 OS-random samples, each 0–4095\n"
             f"First 16 samples: {samples[:16]}\n"
             f"SHA-256(samples) → 32-byte AES key (key kept private)\n"
             f"AES-256-GCM → {len(ciphertext)-16} ciphertext bytes + 16-byte tag\n"
             f"Nonce: {encode(nonce)}\nCiphertext + tag: {encode(ciphertext)}\n"
             f"RSA-OAEP-SHA256 → {len(wrapped)} wrapped-key bytes\n"
             f"Packet ready for real POST /receive. Message ID: {message['id']}")
    return packet, trace


def deliver(packet, config):
    body = canonical(packet)
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    signed = timestamp.encode() + b'\n' + nonce.encode() + b'\n' + body
    signature = hmac.new(config['secret'].encode(), signed, hashlib.sha256).hexdigest()
    response = fetch(validate_url(config['url']) + '/receive', body,
        {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + config['token'],
         'X-Timestamp': timestamp, 'X-Nonce': nonce, 'X-Signature': signature})
    if response.get('id') != packet['id'] or response.get('status') not in ('received', 'already_received'):
        raise ValueError('Receiver did not acknowledge this message')
    return response


class Receiver:
    def __init__(self, directory, store, port=5055):
        self.store = store
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        key_path = directory / 'private.pem'
        if not key_path.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        secret_path = directory / 'credentials.json'
        if not secret_path.exists():
            secret_path.write_text(json.dumps({'token': secrets.token_urlsafe(32),
                'secret': secrets.token_urlsafe(48)}), encoding='utf-8')
        self.config = json.loads(secret_path.read_text(encoding='utf-8'))
        self.config.update(url=f'http://127.0.0.1:{port}', fingerprint=fingerprint(self.key.public_key()),
                           schema='cipherchaos-dsa-v1')
        self.clients_path = directory / 'paired_clients.json'
        self.clients = json.loads(self.clients_path.read_text(encoding='utf-8')) if self.clients_path.exists() else {}
        self.pair_lock = threading.Lock()
        self.pair_until = 0
        self.pair_attempts = 0
        self.pair = None
        self.nonces = {}
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, data):
                body = canonical(data)
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == '/public-key':
                    pem = owner.key.public_key().public_bytes(serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                    self.reply(200, {'pem': pem})
                elif self.path == '/health':
                    self.reply(200, {'status': 'ok'})
                else:
                    self.reply(404, {'error': 'Unknown endpoint'})

            def do_POST(self):
                if self.path in ('/pair/start', '/pair/claim'):
                    try:
                        length = int(self.headers.get('Content-Length', '0'))
                        if not 0 < length <= 2048:
                            return self.reply(400, {'error': 'Invalid pairing request'})
                        self.connection.settimeout(10)
                        payload = json.loads(self.rfile.read(length))
                        status, response = owner.pair_request(self.path, payload,
                            self.headers.get('Authorization', ''))
                        return self.reply(status, response)
                    except Exception:
                        return self.reply(400, {'error': 'Invalid pairing request'})
                if self.path != '/receive':
                    return self.reply(404, {'error': 'Unknown endpoint'})
                try:
                    authorization = self.headers.get('Authorization', '')
                    token = authorization[len('Bearer '):] if authorization.startswith('Bearer ') else ''
                    signing_secret = owner.signing_secret(token)
                    if not signing_secret:
                        return self.reply(401, {'error': 'Invalid token'})
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 32768:
                        return self.reply(413, {'error': 'Packet too large or empty'})
                    self.connection.settimeout(10)
                    body = self.rfile.read(length)
                    stamp = self.headers.get('X-Timestamp', '')
                    nonce = self.headers.get('X-Nonce', '')
                    if abs(time.time() - int(stamp)) > 120 or not 16 <= len(nonce) <= 128:
                        raise ValueError('Invalid timestamp or nonce')
                    signed = stamp.encode() + b'\n' + nonce.encode() + b'\n' + body
                    expected = hmac.new(signing_secret.encode(), signed, hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(expected, self.headers.get('X-Signature', '')):
                        return self.reply(401, {'error': 'Invalid signature'})
                    packet = json.loads(body)
                    if type(packet['id']) is not int or packet['id'] <= 0:
                        raise ValueError('Invalid ID')
                    with owner.lock:
                        now = time.time()
                        owner.nonces = {n: expiry for n, expiry in owner.nonces.items() if expiry > now}
                        if nonce in owner.nonces:
                            return self.reply(409, {'error': 'Replayed request nonce'})
                        owner.nonces[nonce] = now + 240
                        digest = hashlib.sha256(body).hexdigest()
                        previous, _ = owner.store.index.lookup(packet['id'])
                        if previous:
                            if previous.get('packet_digest') != digest:
                                return self.reply(409, {'error': 'Message ID already used by another packet'})
                            return self.reply(200, {'id': packet['id'], 'status': 'already_received'})
                        key = owner.key.decrypt(decode(packet['wrapped_key']), padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        plaintext = AESGCM(key).decrypt(decode(packet['nonce']),
                            decode(packet['ciphertext']), None).decode('utf-8')
                        owner.store.add({'id': packet['id'], 'text': plaintext, 'status': 'Received',
                            'time': time.strftime('%H:%M:%S'), 'packet_digest': digest})
                    self.reply(200, {'id': packet['id'], 'status': 'received'})
                except Exception:
                    self.reply(400, {'error': 'Invalid or unauthentic packet'})

        self.server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.server.daemon_threads = True
        self.config['url'] = f'http://127.0.0.1:{self.server.server_port}'

    def signing_secret(self, token):
        if hmac.compare_digest(token, self.config['token']):
            return self.config['secret']
        with self.pair_lock:
            client = self.clients.get(hashlib.sha256(token.encode()).hexdigest())
            return client['secret'] if client else None

    def allow_pairing(self):
        with self.pair_lock:
            self.pair_until = time.time() + 120
            self.pair_attempts = 0
            self.pair = None

    def pending_pair(self):
        with self.pair_lock:
            if self.pair and time.time() < self.pair['expires']:
                return {key: self.pair[key] for key in ('session', 'code', 'status', 'expires')}
            return None

    def approve_pair(self, session):
        with self.pair_lock:
            pair = self.pair
            if not pair or pair['session'] != session or pair['status'] != 'pending' or time.time() >= pair['expires']:
                raise ValueError('This pairing request is no longer active')
            token, secret = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            clients = dict(self.clients)
            clients[token_hash] = {'secret': secret, 'paired_at': int(time.time())}
            temp = self.clients_path.with_suffix('.tmp')
            temp.write_text(json.dumps(clients, indent=2), encoding='utf-8')
            temp.replace(self.clients_path)
            self.clients = clients
            pair['config'] = dict(self.config, token=token, secret=secret)
            pair['status'] = 'approved'
            self.pair_until = 0

    def reject_pair(self):
        with self.pair_lock:
            self.pair = None
            self.pair_until = 0

    def pair_request(self, path, payload, authorization):
        with self.pair_lock:
            now = time.time()
            if path == '/pair/start':
                if now >= self.pair_until:
                    return 403, {'error': 'Pairing closed. Click Allow pairing on receiver.'}
                if self.pair_attempts >= 5:
                    return 429, {'error': 'Pairing attempt limit reached'}
                if self.pair and now < self.pair['expires']:
                    return 409, {'error': 'A pairing request is already awaiting approval'}
                self.pair_attempts += 1
                nonce = payload.get('client_nonce')
                if not isinstance(nonce, str) or not 32 <= len(nonce) <= 128:
                    return 400, {'error': 'Invalid client nonce'}
                session, claim = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
                code = pairing_code(session, nonce, self.config['fingerprint'])
                self.pair = {'session': session, 'claim': claim, 'code': code,
                             'expires': self.pair_until, 'status': 'pending', 'claims': 0}
                return 200, {'session': session, 'claim': claim, 'code': code,
                             'fingerprint': self.config['fingerprint'], 'expires': self.pair_until}
            pair = self.pair
            if not pair or now >= pair['expires'] or payload.get('session') != pair['session']:
                return 410, {'error': 'Pairing expired or rejected'}
            pair['claims'] += 1
            if pair['claims'] > 180:
                return 429, {'error': 'Too many pairing checks'}
            if not hmac.compare_digest(authorization, 'Pair ' + pair['claim']):
                return 401, {'error': 'Invalid pairing claim'}
            if pair['status'] == 'approved':
                result = {'status': 'approved', 'config': pair.pop('config')}
                self.pair = None
                return 200, result
            return 200, {'status': 'pending'}

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
