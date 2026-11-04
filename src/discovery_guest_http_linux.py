
# Appended to the fixed process probe only when signed HTTP and guest execution
# are both authorized. Literal guest loopback only; never proxy or redirect.
if len(sys.argv) != 2 or len(sys.argv[1]) > 16384:
    raise RuntimeError('invalid_guest_http_request')
request = json.loads(sys.argv[1])
if not isinstance(request, dict) or set(request) != {'paths', 'offset'}:
    raise RuntimeError('invalid_guest_http_request')
paths = request['paths']
offset = request['offset']
if (not isinstance(paths, list) or not 1 <= len(paths) <= 32
        or not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 4294967295):
    raise RuntimeError('invalid_guest_http_request')
for path in paths:
    if (not isinstance(path, str) or not path.startswith('/') or len(path) > 256
            or '//' in path or any(part in ('.', '..') for part in path.split('/'))
            or not all(char.isascii() and (char.isalnum() or char in '/._-~') for char in path)):
        raise RuntimeError('invalid_guest_http_request')
if len(set(paths)) != len(paths):
    raise RuntimeError('invalid_guest_http_request')
try:
    import http.client
except (ImportError, OSError):
    # A minimal guest Python installation may omit HTTP support. Preserve the
    # existing process inventory instead of losing all positive observations.
    payload['http'] = dict(complete=False, responses=[])
    emit(payload)
    raise SystemExit(0)
# IPv6 and TLS-only listeners are not covered by this adapter.
http_complete = False
ports = set()
try:
    with open('/proc/net/tcp', encoding='ascii') as stream:
        table = stream.read(1024 * 1024 + 1)
    if len(table) > 1024 * 1024:
        raise RuntimeError('listener_limit')
    for index, line in enumerate(table.splitlines()[1:]):
        if index >= 4096:
            http_complete = False
            break
        columns = line.split()
        if len(columns) < 4 or columns[3] != '0A':
            continue
        address, port = columns[1].split(':')
        if address in ('00000000', '0100007F') and 0 < int(port, 16) <= 65535:
            ports.add(int(port, 16))
except (OSError, ValueError, RuntimeError, IndexError):
    http_complete = False
ports = sorted(ports)
if ports:
    cursor = offset % len(ports)
    ports = ports[cursor:] + ports[:cursor]
if len(ports) > 16:
    http_complete = False
ports = ports[:16]
cursor = offset % len(paths)
paths = paths[cursor:] + paths[:cursor]
responses = []
http_bytes = 0
attempts = 0
http_deadline = min(deadline, time.monotonic() + 2.5)


def http_timeout(signum, frame):
    raise TimeoutError('guest_http_timeout')


signal.signal(signal.SIGALRM, http_timeout)
for port in ports:
    port_deadline = min(http_deadline, time.monotonic() + 1.0) if len(ports) > 1 else http_deadline
    for path in paths:
        remaining = port_deadline - time.monotonic()
        if remaining <= 0 or attempts >= 128 or http_bytes >= 131072:
            http_complete = False
            break
        attempts += 1
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=min(remaining, 0.75))
        # Socket timeouts alone restart on each read. Bound the entire request,
        # including a peer which sends headers or a body one byte at a time.
        signal.setitimer(signal.ITIMER_REAL, min(remaining, 0.75))
        try:
            connection.request('GET', path, headers={
                'Accept': 'text/html, application/json, application/manifest+json',
                'User-Agent': 'Milvago-Discovery/1', 'Connection': 'close'})
            response = connection.getresponse()
            if not 100 <= response.status <= 599 or 300 <= response.status <= 399:
                http_complete = False
                continue
            length = response.getheader('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) > 65536):
                http_complete = False
                continue
            body = response.read(min(65537, 131073 - http_bytes))
            if len(body) > 65536 or http_bytes + len(body) > 131072:
                http_complete = False
                continue
            body = body.decode('utf-8', errors='strict')
            content_type = response.getheader('Content-Type')
            if content_type is not None:
                if len(content_type) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in content_type):
                    http_complete = False
                    continue
                content_type = content_type.split(';', 1)[0].strip().lower()
            http_bytes += len(body.encode('utf-8'))
            responses.append(dict(port=port, path=path, status=response.status,
                                  content_type=content_type, body=body))
        except (OSError, ValueError, UnicodeError, http.client.HTTPException):
            http_complete = False
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            connection.close()
    if time.monotonic() >= http_deadline or attempts >= 128 or http_bytes >= 131072:
        break
payload['http'] = dict(complete=http_complete, responses=responses)
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.alarm(1)
emit(payload)
