"""Run in an offline Linux namespace; only synthetic loopback services are used."""
import http.server
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROCESS = (ROOT / 'src/discovery_guest_linux.py').read_text(encoding='utf-8')
HTTP = PROCESS + (ROOT / 'src/discovery_guest_http_linux.py').read_text(encoding='utf-8')


class GuestHttp(unittest.TestCase):
    def run_probe(self, request=None, source=HTTP):
        arguments = [sys.executable, '-I', '-S', '-c', source]
        if request is not None:
            arguments.append(json.dumps(request, separators=(',', ':')))
        return subprocess.run(arguments, capture_output=True, timeout=7, env={
            'HTTP_PROXY': 'http://127.0.0.1:1',
            'HTTPS_PROXY': 'http://127.0.0.1:1',
            'NO_PROXY': '',
        })

    def test_listener_rotation_reaches_a_custom_port_beyond_the_first_window(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(1)

            def log_message(self, *arguments):
                pass

            def do_GET(self):
                body = b'rotation-target' if self.server.target else b'other-service'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        servers, selector = [], selectors.DefaultSelector()
        stop = threading.Event()
        thread = None
        try:
            for _ in range(17):
                server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
                server.timeout = 1
                servers.append(server)
            servers.sort(key=lambda server: server.server_port)
            for index, server in enumerate(servers):
                server.target = index == 16
                selector.register(server, selectors.EVENT_READ, server)

            def serve():
                # One wait loop keeps seventeen idle listeners from competing
                # with the bounded probe on a small guest's two virtual CPUs.
                while not stop.is_set():
                    for key, _ in selector.select(.1):
                        key.data.handle_request()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            target = servers[-1].server_port
            for offset in [0, 16]:
                started_at = time.monotonic()
                result = self.run_probe({'paths': ['/'], 'offset': offset})
                self.assertEqual(result.returncode, 0, result.stderr)
                projection = json.loads(result.stdout)['http']
                self.assertLessEqual(len(projection['responses']), 16)
                self.assertFalse(projection['complete'])
                found = any(row['port'] == target and row['body'] == 'rotation-target'
                    for row in projection['responses'])
                diagnostic = {
                    'fixture_http_failure': True, 'fixture': 'listener-rotation',
                    'offset': offset, 'target': target,
                    'elapsed': time.monotonic() - started_at,
                    'responses': [(row['port'], row['status'], len(row['body']))
                        for row in projection['responses']],
                }
                if found != (offset == 16):
                    print(json.dumps(diagnostic), flush=True)
                self.assertEqual(found, offset == 16, diagnostic)
        finally:
            stop.set()
            if thread is not None:
                thread.join(timeout=2)
            selector.close()
            for server in servers:
                server.server_close()
            if thread is not None:
                self.assertFalse(thread.is_alive())

    def test_actual_guest_loopback_and_dynamic_ports_redirect_size_drip_and_legacy(self):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *arguments):
                pass

            def do_GET(self):
                requests.append(self.path)
                self.connection.settimeout(1)
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/not-requested-by-policy')
                    self.end_headers()
                    return
                if self.path == '/large':
                    self.send_response(200)
                    self.send_header('Content-Length', '65537')
                    self.end_headers()
                    return
                if self.path == '/drip':
                    self.send_response(200)
                    self.send_header('Content-Length', '20')
                    self.end_headers()
                    try:
                        for _ in range(20):
                            self.wfile.write(b'x')
                            self.wfile.flush()
                            time.sleep(.05)
                    except OSError:
                        pass
                    return
                body = b'Ollama is running' if self.path == '/' else b'{"status":"ok"}'
                self.send_response(200)
                self.send_header('Content-Type', 'Application/JSON; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        ready = threading.Event()

        class Server(http.server.ThreadingHTTPServer):
            def service_actions(self):
                ready.set()

        server = Server(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        try:
            self.assertTrue(ready.wait(2), 'fixture selector did not start')
            before = len(os.listdir('/proc/self/fd'))
            legacy = self.run_probe(source=PROCESS)
            self.assertEqual(legacy.returncode, 0, legacy.stderr)
            self.assertNotIn('http', json.loads(legacy.stdout))
            self.assertEqual(requests, [])
            for _ in range(5):
                result = self.run_probe({'paths': ['/', '/health', '/redirect', '/large', '/drip'], 'offset': 0})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertLessEqual(len(result.stdout), 1024 * 1024)
                data = json.loads(result.stdout)
                self.assertIn('boot', data)
                self.assertIn('processes', data)
                projection = data['http']
                self.assertFalse(projection['complete'])
                rows = [row for row in projection['responses'] if row['port'] == server.server_port]
                observed = {row['path'] for row in rows}
                if observed != {'/', '/health'}:
                    print(json.dumps({'fixture_http_failure': True, 'expected_port': server.server_port,
                                      'responses': [{'port': row['port'], 'path': row['path'], 'status': row['status']}
                                                    for row in projection['responses']]}), flush=True)
                self.assertEqual(observed, {'/', '/health'})
                self.assertTrue(all(row['status'] == 200 for row in rows))
                self.assertTrue(all(row['content_type'] == 'application/json' for row in rows))
                self.assertNotIn('/not-requested-by-policy', requests)
            time.sleep(.5)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_malformed_requests_are_rejected_without_a_projection(self):
        invalid = [
            {'paths': [], 'offset': 0},
            {'paths': ['/', '/'], 'offset': 0},
            {'paths': ['//127.0.0.1/'], 'offset': 0},
            {'paths': ['/../secret'], 'offset': 0},
            {'paths': ['/?token=fixture'], 'offset': 0},
            {'paths': ['data:image/png'], 'offset': 0},
            {'paths': [{'image': 'fixture'}], 'offset': 0},
            {'paths': ['/'], 'offset': True},
            {'paths': ['/'], 'offset': -1},
            {'paths': ['/'], 'offset': 4294967296},
            {'paths': ['/'], 'offset': 0, 'command': 'fixture'},
        ]
        for request in invalid:
            result = self.run_probe(request)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')

    def test_stalled_listener_leaves_time_for_a_later_healthy_listener(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *arguments):
                pass

            def do_GET(self):
                if self.server.stalled:
                    time.sleep(2)
                body = b'Ollama is running'
                try:
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

        servers = sorted([http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                          for _ in range(2)], key=lambda server: server.server_port)
        threads = []
        for index, server in enumerate(servers):
            server.stalled = index == 0
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever,
                kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            threads.append(thread)
        try:
            started = time.monotonic()
            source = HTTP.replace('deadline = time.monotonic() + 4',
                'qa_started = time.monotonic()\ndeadline = time.monotonic() + 4', 1)
            source = source.replace('def emit(payload):',
                "def emit(payload):\n    print(json.dumps({'probe_budget_elapsed': time.monotonic() - qa_started}), file=sys.stderr)", 1)
            result = self.run_probe({'paths': ['/', '/one', '/two', '/three', '/four'], 'offset': 0}, source=source)
            self.assertEqual(result.returncode, 0, result.stderr)
            elapsed = time.monotonic() - started
            probe_elapsed = json.loads(result.stderr)['probe_budget_elapsed']
            if elapsed >= 4:
                print(json.dumps({'fixture_http_failure': 'probe_timing', 'wall_seconds': elapsed,
                    'probe_budget_seconds': probe_elapsed}), flush=True)
            self.assertLess(elapsed, 4)
            self.assertLess(probe_elapsed, 4)
            projection = json.loads(result.stdout)['http']
            healthy = [row for row in projection['responses'] if row['port'] == servers[1].server_port]
            self.assertEqual({row['path'] for row in healthy}, {'/', '/one', '/two', '/three', '/four'})
            self.assertFalse(projection['complete'])
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=2)

    def test_missing_optional_http_module_preserves_process_inventory(self):
        import_failure = '''
import builtins
original_import = builtins.__import__
def fixture_import(name, *args, **kwargs):
    if name == 'http.client':
        raise ImportError('synthetic minimal guest standard library')
    return original_import(name, *args, **kwargs)
builtins.__import__ = fixture_import
'''
        source = PROCESS + import_failure + (ROOT / 'src/discovery_guest_http_linux.py').read_text(encoding='utf-8')
        result = self.run_probe({'paths': ['/'], 'offset': 0}, source=source)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data['processes'])
        self.assertIn('boot', data)
        self.assertEqual(data['http'], {'complete': False, 'responses': []})


if __name__ == '__main__':
    unittest.main()
