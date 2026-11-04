# Kernel-backed fixture: a silent reader must die with its relay, not on stdout.
import json
import os
import signal
import subprocess
import sys
import time

def timed_out(_signum, _frame):
    raise TimeoutError('lifetime fixture exceeded its wall budget')


signal.signal(signal.SIGALRM, timed_out)
signal.alarm(8)
guard = sys.stdin.read(16385)
assert 0 < len(guard) <= 16384


def running(pid):
    try:
        with open('/proc/' + str(pid) + '/stat', encoding='ascii') as stream:
            value = stream.read(8193)
        assert len(value) <= 8192
        return value[value.rfind(')') + 2:].split()[0] not in ('Z', 'X')
    except FileNotFoundError:
        return False


for enabled in (False, True):
    worker = (guard if enabled else '') + '\nimport os,signal,time\nsignal.alarm(6)\nprint(os.getpid(),flush=True)\ntime.sleep(5)\n'
    parent = '''import os,signal,subprocess,sys
signal.alarm(7)
child=subprocess.Popen([sys.executable,'-I','-S','-c',SCRIPT],stdout=subprocess.PIPE,text=True,env={'PATH':'/usr/bin:/bin'})
print(child.stdout.readline(64).strip(),flush=True)
sys.stdin.read(1)
os._exit(0)
'''.replace('SCRIPT', repr(worker))
    relay = subprocess.Popen([sys.executable, '-I', '-S', '-c', parent], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env={'PATH': '/usr/bin:/bin'})
    pidfd = None
    try:
        value = relay.stdout.readline(64).strip()
        assert value.isdecimal() and 1 < int(value) < 2**31
        pid = int(value)
        pidfd = os.pidfd_open(pid)
        assert running(pid)
        relay.stdin.write('x')
        relay.stdin.flush()
        assert relay.wait(timeout=2) == 0
        deadline = time.monotonic() + 0.75
        while running(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert running(pid) != enabled, 'reader lifetime did not match its relay guard'
    finally:
        if pidfd is not None:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(pidfd)
        if relay.poll() is None:
            relay.kill()
            relay.wait(timeout=2)
        relay.stdin.close()
        relay.stdout.close()
print(json.dumps({'guarded_reader_terminated': True, 'unguarded_reader_survived': True}))
