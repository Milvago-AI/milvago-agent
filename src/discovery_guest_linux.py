# Fixed metadata-only guest command, carried in the executable. Never loaded
# from a catalogue or the network. Python isolated mode ignores user modules.
import json
import os
import signal
import time

signal.alarm(5)
deadline = time.monotonic() + 4
with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
    boot = stream.read(81).strip()
rows = []
complete = True
for entry in os.scandir('/proc'):
    if not entry.name.isdecimal():
        continue
    if len(rows) >= 4096 or time.monotonic() >= deadline:
        complete = False
        break
    path = '/proc/' + entry.name
    try:
        with open(path + '/stat', 'rb') as stream:
            before = stream.read(8193)
        if len(before) > 8192:
            complete = False
            continue
        fields = before[before.rfind(b')') + 2:].split()
        start = fields[19].decode('ascii')
        executable = os.path.basename(os.readlink(path + '/exe'))
        if executable.endswith(' (deleted)'):
            executable = executable[:-len(' (deleted)')]
        tokens = []
        python_version = executable[len('python3.'):] if executable.startswith('python3.') else ''
        interpreter = executable in ('node', 'nodejs', 'python', 'python3') or (1 <= len(python_version) <= 2 and all('0' <= char <= '9' for char in python_version))
        if interpreter:
            with open(path + '/cmdline', 'rb') as stream:
                arguments = stream.read(8193)
            if len(arguments) <= 8192:
                arguments = arguments.split(b'\0')[1:3]
                first = arguments[0].decode('utf-8', errors='strict') if arguments else ''
                module = first == '-m' and executable.startswith('python')
                value = arguments[1].decode('utf-8', errors='strict') if module and len(arguments) > 1 else first
                if value and (module or not value.startswith('-')) and len(value) <= 1024:
                    parts = value.replace('\\', '/').split('/')
                    tokens.append(parts[-1].lower())
                    for left, right in zip(parts, parts[1:]):
                        if left == 'node_modules' and right in ('openclaw', 'ollama'):
                            tokens.append(right)
                        if executable.startswith('python') and left == 'hermes_cli' and right == 'main.py':
                            tokens.append('hermes_cli.main')
        # PID reuse during collection must not combine two process identities.
        with open(path + '/stat', 'rb') as stream:
            after = stream.read(8193)
        if after[after.rfind(b')') + 2:].split()[19].decode('ascii') != start:
            continue
        rows.append(dict(pid=int(entry.name), start_time=start, executable=executable, argument_tokens=sorted(set(tokens))))
    except (FileNotFoundError, ProcessLookupError):
        # Kernel threads and processes which exited have no readable executable.
        continue
    except (OSError, ValueError, IndexError, UnicodeError):
        complete = False
payload = json.dumps(dict(boot=boot, processes=rows, complete=complete), separators=(',', ':'))
if len(payload.encode('utf-8')) > 1024 * 1024:
    raise RuntimeError('projection_limit')
print(payload)
