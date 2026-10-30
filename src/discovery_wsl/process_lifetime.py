# The WSL relay owns this process. Closing the Windows control channel must
# also end the reader, including when it is silent or blocked on its own work.
import ctypes
import os
import signal

_parent = os.getppid()
if _parent <= 1:
    os._exit(125)
_libc = ctypes.CDLL(None, use_errno=True)
_prctl = _libc.prctl
_prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
_prctl.restype = ctypes.c_int
if _prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != _parent:
    os._exit(125)
del _libc, _prctl, _parent
