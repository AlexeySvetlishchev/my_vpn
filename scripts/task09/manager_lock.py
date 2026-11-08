#!/usr/bin/python3
"""Single-host lock spanning SQLite, secret files and AWG operations."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from manager_db import Refusal

LOCK_DIR = Path('/run/vpn-task09')
LOCK_FILE = LOCK_DIR / 'control.lock'


@contextmanager
def process_lock():
    LOCK_DIR.mkdir(mode=0o700, exist_ok=True)
    st = LOCK_DIR.lstat()
    if LOCK_DIR.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise Refusal('unsafe_lock', 'Manager lock directory ownership mismatch')
    fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600 or not stat.S_ISREG(st.st_mode):
            raise Refusal('unsafe_lock', 'Manager lock file ownership mismatch')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('busy', 'another Manager operation is running') from None
        yield
    finally:
        os.close(fd)
