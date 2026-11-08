#!/usr/bin/python3
"""Narrow TASK 07 RU AmneziaWG interface lifecycle helper."""
from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

IFACE = "awg-client"
ALIAS_PREFIX = "vpn-task07:"
NETWORK = ipaddress.ip_network("10.203.253.0/24")
SERVER_IP = "10.203.253.1/24"
CLIENT_IP = "10.203.253.2/32"
PORT = 51821
MTU = 1280
ENDPOINT = "137.22.146.212:51821"
OWNER = "/etc/vpn-task07"
STATE_FILE = OWNER + "/state.json"
SERVER_KEY = OWNER + "/server.key"
CLIENT_KEY = OWNER + "/client.key"
CLIENT_PUB = OWNER + "/client.pub"
PROFILE = OWNER + "/Test_iPhone.conf"
EXPORT_DIR = "/home/wolffrog/task07-export"
EXPORT_PROFILE = EXPORT_DIR + "/Test_iPhone.conf"
IP = "/usr/sbin/ip"
AWG = "/opt/vpn-task07/awg"
GO = "/opt/vpn-task07/amneziawg-go"
BIN_HASHES = {
    "amneziawg-go": "f5868b52775eaa17a275dc1f8c451d585df70c816e283bccec9be2e9ec745e44",
    "awg": "6baceec819f5e6cd716cad1640073d9a6b34ae9ef4b688a7997a50b7892acbb9",
}
RUNTIME = Path("/run/vpn-task07")
SS = "/usr/bin/ss"


class Refusal(Exception):
    pass


def run(argv: list[str], *, input_text: str | None = None) -> str:
    try:
        p = subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                           timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise Refusal("required fixed system command failed")
    if p.returncode:
        raise Refusal("required fixed system command failed")
    return p.stdout.strip()


def require_root() -> None:
    if os.geteuid() != 0:
        raise Refusal("must run as root")


def ensure_owner_dir() -> None:
    p = Path(OWNER)
    if p.exists():
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode) or s.st_uid != 0:
            raise Refusal("ownership directory conflict")
        os.chmod(p, 0o700)
    else:
        p.mkdir(mode=0o700)
    for name in (STATE_FILE, SERVER_KEY, CLIENT_KEY, CLIENT_PUB, PROFILE):
        path = Path(name)
        if path.exists():
            st = path.lstat()
            if (path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                    stat.S_IMODE(st.st_mode) != 0o600):
                raise Refusal("owned file conflict")


def atomic_write(path: str, data: str, mode: int) -> None:
    target = Path(path)
    tmp = target.with_name(target.name + ".new-" + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def load_state() -> dict:
    p = Path(STATE_FILE)
    if not p.exists() or p.is_symlink():
        raise Refusal("TASK 07 ownership record missing")
    s = p.lstat()
    if s.st_uid != 0 or stat.S_IMODE(s.st_mode) != 0o600:
        raise Refusal("TASK 07 ownership record permissions mismatch")
    try:
        v = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Refusal("TASK 07 ownership record invalid")
    if (v.get("schema") != 1 or v.get("iface") != IFACE or
            not isinstance(v.get("nonce"), str) or len(v["nonce"]) != 32):
        raise Refusal("TASK 07 ownership record invalid")
    return v


def current_link() -> dict | None:
    raw = run([IP, "-j", "-d", "link", "show"])
    rows = json.loads(raw)
    return next((row for row in rows if row.get("ifname") == IFACE), None)


def check_address_conflicts() -> None:
    addresses = json.loads(run([IP, "-j", "-4", "address", "show"]))
    for link in addresses:
        for addr in link.get("addr_info", []):
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            if not local or prefix is None:
                continue
            network = ipaddress.ip_interface(f"{local}/{prefix}").network
            if link.get("ifname") == IFACE:
                continue
            if network.overlaps(NETWORK):
                raise Refusal("client subnet overlaps a live address")
    routes = json.loads(run([IP, "-j", "-4", "route", "show", "table", "all"]))
    for route in routes:
        dst = route.get("dst")
        if dst in (None, "default"):
            continue
        try:
            network = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if network.overlaps(NETWORK):
            raise Refusal("client subnet overlaps a live route")
    if run([SS, "-H", "-uan", "sport = :" + str(PORT)]):
        raise Refusal("client UDP port is already occupied")
    listening = run([AWG, "show", "all", "listen-port"])
    if any(line.split()[-1:] == [str(PORT)] for line in listening.splitlines()):
        raise Refusal("client UDP port is already occupied by AmneziaWG")


def keypair(path: str) -> tuple[str, str]:
    if Path(path).exists():
        key = Path(path).read_text(encoding="ascii").strip()
    else:
        key = run([AWG, "genkey"])
        if not key or len(key) > 128:
            raise Refusal("key generation failed")
        atomic_write(path, key + "\n", 0o600)
    pub = run([AWG, "pubkey"], input_text=key + "\n")
    if not pub or len(pub) > 128:
        raise Refusal("public key derivation failed")
    return key, pub


def render_profile(server_pub: str, client_key: str) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {client_key}\n"
        f"Address = {CLIENT_IP}\n"
        f"MTU = {MTU}\n"
        "DNS = 10.203.253.1\n"
        "Jc = 4\nJmin = 64\nJmax = 256\n"
        "S1 = 32\nS2 = 64\nS3 = 32\nS4 = 32\n"
        "H1 = 176321011-176321111\n"
        "H2 = 276321011-276321111\n"
        "H3 = 376321011-376321111\n"
        "H4 = 476321011-476321111\n\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"Endpoint = {ENDPOINT}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )


def prepare() -> None:
    require_root()
    ensure_owner_dir()
    try:
        state = load_state()
    except Refusal as exc:
        if str(exc) != "TASK 07 ownership record missing":
            raise
        state = None
    link = current_link()
    if state is None:
        if link is not None:
            raise Refusal("unowned awg-client link exists; refusing adoption")
        check_address_conflicts()
        state = {"schema": 1, "iface": IFACE, "nonce": secrets.token_hex(16),
                 "ifindex": None, "phase": "prepared", "port": PORT,
                 "network": str(NETWORK)}
        atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n", 0o600)
    elif state.get("phase") == "prepared":
        check_address_conflicts()
        if state.get("implementation") != "userspace":
            if link is not None:
                raise Refusal("client implementation migration requires an absent interface")
            state["implementation"] = "userspace"
            atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n", 0o600)
    elif state.get("phase") not in ("active",):
        raise Refusal("unfinished TASK 07 operation requires manual review")
    if state.get("phase") == "active":
        verify_owned(state, link)
    server_key, server_pub = keypair(SERVER_KEY)
    client_key, client_pub = keypair(CLIENT_KEY)
    if Path(CLIENT_PUB).exists() and Path(CLIENT_PUB).read_text().strip() != client_pub:
        raise Refusal("client public identity mismatch")
    if not Path(CLIENT_PUB).exists():
        atomic_write(CLIENT_PUB, client_pub + "\n", 0o600)
    profile = render_profile(server_pub, client_key)
    if Path(PROFILE).exists() and Path(PROFILE).read_text(encoding="ascii") != profile:
        raise Refusal("profile differs from the prepared test identity")
    if not Path(PROFILE).exists():
        atomic_write(PROFILE, profile, 0o600)


def verify_owned(state: dict, link: dict | None) -> None:
    if not link:
        raise Refusal("owned client interface is absent")
    if link.get("ifalias") != ALIAS_PREFIX + state["nonce"]:
        raise Refusal("interface ownership marker mismatch")
    if state.get("ifindex") is not None and state.get("ifindex") != link.get("ifindex"):
        raise Refusal("interface index mismatch")
    if state.get("ifindex") is None and state.get("phase") != "creating":
        raise Refusal("interface ledger lacks an index")
    if state.get("implementation") != "userspace":
        raise Refusal("client implementation mismatch")
    if link.get("linkinfo", {}).get("info_kind") not in (None, "tun"):
        raise Refusal("interface type mismatch")
    if "POINTOPOINT" not in link.get("flags", []):
        raise Refusal("interface flags mismatch")


def serve() -> None:
    require_root()
    prepare()
    state = load_state()
    link = current_link()
    if link is not None:
        raise Refusal("client interface already exists; refusing adoption")
    control = RUNTIME / "amneziawg"
    if control.exists() or control.is_symlink():
        raise Refusal("TASK 07 UAPI directory conflict")
    control.mkdir(mode=0o700)
    state["phase"] = "creating"
    atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n", 0o600)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    proc = None
    try:
        proc = subprocess.Popen([GO, "-f", IFACE], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                                     "LOG_LEVEL": "silent", "GOMAXPROCS": "1"}, close_fds=True)
        for _ in range(100):
            link = current_link()
            if link and (control / (IFACE + ".sock")).exists():
                break
            if proc.poll() is not None or stopping.wait(.1):
                raise Refusal("TASK 07 userspace process exited during setup")
        if not link:
            raise Refusal("TASK 07 userspace interface did not appear")
        run([IP, "link", "set", "dev", IFACE, "alias", ALIAS_PREFIX + state["nonce"]])
        link = current_link()
        if not link or link.get("ifalias") != ALIAS_PREFIX + state["nonce"]:
            raise Refusal("new link ownership marker could not be confirmed")
        state["ifindex"] = link["ifindex"]
        atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n", 0o600)
        _, client_pub = keypair(CLIENT_KEY)
        run([AWG, "set", IFACE, "private-key", SERVER_KEY, "listen-port", str(PORT),
             "jc", "4", "jmin", "64", "jmax", "256", "s1", "32", "s2", "64",
             "s3", "32", "s4", "32", "h1", "176321011-176321111",
             "h2", "276321011-276321111", "h3", "376321011-376321111",
             "h4", "476321011-476321111", "peer", client_pub,
             "allowed-ips", CLIENT_IP])
        run([IP, "address", "add", SERVER_IP, "dev", IFACE])
        run([IP, "link", "set", "dev", IFACE, "mtu", str(MTU), "up"])
        state["phase"] = "active"
        atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n", 0o600)
        print(json.dumps({"status": "active", "iface": IFACE, "port": PORT}), flush=True)
        while not stopping.wait(.5):
            if proc.poll() is not None:
                raise Refusal("TASK 07 userspace process exited")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        link = current_link()
        if link and link.get("ifalias") == ALIAS_PREFIX + state["nonce"]:
            down()
        elif not link:
            state["phase"] = "prepared"
            state["ifindex"] = None
            atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n", 0o600)


def export_profile() -> None:
    import pwd
    require_root()
    prepare()
    user = pwd.getpwnam("wolffrog")
    p = Path(EXPORT_DIR)
    if p.exists():
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode):
            raise Refusal("profile export directory conflict")
        if s.st_uid != user.pw_uid:
            raise Refusal("profile export directory ownership conflict")
        os.chmod(p, 0o700)
    else:
        p.mkdir(mode=0o700)
        os.chown(p, user.pw_uid, user.pw_gid)
    source = Path(PROFILE)
    data = source.read_text(encoding="ascii")
    if Path(EXPORT_PROFILE).exists() or Path(EXPORT_PROFILE).is_symlink():
        raise Refusal("an exported profile already exists; refusing overwrite")
    tmp = Path(EXPORT_PROFILE + ".new")
    if tmp.exists() or tmp.is_symlink():
        raise Refusal("temporary profile export already exists")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chown(tmp, user.pw_uid, user.pw_gid)
    os.replace(tmp, EXPORT_PROFILE)
    os.chmod(EXPORT_PROFILE, 0o600)
    print(json.dumps({"status": "export_ready", "path": EXPORT_PROFILE,
                      "mode": "0600", "contains_secret": True}))


def status() -> None:
    require_root()
    state = load_state()
    link = current_link()
    verify_owned(state, link)
    addresses = json.loads(run([IP, "-j", "-4", "address", "show", "dev", IFACE]))
    if not any(a.get("local") == "10.203.253.1" for a in addresses[0].get("addr_info", [])):
        raise Refusal("client interface address mismatch")
    port = run([AWG, "show", IFACE, "listen-port"])
    if port != str(PORT):
        raise Refusal("client interface listen port mismatch")
    hs = run([AWG, "show", IFACE, "latest-handshakes"]).split()
    peer = Path(CLIENT_PUB).read_text(encoding="ascii").strip()
    row = next((hs[i:i + 2] for i in range(0, len(hs), 2) if hs[i] == peer), None)
    age = None if not row or row[1] == "0" else max(0, int(time.time()) - int(row[1]))
    print(json.dumps({"status": "active", "iface": IFACE, "port": PORT,
                      "handshake_age_seconds": age}))


def wait_ready() -> None:
    for _ in range(100):
        try:
            status()
            return
        except Refusal:
            time.sleep(.1)
    raise Refusal("TASK 07 interface readiness timeout")


def down() -> None:
    require_root()
    state = load_state()
    link = current_link()
    if not link:
        print(json.dumps({"status": "already_down", "iface": IFACE}))
        return
    verify_owned(state, link)
    run([IP, "link", "set", "dev", IFACE, "down"])
    run([IP, "link", "delete", "dev", IFACE])
    state["phase"] = "prepared"
    state["ifindex"] = None
    atomic_write(STATE_FILE, json.dumps(state, sort_keys=True) + "\n", 0o600)
    print(json.dumps({"status": "down", "iface": IFACE}))


def clean_export() -> None:
    import pwd
    require_root()
    path = Path(EXPORT_PROFILE)
    if path.exists() or path.is_symlink():
        st = path.lstat()
        user = pwd.getpwnam("wolffrog")
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid != user.pw_uid:
            raise Refusal("profile export ownership mismatch")
        path.unlink()
    print(json.dumps({"status": "export_removed"}))


def rollback() -> None:
    require_root()
    unit = run(["/usr/bin/systemctl", "show", "-p", "ActiveState", "--value",
                "vpn-task07-client.service"])
    if unit == "active" or unit == "activating" or unit == "deactivating":
        raise Refusal("disable and stop the TASK 07 unit before rollback")
    binary_dir = Path("/opt/vpn-task07")
    if binary_dir.exists():
        st = binary_dir.lstat()
        if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or
                st.st_uid != 0 or {p.name for p in binary_dir.iterdir()} != set(BIN_HASHES)):
            raise Refusal("TASK 07 binary directory mismatch")
        for name, expected in BIN_HASHES.items():
            item = binary_dir / name
            if (item.is_symlink() or not item.is_file() or item.lstat().st_uid != 0 or
                    hashlib.sha256(item.read_bytes()).hexdigest() != expected):
                raise Refusal("TASK 07 binary ownership or hash mismatch")
    state_path = Path(STATE_FILE)
    if state_path.exists():
        state = load_state()
        link = current_link()
        if link:
            verify_owned(state, link)
            down()
    clean_export()
    owner = Path(OWNER)
    if owner.exists():
        allowed = {"state.json", "server.key", "client.key", "client.pub", "Test_iPhone.conf"}
        entries = list(owner.iterdir())
        if any(item.name not in allowed or item.is_symlink() or not item.is_file() for item in entries):
            raise Refusal("unexpected TASK 07 state; refusing removal")
        for item in entries:
            if item.lstat().st_uid != 0:
                raise Refusal("TASK 07 state ownership mismatch")
        for item in entries:
            item.unlink()
        owner.rmdir()
    export_dir = Path(EXPORT_DIR)
    if export_dir.exists():
        if export_dir.is_symlink() or not export_dir.is_dir() or any(export_dir.iterdir()):
            raise Refusal("profile export directory not empty; refusing removal")
        export_dir.rmdir()
    for path in ("/etc/systemd/system/vpn-task07-client.service", "/usr/local/sbin/vpn-task07"):
        item = Path(path)
        if item.exists():
            if item.is_symlink() or not item.is_file() or item.lstat().st_uid != 0:
                raise Refusal("TASK 07 installed file ownership mismatch")
            item.unlink()
    if binary_dir.exists():
        for name in BIN_HASHES:
            (binary_dir / name).unlink()
        binary_dir.rmdir()
    run(["/usr/bin/systemctl", "daemon-reload"])
    print(json.dumps({"status": "rolled_back", "iface": IFACE}))


def main() -> int:
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "serve", "wait-ready", "down", "status", "export", "clean-export", "rollback"}:
            raise Refusal("invalid command")
        {"prepare": prepare, "serve": serve, "wait-ready": wait_ready,
         "down": down, "status": status,
         "export": export_profile, "clean-export": clean_export,
         "rollback": rollback}[sys.argv[1]]()
        return 0
    except Refusal as e:
        # Deliberately avoid forwarding stderr or sensitive command arguments.
        print(json.dumps({"status": "blocked", "reason": str(e)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"status": "blocked", "reason": "unexpected internal error"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
