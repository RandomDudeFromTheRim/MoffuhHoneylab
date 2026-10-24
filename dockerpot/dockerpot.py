#!/usr/bin/env python3
"""Low-interaction Docker Engine API honeypot (zgw-dockerpot.service, :2375).

Bots scan TCP 2375 for an unauthenticated Docker API, then pull an image and create+start a container
that runs a cryptominer or escapes to the host via a bind mount. This EMULATES that API and runs NOTHING:
it never imports docker, never opens the real docker socket, never creates or starts a container, and makes
no outbound connection. It just answers convincingly and logs every request - above all the full
POST /containers/create body, where the miner's pool + wallet and any `/:/host` escape sit in cleartext.

Modelled on Cisco CSIRT's dhp (version/ping/image-create, 500 otherwise), extended to fake-handle
create/start/exec so the attacker's payload is captured instead of thrown away. Themed as eth-validator-03.

Safety: this is a plain HTTP responder, not a container, so there is nothing to escape. The systemd unit
denies AF_UNIX (so it physically cannot reach /var/run/docker.sock), marks the docker sockets inaccessible,
and runs as a non-root DynamicUser outside the docker group. Log: /var/lib/dockerpot/events.jsonl
"""
import datetime as dt, ipaddress, json, os, re, secrets, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EVENTS = os.environ.get("DOCKERPOT_LOG", "/var/lib/dockerpot/events.jsonl")
HOST = "example-validator"
MAX_BODY = 1 << 20
MAX_CONNECTIONS = 64
SOCKET_TIMEOUT = 15
DOCKER_VERSION = "20.10.7"      # oldish on purpose: looks juicier to scanners
API_VERSION = "1.41"
_lock = threading.Lock()
_ver_prefix = re.compile(r"^/v[0-9]+\.[0-9]+")


def hexid():
    return secrets.token_hex(32)


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def log(ip, method, path, query, body):
    """One JSON line per request. The create/exec bodies are the intel, so keep them whole (capped)."""
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "src_ip": ip,
           "method": method, "path": path}
    if query:
        rec["query"] = str(query)[:2048]
    if body:
        rec["body"] = body if isinstance(body, (dict, list)) else str(body)[:8000]
    try:
        with _lock, open(EVENTS, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


# ---- fake response bodies -----------------------------------------------------------------------
def version_json():
    return {
        "Platform": {"Name": "Docker Engine - Community"},
        "Components": [{"Name": "Engine", "Version": DOCKER_VERSION,
                        "Details": {"ApiVersion": API_VERSION, "Arch": "amd64", "BuildTime":
                                    "2021-06-02T11:56:40.000000000+00:00", "GitCommit": "b0f5bc3",
                                    "GoVersion": "go1.13.15", "KernelVersion": "5.15.0-1042-raspi",
                                    "MinAPIVersion": "1.12", "Os": "linux"}}],
        "Version": DOCKER_VERSION, "ApiVersion": API_VERSION, "MinAPIVersion": "1.12",
        "GitCommit": "b0f5bc3", "GoVersion": "go1.13.15", "Os": "linux", "Arch": "amd64",
        "KernelVersion": "5.15.0-1042-raspi", "BuildTime": "2021-06-02T11:56:40.000000000+00:00"}


def info_json():
    return {
        "ID": "VALD:ATOR:03" + hexid()[:24].upper(), "Containers": 2, "ContainersRunning": 2,
        "ContainersPaused": 0, "ContainersStopped": 0, "Images": 7, "Driver": "overlay2",
        "SystemStatus": None, "Plugins": {"Volume": ["local"], "Network": ["bridge", "host", "null"]},
        "MemoryLimit": True, "SwapLimit": True, "KernelMemory": True, "CpuCfsPeriod": True,
        "OperatingSystem": "Ubuntu 22.04.3 LTS", "OSType": "linux", "Architecture": "x86_64",
        "NCPU": 8, "MemTotal": 33568067584, "DockerRootDir": "/var/lib/docker",
        "Name": HOST, "ServerVersion": DOCKER_VERSION, "KernelVersion": "5.15.0-1042-raspi",
        "ExperimentalBuild": False, "LiveRestoreEnabled": False, "Warnings":
        ["WARNING: API is accessible on http://docker.example.invalid:2375 without encryption."]}


def fake_container(name, image, cmd, cid=None):
    return {"Id": cid or hexid(), "Names": ["/" + name], "Image": image, "ImageID": "sha256:" + hexid(),
            "Command": cmd, "State": "running", "Status": "Up 6 days",
            "Created": 1710000000, "Ports": [], "Labels": {}}


CONTAINERS = [fake_container("geth-node", "ethereum/client-go:stable",
                             "geth --mainnet --http --authrpc.jwtsecret /root/jwt.hex"),
              fake_container("lighthouse-vc", "sigp/lighthouse:latest",
                             "lighthouse vc --network mainnet")]
IMAGES = [{"Id": "sha256:" + hexid(), "RepoTags": [t], "Size": s} for t, s in
          [("ethereum/client-go:stable", 58000000), ("sigp/lighthouse:latest", 141000000),
           ("alpine:latest", 7340032), ("ubuntu:22.04", 77000000)]]

PULL_PROGRESS = ("\n".join(json.dumps(x) for x in [
    {"status": "Pulling from library/alpine", "id": "latest"},
    {"status": "Pulling fs layer", "progressDetail": {}, "id": "a0d0a0d46f8b"},
    {"status": "Downloading", "progressDetail": {"current": 7340032, "total": 7340032}, "id": "a0d0a0d46f8b"},
    {"status": "Pull complete", "progressDetail": {}, "id": "a0d0a0d46f8b"},
    {"status": "Status: Downloaded newer image", "id": "latest"}]) + "\n").encode()


class H(BaseHTTPRequestHandler):
    server_version = f"Docker/{DOCKER_VERSION} (linux)"
    protocol_version = "HTTP/1.1"

    def _ip(self):
        return self.client_address[0]

    def _send(self, code, body=b"", ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Api-Version", API_VERSION)
        self.send_header("Docker-Experimental", "false")
        self.send_header("Ostype", "linux")
        self.send_header("Server", self.server_version)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _body(self):
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self.send_error(400, "Transfer-Encoding is not supported")
            return _BODY_REJECTED
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self.close_connection = True
            self.send_error(400, "Invalid Content-Length")
            return _BODY_REJECTED
        if n < 0 or n > MAX_BODY:
            self.close_connection = True
            self.send_error(413, "Request body too large")
            return _BODY_REJECTED
        raw = self.rfile.read(n) if n else b""
        if len(raw) != n:
            self.close_connection = True
            return _BODY_REJECTED
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return raw.decode(errors="replace")

    def _route(self):
        raw = self.path.split("?", 1)
        path = _ver_prefix.sub("", raw[0]) or "/"
        query = raw[1] if len(raw) > 1 else ""
        return path, query

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path, query = self._route()
        log(self._ip(), self.command, path, query, None)
        if path == "/_ping":
            return self._send(200, "OK", "text/plain")
        if path == "/version":
            return self._send(200, version_json())
        if path == "/info":
            return self._send(200, info_json())
        if path == "/containers/json":
            return self._send(200, CONTAINERS)
        if path == "/images/json":
            return self._send(200, IMAGES)
        if re.match(r"^/containers/[^/]+/json$", path):
            return self._send(200, {"Id": hexid(), "Name": "/geth-node", "State":
                              {"Status": "running", "Running": True, "Pid": 2211},
                              "Config": {"Image": "ethereum/client-go:stable"}})
        if re.match(r"^/containers/[^/]+/logs$", path):
            return self._send(200, "INFO [sync] Imported new chain segment\n", "application/vnd.docker.raw-stream")
        return self._not_found()

    def do_POST(self):
        path, query = self._route()
        body = self._body()
        if body is _BODY_REJECTED:
            return
        log(self._ip(), self.command, path, query, body)
        if path == "/images/create":                       # pull: stream fake progress
            return self._send(200, PULL_PROGRESS)
        if path == "/containers/create":                   # THE intel: image, Cmd, Env, Binds
            return self._send(201, {"Id": hexid(), "Warnings": []})
        if re.match(r"^/containers/[^/]+/start$", path):
            return self._send(204)
        if re.match(r"^/containers/[^/]+/(stop|kill|restart|pause|unpause)$", path):
            return self._send(204)
        if re.match(r"^/containers/[^/]+/wait$", path):
            return self._send(200, {"StatusCode": 0})
        if re.match(r"^/containers/[^/]+/exec$", path):     # exec create -> returns an exec id
            return self._send(201, {"Id": hexid()})
        if re.match(r"^/exec/[^/]+/start$", path):          # exec start -> fake output
            return self._send(200, "uid=0(root) gid=0(root) groups=0(root)\n",
                              "application/vnd.docker.raw-stream")
        if path in ("/commit",) or re.match(r"^/images/[^/]+/push$", path):
            return self._send(200, {"status": "ok"})
        return self._not_found()

    def do_DELETE(self):
        path, query = self._route()
        log(self._ip(), self.command, path, query, None)
        return self._send(204)

    def _not_found(self):
        # Docker's own 404 shape, so the client sees a real daemon, not a broken one.
        self._send(404, {"message": "page not found"})

    def log_message(self, *a):
        pass


_BODY_REJECTED = object()


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server with a fixed worker cap and per-connection timeout."""
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, handler):
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def get_request(self):
        request, client = super().get_request()
        request.settimeout(SOCKET_TIMEOUT)
        return request, client

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def main():
    os.makedirs(os.path.dirname(EVENTS) or ".", exist_ok=True)
    bind = os.environ.get("DOCKERPOT_BIND", "0.0.0.0")
    port = int(os.environ.get("DOCKERPOT_PORT", "2375"))
    BoundedThreadingHTTPServer((bind, port), H).serve_forever()


if __name__ == "__main__":
    main()
