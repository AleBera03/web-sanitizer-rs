"""Bring up the whole test stack and submit every evil-origin scenario to it.

The script starts what is missing and then runs the corpus:

    docker image + container   `evil-origin.zip` from the GitHub release,
                               then `just load-image` and `just run-image`
    sanitizer on :3000         via `just serve`, spawned as a child process
    scenarios                  read from the origin's `GET /scenarios`

Anything already running is reused and left alone.
The spawned sanitizer is stopped again when the run ends.
"""

import argparse
import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "evil-origin"
IMAGE_TAR = ROOT / "scenarios" / "evil-origin.tar"
IMAGE_ZIP = ROOT / "scenarios" / "evil-origin.zip"
IMAGE_MEMBER = "evil-origin.tar"
IMAGE_RELEASE = ("https://github.com/AleBera03/web-sanitizer-rs/releases"
                 "/download/evil-origin-v1/evil-origin.zip")

# markers that must not survive in sanitised output
DANGER = [
    ("<script", re.compile(rb"<script", re.I)),
    ("javascript:", re.compile(rb"javascript:", re.I)),
    ("on*= handler", re.compile(rb"\son(?:click|error|load|mouseover)\s*=", re.I)),
    ("meta refresh", re.compile(rb"http-equiv\s*=\s*[\"']?refresh", re.I)),
    ("<iframe", re.compile(rb"<iframe", re.I)),
    ("<object", re.compile(rb"<object", re.I)),
    ("<embed", re.compile(rb"<embed", re.I)),
    ("data: uri", re.compile(rb"data:text/html", re.I)),
    ("expression(", re.compile(rb"expression\s*\(", re.I)),
    ("@import", re.compile(rb"@import", re.I)),
    ("169.254.169.254", re.compile(rb"(?<![\w.-])169\.254\.169\.254(?![\w.-])")),
    ("/JavaScript", re.compile(rb"/JavaScript")),
    ("/OpenAction", re.compile(rb"/OpenAction")),
]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="http://localhost:3000",
                        help="sanitizer base URL")
    parser.add_argument("--origin", default="http://localhost:3100",
                        help="evil-origin base URL")
    parser.add_argument("--scenarios",
                        help="read the corpus from this JSON file instead of the origin")
    parser.add_argument("--out", help="write the full results as JSON to this path")
    parser.add_argument("--timeout", type=int, default=45,
                        help="per-request timeout in seconds")
    parser.add_argument("--category", help="run only this category")
    parser.add_argument("--no-setup", action="store_true",
                        help="assume both services are already running")
    parser.add_argument("--image-url", default=IMAGE_RELEASE,
                        help="release asset holding the evil-origin image")
    parser.add_argument("--boot-timeout", type=int, default=300,
                        help="seconds to wait for a service to answer after starting it")
    return parser.parse_args()


# http

def request(url, payload, timeout):
    """Send one request and return the HTTP code with the raw body."""
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data, headers=headers), timeout=timeout
        ) as response:
            return response.status, response.read(), None
    except urllib.error.HTTPError as error:
        return error.code, error.read(), None
    except (urllib.error.URLError, OSError) as error:
        return None, None, str(getattr(error, "reason", error))


def request_json(url, payload, timeout):
    code, body, transport = request(url, payload, timeout)
    if transport is not None:
        return code, None, transport
    try:
        return code, json.loads(body), None
    except json.JSONDecodeError:
        return code, None, "non-JSON response"


def is_up(url, timeout=2):
    code, _, transport = request(url, None, timeout)
    return transport is None and code is not None


def wait_until_up(url, label, deadline_seconds, child=None):
    """Poll a health URL until it answers, giving up after the deadline."""
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if is_up(url):
            return True
        if child is not None and child.poll() is not None:
            print(f"    {label} exited with code {child.returncode}")
            return False
        time.sleep(0.5)
    print(f"    {label} did not answer within {deadline_seconds}s")
    return False



def just(recipe):
    """Run a justfile recipe from the repository root."""
    executable = shutil.which("just")
    if executable is None:
        sys.exit("just is not on PATH")
    result = subprocess.run([executable, recipe], cwd=ROOT)
    return result.returncode == 0


def prepared(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def docker_has_image():
    executable = shutil.which("docker")
    if executable is None:
        sys.exit("docker is not on PATH")
    result = subprocess.run([executable, "image", "inspect", IMAGE],
                            capture_output=True)
    return result.returncode == 0


def download_image_zip(url):
    """Fetch the release asset holding the image tarball."""
    if IMAGE_ZIP.exists():
        return True

    print(f"    downloading {url}")
    partial = IMAGE_ZIP.with_suffix(".part")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, \
                open(prepared(partial), "wb") as handle:
            shutil.copyfileobj(response, handle)
    except (urllib.error.URLError, OSError) as error:
        partial.unlink(missing_ok=True)
        print(f"    download failed: {getattr(error, 'reason', error)}")
        return False

    partial.replace(IMAGE_ZIP)
    print(f"    {IMAGE_ZIP.name} is {IMAGE_ZIP.stat().st_size // 1024 // 1024} MiB")
    return True


def extract_image_tar(url):
    """Unpack the image tarball out of the release archive."""
    if IMAGE_TAR.exists():
        return True
    if not download_image_zip(url):
        return False

    print(f"    extracting {IMAGE_MEMBER}")
    try:
        with zipfile.ZipFile(IMAGE_ZIP) as archive:
            # one named member, so no archive-controlled path is ever joined
            with archive.open(IMAGE_MEMBER) as source, \
                    open(prepared(IMAGE_TAR), "wb") as target:
                shutil.copyfileobj(source, target)
    except (zipfile.BadZipFile, KeyError, OSError) as error:
        IMAGE_TAR.unlink(missing_ok=True)
        print(f"    cannot read {IMAGE_ZIP.name}: {error}")
        return False
    return True


def ensure_origin(args):
    """Load the image if needed and start the evil-origin container."""
    if is_up(args.origin.rstrip("/") + "/scenarios"):
        print("==> evil-origin already listening")
        return True

    print("==> starting evil-origin")
    if not docker_has_image():
        if not extract_image_tar(args.image_url):
            return False
        if not just("load-image"):
            return False
    if not just("run-image"):
        return False
    return wait_until_up(args.origin.rstrip("/") + "/scenarios", "evil-origin",
                         args.boot_timeout)


def start_server(args):
    """Spawn `just serve` as a child process and wait for its health endpoint.

    Returns the child, or None when a sanitizer is already listening. The child
    gets its own process group.
    """
    health = args.server.rstrip("/") + "/health"
    if is_up(health):
        print("==> sanitizer already listening")
        return None

    print("==> starting sanitizer (just serve)")
    executable = shutil.which("just")
    if executable is None:
        sys.exit("just is not on PATH")

    if os.name == "nt":
        spawn = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        spawn = {"start_new_session": True}
    child = subprocess.Popen([executable, "serve"], cwd=ROOT, **spawn)

    if not wait_until_up(health, "sanitizer", args.boot_timeout, child):
        stop_server(child)
        return False
    return child


def leaf_processes(pid):
    """The bottom of the process tree below pid, `just` and `cargo` excluded."""
    if shutil.which("pgrep") is None:
        return []
    leaves, frontier = [], [pid]
    while frontier:
        parent = frontier.pop()
        found = subprocess.run(["pgrep", "-P", str(parent)],
                               capture_output=True, text=True)
        children = [int(line) for line in found.stdout.split()]
        if children:
            frontier.extend(children)
        elif parent != pid:
            leaves.append(parent)
    return leaves


def stop_server(child):
    """Ask the spawned sanitizer to shut down and wait for the chain to end.

    Only the server itself is signalled, so `cargo` and `just` observe a clean
    exit code instead of dying mid-flight and reporting a signal.
    """
    if not child or child.poll() is not None:
        return
    print("==> stopping sanitizer")
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(child.pid)],
                       capture_output=True)
    else:
        targets = leaf_processes(child.pid)
        for pid in targets or [child.pid]:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
        child.wait()



def load_scenarios(args):
    if args.scenarios:
        with open(args.scenarios) as handle:
            return json.load(handle)["scenarios"]

    url = args.origin.rstrip("/") + "/scenarios"
    _, document, transport = request_json(url, None, args.timeout)
    if document is None:
        sys.exit(f"cannot read the corpus from {url}: {transport}")
    return document["scenarios"]


def inspect(document):
    """Decode the sanitised output and look for markers that should be gone."""
    encoded = document.get("content")
    if not encoded:
        return 0, [], ""
    decoded = base64.b64decode(encoded)
    leaked = [label for label, pattern in DANGER if pattern.search(decoded)]
    preview = decoded[:220].decode("utf-8", "replace")
    return len(decoded), leaked, preview


def run_scenarios(args, scenarios):
    endpoint = args.server.rstrip("/") + "/v1/resources"
    results = []

    for scenario in scenarios:
        url = args.origin.rstrip("/") + scenario["path"]
        started = time.monotonic()
        code, document, transport = request_json(endpoint, {"url": url}, args.timeout)
        elapsed = round((time.monotonic() - started) * 1000)

        row = {
            "category": scenario["category"],
            "name": scenario["name"],
            "url": url,
            "expected": scenario["metadata"]["expectedSanitizerBehavior"],
            "wall_ms": elapsed,
            "http": code,
        }

        if document is None:
            row["transport"] = transport
            print(f"{scenario['category']:9} {scenario['name']:28} {transport}", flush=True)
            results.append(row)
            continue

        report = document.get("report") or {}
        out_len, leaked, preview = inspect(document)
        row.update({
            "status": report.get("status"),
            "bytes_in": report.get("bytes_in"),
            "bytes_out": report.get("bytes_out"),
            "duration_ms": report.get("duration_ms"),
            "actions": [action.get("rule_id") for action in report.get("actions", [])],
            "report_error": report.get("error"),
            "error": document.get("error") or document.get("detail"),
            "assets": len(document.get("assets", [])),
            "subresources": len(report.get("subresources") or []),
            "out_len": out_len,
            "leaked": leaked,
            "preview": preview,
        })

        print(
            f"{row['category']:9} {row['name']:28} {code:>3} {str(row['status']):16} "
            f"actions={len(row['actions']):<2} leaked={','.join(leaked) or '-'}",
            flush=True,
        )
        results.append(row)

    return results


def main():
    args = parse_args()

    child = None
    if not args.no_setup:
        if not ensure_origin(args):
            sys.exit("evil-origin is not available")
        child = start_server(args)
        if child is False:
            sys.exit("the sanitizer did not come up")

    try:
        scenarios = load_scenarios(args)
        if args.category:
            scenarios = [s for s in scenarios if s["category"] == args.category]
        if not scenarios:
            sys.exit("no scenario matched")

        results = run_scenarios(args, scenarios)

        leaking = sum(1 for row in results if row.get("leaked"))
        print(f"\n{len(results)} scenarios, {leaking} returned a dangerous marker")

        if args.out:
            try:
                with open(prepared(args.out), "w") as handle:
                    json.dump(results, handle, indent=2)
            except OSError as error:
                print(f"cannot write {args.out}: {error}")
            else:
                print(f"full results written to {args.out}")
    finally:
        stop_server(child)


if __name__ == "__main__":
    main()