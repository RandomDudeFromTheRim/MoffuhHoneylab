#!/usr/bin/env python3
"""Look up / submit honeypot malware samples on MalwareBazaar (abuse.ch). Manual tool, no timer.

  mb_submit.py info <sha256>            is this hash known? what family? (no upload)
  mb_submit.py upload <file> [tag ...]  upload a captured sample (default tags: cowrie, honeypot)

Auth-Key is read from the protected ABUSECH_KEY environment variable. Uses curl for the multipart upload.
Only upload WHOLE samples: a file truncated by Cowrie's download cap hashes differently from the real
malware and is useless (or misleading) to the feed. Check the on-disk size vs the real size first.
"""
import json, os, re, subprocess, sys

API = "https://mb-api.abuse.ch/api/v1/"


def key():
    value = os.environ.get("ABUSECH_KEY", "").strip()
    if not value:
        sys.exit("set ABUSECH_KEY in the protected service environment")
    return value


def curl(args):
    out = subprocess.run(["curl", "-sS", "--connect-timeout", "10", "--max-time", "120", "-H", f"Auth-Key: {key()}", *args, API],
                         capture_output=True, text=True, timeout=120)
    try:
        return json.loads(out.stdout)
    except ValueError:
        sys.exit(f"non-JSON reply: {out.stdout[:300] or out.stderr[:300]}")


def info(h):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", h):
        sys.exit("hash must be a 64-character SHA-256 hex string")
    r = curl(["-d", f"query=get_info&hash={h}"])
    status = r.get("query_status")
    if status == "hash_not_found":
        print(f"{h}: not in MalwareBazaar (new sample, or truncated/altered)")
        return
    if status != "ok":
        print(f"{h}: {status}")
        return
    d = r["data"][0]
    print(f"{h}:\n  family: {d.get('signature') or '(unclassified)'}  type: {d.get('file_type')}  "
          f"size: {d.get('file_size')}\n  first seen: {d.get('first_seen')}  "
          f"tags: {', '.join(d.get('tags') or []) or '-'}")


def upload(path, tags):
    args = ["-F", "query=upload_file", "-F", f"file=@{path}"]
    for t in (tags or ["cowrie", "honeypot"]):
        args += ["-F", f"tags[]={t}"]
    r = curl(args)
    print(json.dumps(r, indent=2))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "info":
        info(sys.argv[2])
    elif cmd == "upload":
        upload(sys.argv[2], sys.argv[3:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
