#!/usr/bin/env python3
"""JSON-lines helper for tests/e2e/run.sh (stdlib only).

Event files are the stdout of `vq-host` and `PhoneSim`: one JSON object per
line. Predicates are Python expressions over `e` (the event); extra
`name=value` arguments become variables in the expression (strings), and
`json` is available. A predicate that raises (e.g. KeyError) is false.

  e2e.py wait FILE AFTER TIMEOUT EXPR [k=v ...]   first match after line AFTER; prints it
  e2e.py count FILE AFTER EXPR [k=v ...]          number of matches after line AFTER
  e2e.py expect-count FILE AFTER N EXPR [k=v ...] fail unless exactly N matches
  e2e.py lines FILE                               number of complete lines
  e2e.py get JSON PATH                            field of a JSON object, e.g. entry.id
  e2e.py log-check LOG_DIR HOST_EVENTS...         log files == what the events imply
  e2e.py log-count LOG_DIR NEEDLE                 occurrences of NEEDLE in all log files
  e2e.py render TEXT_JSON                         the core's inert log rendering of a text
"""

import json
import os
import sys
import time
import unicodedata


def die(msg):
    print(f"e2e.py: {msg}", file=sys.stderr)
    sys.exit(1)


def read_events(path, after=0):
    """Complete lines after line number `after`, parsed."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return []
    lines = data.split(b"\n")[:-1]  # drop a torn last line
    out = []
    for raw in lines[after:]:
        try:
            out.append(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError) as exc:
            die(f"{path}: not a JSON line: {raw[:200]!r} ({exc})")
    return out


def predicate(expr, kv):
    env = {"json": json}
    for item in kv:
        k, _, v = item.partition("=")
        env[k] = v
    code = compile(expr, "<predicate>", "eval")

    def test(e):
        try:
            return bool(eval(code, dict(env, e=e)))  # noqa: S307 (test helper)
        except (KeyError, TypeError, IndexError, AttributeError):
            return False

    return test


# --- the core's log rendering (desktop/core/src/logger.rs) ---------------

BIDI = {0x061C, 0x200E, 0x200F, 0x2028, 0x2029} | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def needs_escape(c):
    return (unicodedata.category(c) == "Cc" and c != "\t") or ord(c) in BIDI


def inert(s, escape_tab):
    return "".join(
        f"\\u{{{ord(c):x}}}" if needs_escape(c) or (escape_tab and c == "\t") else c for c in s
    )


def render_text(text):
    out = []
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        out.append("  " + inert(line, False) + "\n")
    return "".join(out)


def render_entry(entry):
    hex8 = entry["id"].replace("-", "")[:8]
    edited = " · edited" if entry["state"] == "edit" else ""
    head = f"- **{entry['time']}** · {inert(entry['device_name'], True)} · `id={hex8}`{edited}\n"
    return head + render_text(entry["text"])


def expected_logs(host_files):
    """{date: file content} implied by the accepted final/edit revisions."""
    days = {}
    for path in host_files:
        for e in read_events(path):
            if e.get("event") != "entry_upserted":
                continue
            entry = e["entry"]
            if entry["state"] not in ("final", "edit"):
                continue
            day = entry["received_at"][:10]
            days.setdefault(day, f"# Ventriloquist — {day}\n\n")
            days[day] += render_entry(entry)
    return days


def log_files(log_dir):
    if not os.path.isdir(log_dir):
        return {}
    out = {}
    for name in sorted(os.listdir(log_dir)):
        if name.endswith(".md"):
            with open(os.path.join(log_dir, name), "rb") as f:
                out[name[:-3]] = f.read().decode("utf-8")
    return out


def main(argv):
    if len(argv) < 2:
        die(__doc__)
    cmd, args = argv[1], argv[2:]
    if cmd == "wait":
        path, after, timeout, expr, kv = args[0], int(args[1]), float(args[2]), args[3], args[4:]
        test = predicate(expr, kv)
        deadline = time.monotonic() + timeout
        while True:
            for e in read_events(path, after):
                if test(e):
                    print(json.dumps(e, ensure_ascii=False))
                    return
            if time.monotonic() >= deadline:
                die(f"timeout ({timeout:g}s) waiting in {os.path.basename(path)} for: {expr} {' '.join(kv)}")
            time.sleep(0.05)
    elif cmd == "count":
        path, after, expr, kv = args[0], int(args[1]), args[2], args[3:]
        test = predicate(expr, kv)
        print(sum(1 for e in read_events(path, after) if test(e)))
    elif cmd == "expect-count":
        path, after, n, expr, kv = args[0], int(args[1]), int(args[2]), args[3], args[4:]
        test = predicate(expr, kv)
        got = sum(1 for e in read_events(path, after) if test(e))
        if got != n:
            die(f"expected {n} match(es) in {os.path.basename(path)}, got {got}: {expr} {' '.join(kv)}")
    elif cmd == "lines":
        try:
            with open(args[0], "rb") as f:
                print(f.read().count(b"\n"))
        except FileNotFoundError:
            print(0)
    elif cmd == "get":
        value = json.loads(args[0])
        for part in args[1].split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
        print(value if isinstance(value, str) else json.dumps(value))
    elif cmd == "log-check":
        log_dir, host_files = args[0], args[1:]
        want, got = expected_logs(host_files), log_files(log_dir)
        if want.keys() != got.keys():
            die(f"log files: expected {sorted(want)}, found {sorted(got)}")
        for day in want:
            if want[day] != got[day]:
                import difflib

                diff = "".join(
                    difflib.unified_diff(
                        want[day].splitlines(True), got[day].splitlines(True), "expected", "actual"
                    )
                )
                die(f"log {day}.md differs from the accepted final/edit events:\n{diff}")
    elif cmd == "log-count":
        log_dir, needle = args[0], args[1]
        print(sum(content.count(needle) for content in log_files(log_dir).values()))
    elif cmd == "render":
        sys.stdout.write(render_text(json.loads(args[0])))
    else:
        die(f"unknown command {cmd}")


if __name__ == "__main__":
    main(sys.argv)
