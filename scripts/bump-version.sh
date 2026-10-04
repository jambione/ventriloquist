#!/usr/bin/env bash
# Set the app version everywhere. Usage: scripts/bump-version.sh X.Y.Z
# Updates the desktop app (tauri.conf.json, Cargo.toml, package.json,
# package-lock.json), Cargo.lock, and the iOS app (ios/App/project.yml).
# iOS build number rule: CURRENT_PROJECT_VERSION = major*10000 + minor*100 + patch
# (0.2.2 -> 202, 1.4.7 -> 10407). Makes no git commit or tag.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

V="${1:-}"
if [[ ! "$V" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "usage: $0 X.Y.Z (plain semver, e.g. 0.2.3)" >&2
  exit 1
fi
IFS=. read -r MAJ MIN PAT <<<"$V"
if (( MIN > 99 || PAT > 99 )); then
  echo "minor and patch must be <= 99 (iOS build number rule)" >&2
  exit 1
fi
BUILD=$(( MAJ * 10000 + MIN * 100 + PAT ))

VQ_V="$V" VQ_BUILD="$BUILD" python3 - <<'PY'
import json, os, re
v, build = os.environ["VQ_V"], os.environ["VQ_BUILD"]
D = "desktop/app/"

def rw(path, fn):
    s = open(path).read()
    n = fn(s)
    if n != s:
        open(path, "w").write(n)
    print(f"  {path}")

def sub1(pat, rep, s, flags=re.M):
    n, c = re.subn(pat, rep, s, count=1, flags=flags)
    assert c == 1, pat
    return n

rw(D + "src-tauri/tauri.conf.json",
   lambda s: sub1(r'^(\s*"version":\s*)"[^"]*"', r'\g<1>"%s"' % v, s))
# Only the [package] version line (first top-level `version =`).
rw(D + "src-tauri/Cargo.toml",
   lambda s: sub1(r'^version = "[^"]*"', 'version = "%s"' % v, s))
rw(D + "package.json",
   lambda s: sub1(r'^(\s*"version":\s*)"[^"]*"', r'\g<1>"%s"' % v, s))

def lock(s):
    d = json.loads(s)
    d["version"] = v
    d["packages"][""]["version"] = v
    return json.dumps(d, indent=2, ensure_ascii=False) + "\n"
rw(D + "package-lock.json", lock)

def cargo_lock(s):
    return re.sub(r'(name = "ventriloquist-desktop"\nversion = )"[^"]*"',
                  r'\g<1>"%s"' % v, s)
rw("Cargo.lock", cargo_lock)

def yml(s):
    s = sub1(r'^(\s*MARKETING_VERSION:\s*)"[^"]*"', r'\g<1>"%s"' % v, s)
    return sub1(r'^(\s*CURRENT_PROJECT_VERSION:\s*)"[^"]*"', r'\g<1>"%s"' % build, s)
rw("ios/App/project.yml", yml)
PY

echo
echo "Version set to $V (iOS build $BUILD)."
echo "Next:"
echo "  git commit -am \"Release v$V\""
echo "  git tag v$V && git push origin main v$V"
