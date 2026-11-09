#!/usr/bin/env python3
"""打包一个版本的全部产物。

产物：dist/ 下的 x86 / arm fpk、Windows exe、Linux 独立二进制与 SHA256SUMS.txt；
--notes-out 写出该版本的更新日志（取自 .changes/v<版本>.md）。
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
DIST = os.path.join(ROOT, "dist")
CHANGES = os.path.join(ROOT, ".changes")

FPK_TOP_ALLOWED = re.compile(
    r"^(?:manifest|app\.tgz|ICON\.PNG|ICON_256\.PNG|(?:cmd|config|wizard)(?:/.*)?)$"
)
FORBIDDEN = re.compile(
    r"(?:^|/)(?:admin\.json|config\.json|\.env(?:\..*)?)$"
    r"|\.(?:pfx|p12|pem|key|jks|keystore|log|crt)$"
    r"|(?:^|/)(?:etc|data|logs|var)/",
    re.IGNORECASE,
)


def log(msg):
    print(msg, flush=True)


def read_manifest():
    data = {}
    with open(os.path.join(ROOT, "manifest"), "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def update_manifest(version, summary):
    """同步安装包 manifest 的版本与一行更新日志。"""
    path = os.path.join(ROOT, "manifest")
    lines = []
    seen_version = seen_changelog = False
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.rstrip("\n")
            if raw.startswith("version="):
                lines.append("version=" + version)
                seen_version = True
            elif raw.startswith("changelog="):
                lines.append("changelog=%s %s" % (version, summary))
                seen_changelog = True
            else:
                lines.append(raw)
    if not seen_version:
        raise SystemExit("manifest 缺少 version= 行")
    if not seen_changelog:
        lines.append("changelog=%s %s" % (version, summary))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def read_changelog(version):
    path = os.path.join(CHANGES, "v%s.md" % version)
    if not os.path.isfile(path):
        raise SystemExit("缺少更新日志: " + path)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        raise SystemExit("更新日志为空: " + path)
    return text


def summarize(text):
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", ">", "```", "|")):
            continue
        s = re.sub(r"^[-*+]\s*", "", s)
        if s:
            return s[:160]
    return "版本更新"


def run_build(base_url):
    cmd = [sys.executable, os.path.join(ROOT, "scripts", "build.py"), "--base-url", base_url]
    log("执行: " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def norm(name):
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def check_fpk(path, version):
    with tarfile.open(path, "r:*") as tar:
        members = [m for m in tar.getmembers() if not m.isdir() and norm(m.name)]
        names = {norm(m.name) for m in members}
        for name in names:
            if not FPK_TOP_ALLOWED.match(name):
                raise SystemExit("%s 顶层多余文件: %s" % (path, name))
        if "manifest" not in names or "app.tgz" not in names:
            raise SystemExit("%s 缺少 manifest 或 app.tgz" % path)
        manifest = next(m for m in members if norm(m.name) == "manifest")
        text = tar.extractfile(manifest).read().decode("utf-8", "ignore")
        if "version=%s" % version not in text:
            raise SystemExit("%s 版本号不是 %s" % (path, version))
        app_member = next(m for m in members if norm(m.name) == "app.tgz")
        with tarfile.open(fileobj=tar.extractfile(app_member), mode="r:*") as app:
            for m in app.getmembers():
                if m.isdir():
                    continue
                name = norm(m.name)
                if not name:
                    continue
                if FORBIDDEN.search(name):
                    raise SystemExit("%s app.tgz 包含禁止文件: %s" % (path, name))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksums(files):
    path = os.path.join(DIST, "SHA256SUMS.txt")
    lines = ["%s  %s" % (sha256(p), os.path.basename(p)) for p in files]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="版本号，可带 v 前缀")
    ap.add_argument("--tag", default="", help="兼容旧参数，未使用")
    ap.add_argument("--notes-out", default=os.path.join(BUILD, "release_notes.md"))
    ap.add_argument("--skip-build", action="store_true", help="复用 build/bin 下的二进制")
    ap.add_argument("--base-url", default="", help="fnpack.json 中的下载地址前缀")
    args = ap.parse_args()

    version = args.version.lstrip("v")
    changelog = read_changelog(version)
    update_manifest(version, summarize(changelog))

    if os.path.isdir(DIST):
        for name in os.listdir(DIST):
            path = os.path.join(DIST, name)
            if os.path.isfile(path) and version not in name:
                os.remove(path)

    base_url = args.base_url or "https://github.com/wabisabi926/dynv6/releases/download/v" + version
    if args.skip_build:
        log("复用已有二进制")
    else:
        run_build(base_url)

    os.makedirs(DIST, exist_ok=True)
    for arch, suffix in (("amd64", "linux_amd64"), ("arm64", "linux_arm64")):
        src = os.path.join(BUILD, "bin", "dynv6-" + arch)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(DIST, "dynv6_%s_%s" % (version, suffix)))

    for name in sorted(os.listdir(DIST)):
        if name.endswith(".fpk"):
            check_fpk(os.path.join(DIST, name), version)

    files = [
        os.path.join(DIST, name)
        for name in sorted(os.listdir(DIST))
        if os.path.isfile(os.path.join(DIST, name)) and name != "SHA256SUMS.txt"
    ]
    for path in files:
        log("%9d  %s" % (os.path.getsize(path), os.path.basename(path)))
    log("校验和: " + write_checksums(files))

    notes_dir = os.path.dirname(os.path.abspath(args.notes_out))
    os.makedirs(notes_dir, exist_ok=True)
    with open(args.notes_out, "w", encoding="utf-8", newline="\n") as f:
        f.write(changelog + "\n")
    log("更新日志: " + args.notes_out)


if __name__ == "__main__":
    main()
