#!/usr/bin/env python3
"""发布流程编排：版本同步 -> 中文更新日志 -> 敏感信息检查 -> 构建 -> 产物校验 -> 校验和/发布说明。

用法：
  python scripts/release.py --version 1.0.1 --tag v1.0.1
  python scripts/release.py --version 1.0.1 --skip-build     # 只做版本/日志/检查，复用已有 dist

做了什么：
  1. 用 tag 版本号覆盖 manifest 的 version / changelog；
  2. 从 .changes/v<版本>.md 读取中文更新日志（缺失直接失败）；
  3. 在 fnpack.json 中创建/更新该版本节点（changelog 取日志首条要点）；
  4. 提交前扫描仓库，阻止配置里的真实 Token / 密码 / 私钥 / 证书文件混入；
  5. 调用 build.py 生成飞牛 fpk（x86/arm）与 Windows exe，并收集 Linux 独立二进制；
  6. 逐个校验 fpk 内容白名单（只允许程序、UI、安装脚本与图标）；
  7. 生成 dist/SHA256SUMS.txt 与 build/release_notes.md（中文 GitHub Release 说明）。
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
BUILD = os.path.join(ROOT, "build")
DIST = os.path.join(ROOT, "dist")
CHANGES = os.path.join(ROOT, ".changes")

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")

# fpk 顶层只允许这些成员；其余一律视为打包错误
FPK_TOP_ALLOWED = re.compile(
    r"^(?:manifest|app\.tgz|ICON\.PNG|ICON_256\.PNG|(?:cmd|config|wizard)(?:/.*)?)$"
)
# app.tgz 内只允许程序本体与 Web UI
APP_ALLOWED = re.compile(r"^(?:bin/dynv6|ui(?:/.*)?)$")
# 任何层级出现这些内容都直接判定失败（本地配置、管理员密码、证书私钥、日志）
FORBIDDEN_MEMBER = re.compile(
    r"(?:^|/)(?:admin\.json|config\.json|\.env(?:\..*)?)$"
    r"|\.(?:pfx|p12|pem|key|jks|keystore|log|crt)$"
    r"|(?:^|/)(?:etc|data|logs|var)/",
    re.IGNORECASE,
)
# 仓库里绝不应该出现的文件
FORBIDDEN_TRACKED = re.compile(
    r"(?:^|/)(?:admin\.json|config\.json|\.env(?:\..*)?)$"
    r"|\.(?:pfx|p12|pem|key|jks|keystore)$",
    re.IGNORECASE,
)
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "私钥内容"),
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), "Telegram Bot Token"),
]
# 只扫 .json，避免源码里的字段名误报；真实配置一旦被提交就会命中
JSON_SECRET = re.compile(r'"(token|pfx_password|p12_password|tg_bot_token)"\s*:\s*"([^"\n]*)"')
PLACEHOLDERS = {"", "__KEEP__", "__CLEAR__", "**************", "changeme", "example", "test"}


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
    """同步安装包 manifest 的版本与一行更新日志（fpk 安装器会展示）。"""
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


def load_changelog(version, tag):
    candidates = [
        os.path.join(CHANGES, "v%s.md" % version),
        os.path.join(CHANGES, "%s.md" % version),
        os.path.join(CHANGES, "%s.md" % tag),
    ]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                text = f.read().strip()
            if not text:
                raise SystemExit("更新日志为空: " + path)
            return path, text
    raise SystemExit(
        "缺少中文更新日志：请先创建 .changes/v%s.md（参考 .changes/v1.0.0.md）" % version
    )


def summarize(text):
    """取更新日志里第一行正文，作为 fnpack / manifest 的一行摘要。"""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(">") or s.startswith("```") or s.startswith("|"):
            continue
        s = re.sub(r"^[-*+]\s*", "", s)
        s = re.sub(r"^\d+[.)]\s*", "", s)
        if s:
            return s[:160]
    return "版本更新"


def ensure_source_release(version, summary):
    """在 fnpack.json 中确保存在该版本节点；哈希由 build.py 回填。"""
    path = os.path.join(ROOT, "fnpack.json")
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    app = doc.get("apps", {}).get("dynv6")
    if not app:
        raise SystemExit("fnpack.json 缺少 apps.dynv6 节点")
    releases = app.setdefault("releases", {})
    rel = releases.setdefault(version, {})
    rel["changelog"] = summary
    rel.setdefault("packages", {})
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")


def iter_repo_files():
    git = shutil.which("git")
    if git and os.path.isdir(os.path.join(ROOT, ".git")):
        out = subprocess.run([git, "ls-files", "-z"], cwd=ROOT, capture_output=True)
        if out.returncode == 0:
            return [p.decode("utf-8", "ignore") for p in out.stdout.split(b"\0") if p]
    files = []
    roots = ["src", "scripts", "app", "cmd", "config", "wizard", ".changes", ".github"]
    skip = {".git", "dist", "build", "node_modules", ".cache"}
    for rel_root in roots:
        base = os.path.join(ROOT, rel_root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                files.append(os.path.relpath(os.path.join(dirpath, fn), ROOT).replace(os.sep, "/"))
    for fn in os.listdir(ROOT):
        if os.path.isfile(os.path.join(ROOT, fn)):
            files.append(fn)
    return files


def scan_sensitive():
    """发布前拦截：真实凭据文件、配置里的真实 Token/密码、私钥、Telegram Token。"""
    issues = []
    for rel in iter_repo_files():
        if FORBIDDEN_TRACKED.search(rel):
            issues.append("%s：不应提交的凭据/证书文件" % rel)
            continue
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path) or os.path.getsize(path) > 2 * 1024 * 1024:
            continue
        if rel.endswith((".png", ".jpg", ".jpeg", ".ico", ".syso", ".fpk", ".exe", ".tgz")):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="strict") as f:
                text = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                issues.append("%s：疑似%s" % (rel, label))
        if rel.endswith(".json"):
            for m in JSON_SECRET.finditer(text):
                key, value = m.group(1), m.group(2)
                if value.strip() in PLACEHOLDERS:
                    continue
                if value.startswith("$") or value.startswith("{{") or value.startswith("<"):
                    continue
                if len(value) >= 8:
                    issues.append('%s：%s 疑似真实值（请改为空值或占位符）' % (rel, key))
    return sorted(set(issues))


def run_build(base_url, skip_build):
    cmd = [sys.executable, os.path.join(ROOT, "scripts", "build.py"), "--base-url", base_url]
    if skip_build:
        cmd.append("--skip-build")
    log("执行: " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def check_fpk(path, version, arch):
    problems = []
    with tarfile.open(path, "r:gz") as tar:
        for name in tar.getnames():
            if not FPK_TOP_ALLOWED.match(name):
                problems.append("顶层多余文件: " + name)
            if FORBIDDEN_MEMBER.search(name):
                problems.append("顶层禁止文件: " + name)
        for member in tar.getmembers():
            if member.name in ("cmd/main", "cmd/install_init") and not member.mode & 0o111:
                problems.append(member.name + " 缺少可执行权限")
        manifest_name = "manifest"
        if manifest_name not in tar.getnames():
            problems.append("缺少 manifest")
        else:
            text = tar.extractfile(manifest_name).read().decode("utf-8", "ignore")
            fields = {}
            for line in text.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    fields[key.strip()] = value.strip()
            if fields.get("version") != version:
                problems.append("manifest 版本不是 " + version)
            if fields.get("platform") != arch:
                problems.append("manifest 架构不是 " + arch)
        if "app.tgz" not in tar.getnames():
            problems.append("缺少 app.tgz")
        else:
            inner_bytes = tar.extractfile("app.tgz").read()
            with tarfile.open(fileobj=io.BytesIO(inner_bytes), mode="r:gz") as inner:
                for member in inner.getmembers():
                    name = member.name
                    if member.isdir():
                        continue
                    if name == "bin/dynv6" and not member.mode & 0o111:
                        problems.append("app.tgz 中 bin/dynv6 缺少可执行权限")
                    # 官方 fnpack 会把顶层 config/privilege、config/resource 一并放进 app.tgz
                    if name in ("config/privilege", "config/resource"):
                        continue
                    if not APP_ALLOWED.match(name):
                        problems.append("app.tgz 多余文件: " + name)
                    if FORBIDDEN_MEMBER.search(name):
                        problems.append("app.tgz 禁止文件: " + name)
    return problems


def collect_linux_bins(version, enabled):
    """把 build.py 为 fpk 编译的 Linux 二进制另存为独立下载项。"""
    out = []
    if not enabled:
        return out
    for goarch in ("amd64", "arm64"):
        src = os.path.join(BUILD, "bin", "dynv6-" + goarch)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(DIST, "dynv6_%s_linux_%s" % (version, goarch))
        shutil.copy2(src, dst)
        try:
            os.chmod(dst, 0o755)
        except OSError:
            pass
        out.append(dst)
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def write_checksums(files):
    lines = []
    for path in sorted(files, key=lambda p: os.path.basename(p)):
        lines.append("%s  %s" % (sha256(path), os.path.basename(path)))
    out = os.path.join(DIST, "SHA256SUMS.txt")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return out, lines


def platform_label(name):
    if name.endswith("_x86.fpk"):
        return "飞牛 fnOS x86_64（.fpk 手动安装）"
    if name.endswith("_arm.fpk"):
        return "飞牛 fnOS ARM64（.fpk 手动安装）"
    if name.endswith("_windows.exe"):
        return "Windows 10/11 x64（免安装单文件）"
    if name.endswith("_linux_amd64"):
        return "Linux x86_64 独立二进制"
    if name.endswith("_linux_arm64"):
        return "Linux ARM64 独立二进制"
    if name == "SHA256SUMS.txt":
        return "SHA256 校验和"
    return "其他"


def trim_changelog(text):
    """只保留更新条目，去掉「安全」小节及其后的内容。"""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"^#{1,3}\s*安全", s):
            break
        if not out and re.match(r"^#{1,3}\s*[\d.]", s):
            continue
        out.append(line)
    return "\n".join(out).strip()


def render_notes(version, tag, changelog, artifacts):
    return "## Dynv6 管家 %s\n\n%s\n" % (tag, trim_changelog(changelog))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="版本号，可带 v 前缀")
    ap.add_argument("--tag", default="", help="发布 tag，默认 v<版本>")
    ap.add_argument("--notes-out", default=os.path.join(BUILD, "release_notes.md"))
    ap.add_argument("--skip-build", action="store_true", help="复用 dist 中已有产物")
    ap.add_argument("--no-linux", action="store_true", help="不附带 Linux 独立二进制")
    ap.add_argument("--base-url", default="", help="fnpack.json 中的下载地址前缀")
    args = ap.parse_args()

    version = args.version.strip().lstrip("v")
    if not VERSION_RE.match(version):
        raise SystemExit("版本号格式不正确: " + args.version)
    tag = args.tag.strip() or ("v" + version)
    repo = os.environ.get("GITHUB_REPOSITORY", "wabisabi926/dynv6")
    base_url = args.base_url or "https://github.com/%s/releases/download/%s" % (repo, tag)

    log("发布版本: %s（tag %s）" % (version, tag))
    changelog_path, changelog = load_changelog(version, tag)
    log("使用更新日志: " + os.path.relpath(changelog_path, ROOT))
    summary = summarize(changelog)

    issues = scan_sensitive()
    if issues:
        log("\n发现可能泄露的敏感信息，已中止发布：")
        for item in issues:
            log("  - " + item)
        log("\n处理方式：删除对应文件或把值改为空/占位符，并确认这些文件未被 git 跟踪。")
        raise SystemExit(1)
    log("敏感信息检查通过")

    update_manifest(version, summary)
    ensure_source_release(version, summary)

    if not args.skip_build:
        if os.path.isdir(DIST):
            shutil.rmtree(DIST)
        os.makedirs(DIST, exist_ok=True)
        run_build(base_url, False)
    else:
        os.makedirs(DIST, exist_ok=True)
        log("跳过构建，复用 dist 中已有产物")

    expected = [
        os.path.join(DIST, "dynv6_%s_x86.fpk" % version),
        os.path.join(DIST, "dynv6_%s_arm.fpk" % version),
        os.path.join(DIST, "dynv6_%s_windows.exe" % version),
    ]
    for path in expected:
        if not os.path.isfile(path):
            raise SystemExit("缺少产物: " + path)

    for arch in ("x86", "arm"):
        path = os.path.join(DIST, "dynv6_%s_%s.fpk" % (version, arch))
        problems = check_fpk(path, version, arch)
        if problems:
            log("\n%s 内容校验失败：" % os.path.basename(path))
            for item in problems:
                log("  - " + item)
            raise SystemExit(1)
        log("已校验 %s（仅程序/UI/安装脚本）" % os.path.basename(path))

    artifacts = list(expected) + collect_linux_bins(version, not args.no_linux)
    sums_path, sums_lines = write_checksums(artifacts)
    artifacts.append(sums_path)

    os.makedirs(BUILD, exist_ok=True)
    notes = render_notes(version, tag, changelog, artifacts)
    with open(args.notes_out, "w", encoding="utf-8", newline="\n") as f:
        f.write(notes)
    log("发布说明: " + args.notes_out)
    log("校验和:")
    for line in sums_lines:
        log("  " + line)
    log("完成，产物位于: " + DIST)


if __name__ == "__main__":
    main()
