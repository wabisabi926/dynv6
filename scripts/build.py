#!/usr/bin/env python3
"""构建 dynv6 的 .fpk 安装包（x86 / arm 双架构），并同步外部应用源 fnpack.json。

用法：
  python scripts/build.py                       # 编译 Go 并生成两个 fpk
  python scripts/build.py --skip-build          # 复用 build/bin 下已有二进制
  python scripts/build.py --base-url https://xxx/dist/   # 同时写入外部源下载地址
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
BUILD = os.path.join(ROOT, "build")
DIST = os.path.join(ROOT, "dist")
ARCHS = {"x86": "amd64", "arm": "arm64"}


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


def go_build(goarch, out, version):
    env = os.environ.copy()
    env.update({"GOOS": "linux", "GOARCH": goarch, "CGO_ENABLED": "0"})
    ldflags = "-s -w -X main.Version=" + version
    cmd = ["go", "build", "-trimpath", "-ldflags", ldflags, "-o", out, "."]
    print("编译:", " ".join(cmd), "GOARCH=" + goarch)
    subprocess.run(cmd, cwd=SRC, env=env, check=True)


def ensure_windows_icon():
    """用 rsrc 把 .ico 写进 Windows exe 资源；.syso 文件已存在且比 ico 新时跳过。"""
    syso = os.path.join(SRC, "rsrc_windows_amd64.syso")
    ico = os.path.join(ROOT, "assets", "dynv6.ico")
    if os.path.exists(syso) and os.path.getmtime(syso) >= os.path.getmtime(ico):
        return
    print("生成 Windows 图标资源...")
    rsrc = shutil.which("rsrc")
    if rsrc:
        cmd = [rsrc, "-ico", ico, "-o", syso, "-arch", "amd64"]
    else:
        cmd = ["go", "run", "github.com/akavel/rsrc@v0.10.2",
               "-ico", ico, "-o", syso, "-arch", "amd64"]
    subprocess.run(cmd, cwd=SRC, check=True)


def go_build_windows(out, version):
    env = os.environ.copy()
    env.update({"GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0"})
    ldflags = "-s -w -H windowsgui -X main.Version=" + version
    cmd = ["go", "build", "-trimpath", "-ldflags", ldflags, "-o", out, "."]
    print("编译 Windows 正式版:", " ".join(cmd))
    subprocess.run(cmd, cwd=SRC, env=env, check=True)


def make_icons(force=False):
    required = [
        os.path.join(ROOT, "ICON.PNG"),
        os.path.join(ROOT, "ICON_256.PNG"),
        os.path.join(ROOT, "app", "ui", "images", "ICON_64.PNG"),
    ]
    if force or not all(os.path.exists(p) for p in required):
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "gen_icon.py")], check=True)
    else:
        print("图标资产已存在，跳过重绘（--force-icons 可强制重绘）")
    # Go embed 需要源码目录里有一份图标，供 Windows 测试版与安装后回退使用
    embed_dir = os.path.join(SRC, "web", "images")
    os.makedirs(embed_dir, exist_ok=True)
    shutil.copy(os.path.join(ROOT, "app", "ui", "images", "ICON_64.PNG"),
                os.path.join(embed_dir, "ICON_64.PNG"))


def sync_vendor_embed():
    """把 app/vendor 的脚本同步到 src/embedded，供 Go embed 打进 Windows/Linux 二进制。"""
    src = os.path.join(ROOT, "app", "vendor")
    dst = os.path.join(SRC, "embedded")
    os.makedirs(os.path.join(dst, "dnsapi"), exist_ok=True)
    shutil.copy(os.path.join(src, "acme.sh"), os.path.join(dst, "acme.sh"))
    shutil.copy(os.path.join(src, "dnsapi", "dns_dynv6.sh"), os.path.join(dst, "dnsapi", "dns_dynv6.sh"))
    print("已同步内嵌 acme.sh 与 dns_dynv6.sh")


def add_file(tar, path, arcname, mode):
    info = tar.gettarinfo(path, arcname=arcname)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with open(path, "rb") as f:
        tar.addfile(info, f)


def add_tree(tar, root, prefix="", exec_pred=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            arc = (prefix + "/" + rel) if prefix else rel
            mode = 0o755 if (exec_pred and exec_pred(rel)) else 0o644
            add_file(tar, full, arc, mode)


def build_app_tgz(stage_app, target):
    with tarfile.open(target, "w:gz") as tar:
        add_tree(tar, stage_app, "", lambda rel: rel.startswith("bin/") or rel.endswith(".sh"))
    return hashlib.md5(open(target, "rb").read()).hexdigest()


def build_fpk(arch, version, checksum, base_url):
    """内置打包：不依赖 fnpack，直接按 fpk 格式（manifest + app.tgz）生成。

    Windows 本地构建走这里，因为 Windows 上 fnpack 打包出的文件权限是 0666，
    会丢失可执行位；Linux/CI 优先使用官方 fnpack。
    """
    name = "dynv6_%s_%s.fpk" % (version, arch)
    out = os.path.join(DIST, name)
    manifest_lines = []
    with open(os.path.join(ROOT, "manifest"), "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("platform="):
                line = "platform=" + arch
            manifest_lines.append(line)
    manifest_lines.append("checksum=" + checksum)
    manifest_text = "\n".join(manifest_lines) + "\n"
    manifest_tmp = os.path.join(BUILD, "manifest." + arch)
    with open(manifest_tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(manifest_text)

    with tarfile.open(out, "w:gz") as tar:
        add_file(tar, manifest_tmp, "manifest", 0o644)
        add_file(tar, os.path.join(BUILD, "app." + arch + ".tgz"), "app.tgz", 0o644)
        add_tree(tar, os.path.join(ROOT, "cmd"), "cmd", lambda rel: not rel.endswith(".bak"))
        add_tree(tar, os.path.join(ROOT, "config"), "config")
        add_tree(tar, os.path.join(ROOT, "wizard"), "wizard")
        for icon in ("ICON.PNG", "ICON_256.PNG"):
            add_file(tar, os.path.join(ROOT, icon), icon, 0o644)
    data = open(out, "rb").read()
    return {"name": name, "path": out, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "url": (base_url.rstrip("/") + "/" + name) if base_url else ""}


def fnpack_bin():
    """优先使用飞牛官方 fnpack；可用 DYNV6_FNPACK 指定路径。"""
    explicit = os.environ.get("DYNV6_FNPACK", "").strip()
    if explicit:
        return explicit
    if os.name == "nt":
        # Windows 上 fnpack 无法保留可执行权限位（打包为 0666），改用内置打包
        return ""
    return shutil.which("fnpack") or ""


def _chmod_tree(root, exec_files):
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            os.chmod(full, 0o755 if rel in exec_files else 0o644)


def stage_fnos(arch, version, stage_app):
    """按 fnpack 要求准备 staging：manifest + app/ + cmd/ + config/ + wizard/ + 图标。"""
    stage = os.path.join(BUILD, "fnos-" + arch)
    if os.path.exists(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)

    lines = []
    with open(os.path.join(ROOT, "manifest"), "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("platform="):
                line = "platform=" + arch
            if line.startswith("checksum="):
                continue  # 由 fnpack 重新计算
            lines.append(line)
    with open(os.path.join(stage, "manifest"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    shutil.copytree(stage_app, os.path.join(stage, "app"))
    shutil.copytree(os.path.join(ROOT, "cmd"), os.path.join(stage, "cmd"),
                    ignore=shutil.ignore_patterns("*.bak"))
    shutil.copytree(os.path.join(ROOT, "config"), os.path.join(stage, "config"))
    shutil.copytree(os.path.join(ROOT, "wizard"), os.path.join(stage, "wizard"))
    for icon in ("ICON.PNG", "ICON_256.PNG"):
        shutil.copy(os.path.join(ROOT, icon), os.path.join(stage, icon))

    # fnOS 以应用身份执行回调脚本，必须显式设置可执行位
    exec_files = {"app/bin/dynv6", "app/vendor/acme.sh", "app/vendor/dnsapi/dns_dynv6.sh"}
    exec_files.update("cmd/" + fn for fn in os.listdir(os.path.join(stage, "cmd")))
    _chmod_tree(stage, exec_files)
    return stage


def build_fpk_with_fnpack(arch, version, base_url, stage_app, fnpack):
    """调用官方 fnpack 打包，产物校验由 release.py 的 check_fpk 负责。"""
    name = "dynv6_%s_%s.fpk" % (version, arch)
    out = os.path.join(DIST, name)
    stage = stage_fnos(arch, version, stage_app)
    print("fnpack 打包:", arch, "->", stage)
    subprocess.run([fnpack, "build"], cwd=stage, check=True)
    produced = [fn for fn in os.listdir(stage) if fn.endswith(".fpk")]
    if not produced:
        raise SystemExit("fnpack 未生成 .fpk: " + stage)
    if os.path.exists(out):
        os.remove(out)
    shutil.move(os.path.join(stage, produced[0]), out)
    data = open(out, "rb").read()
    return {"name": name, "path": out, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "url": (base_url.rstrip("/") + "/" + name) if base_url else ""}


def update_source(results, version, base_url, icon_url):
    path = os.path.join(ROOT, "fnpack.json")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    app = doc.get("apps", {}).get("dynv6", {})
    if icon_url:
        app["icon_url"] = icon_url
    releases = app.get("releases", {})
    rel = releases.get(version)
    if not rel:
        raise SystemExit("fnpack.json 中缺少版本节点 %s；请先添加该版本再打包，避免把新包哈希写进旧版本" % version)
    packages = rel.setdefault("packages", {})
    for arch, info in results.items():
        node = packages.setdefault(arch, {})
        node["sha256"] = info["sha256"]
        node["size"] = info["size"]
        if info["url"]:
            node["download_url"] = info["url"]
    rel["updated_at"] = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("已更新 fnpack.json 的 sha256 / size" + (" / download_url" if base_url else "") + (" / icon_url" if icon_url else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true", help="复用 build/bin 下已有二进制")
    ap.add_argument("--base-url", default="https://github.com/wabisabi926/dynv6/releases/latest/download", help="外部源下载地址前缀，用于填充 fnpack.json")
    ap.add_argument("--icon-url", default="https://raw.githubusercontent.com/wabisabi926/dynv6/main/ICON_256.PNG", help="外部源图标地址")
    ap.add_argument("--arch", choices=["x86", "arm", "all"], default="all")
    ap.add_argument("--force-icons", action="store_true", help="强制重新绘制图标")
    args = ap.parse_args()

    ver = read_manifest().get("version", "1.0.0")
    os.makedirs(BUILD, exist_ok=True)
    os.makedirs(DIST, exist_ok=True)
    make_icons(args.force_icons)
    sync_vendor_embed()
    ensure_windows_icon()

    targets = list(ARCHS.keys()) if args.arch == "all" else [args.arch]
    stage_app = os.path.join(BUILD, "stage_app")
    results = {}
    fnpack = fnpack_bin()
    if fnpack:
        print("使用飞牛官方 fnpack 打包:", fnpack)
    else:
        print("未找到 fnpack，使用内置打包（产物格式一致，权限位由脚本显式设置）")

    for arch in targets:
        binname = "dynv6-" + ARCHS[arch]
        binpath = os.path.join(BUILD, "bin", binname)
        if not args.skip_build:
            go_build(ARCHS[arch], binpath, ver)
        if not os.path.exists(binpath):
            raise SystemExit("缺少二进制: " + binpath)

        if os.path.exists(stage_app):
            shutil.rmtree(stage_app)
        os.makedirs(os.path.join(stage_app, "bin"))
        os.makedirs(os.path.join(stage_app, "ui", "www"))
        shutil.copytree(os.path.join(ROOT, "app", "vendor"), os.path.join(stage_app, "vendor"))
        shutil.copy(os.path.join(ROOT, "app", "ui", "config"), os.path.join(stage_app, "ui", "config"))
        shutil.copytree(os.path.join(ROOT, "app", "ui", "images"), os.path.join(stage_app, "ui", "images"))
        for fn in ("index.html", "app.js", "style.css"):
            shutil.copy(os.path.join(SRC, "web", fn), os.path.join(stage_app, "ui", "www", fn))
        shutil.copy(binpath, os.path.join(stage_app, "bin", "dynv6"))

        if fnpack:
            info = build_fpk_with_fnpack(arch, ver, args.base_url, stage_app, fnpack)
        else:
            app_tgz = os.path.join(BUILD, "app." + arch + ".tgz")
            checksum = build_app_tgz(stage_app, app_tgz)
            info = build_fpk(arch, ver, checksum, args.base_url)
        results[arch] = info
        print("已生成 %s (%d 字节, sha256=%s)" % (info["name"], info["size"], info["sha256"][:16] + "..."))

    win_out = os.path.join(DIST, "dynv6_%s_windows.exe" % ver)
    go_build_windows(win_out, ver)
    print("Windows 正式版:", win_out, os.path.getsize(win_out), "字节")

    update_source(results, ver, args.base_url, args.icon_url)
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "gen_preview.py")], check=True)
    print("完成。安装包位于:", DIST)


if __name__ == "__main__":
    main()
