# -*- coding: utf-8 -*-
"""更新 GitHub Release v1.0.2 的说明为 .changes/v1.0.2.md 内容"""
import json
import os
import subprocess
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 1. 取 token：优先 /tmp/gh_token（Git Bash /tmp 映射），否则从 git credential 获取
token = ""
for cand in (
    os.path.join(os.environ.get("TEMP", ""), "gh_token"),
    r"C:\Program Files\WorkBuddy\resources\app.asar.unpacked\cli\vendor\tmp\gh_token",
):
    if os.path.exists(cand):
        token = open(cand, encoding="utf-8", errors="ignore").read().strip()
        if token:
            break
if not token:
    q = subprocess.run(
        ["git", "-C", ROOT, "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True, text=True,
    )
    for line in q.stdout.splitlines():
        if line.startswith("password="):
            token = line[len("password="):].strip()
            break
if not token:
    raise SystemExit("未获取到 GitHub token")

# 2. 读更新日志
notes = open(os.path.join(ROOT, ".changes", "v1.0.2.md"), encoding="utf-8").read().strip()
body = (
    "## Dynv6 管家 v1.0.2\n\n"
    + notes
    + "\n\n---\n\n"
    "**校验**：所有产物附带 `SHA256SUMS.txt` 及其 cosign keyless 签名"
    "（`SHA256SUMS.txt.sigstore.json`）。飞牛安装请下载对应架构的 `.fpk`"
    "（x86=amd64 / arm=arm64）。\n"
)

req = urllib.request.Request(
    "https://api.github.com/repos/wabisabi926/dynv6/releases/tags/v1.0.2",
    data=json.dumps({"body": body}).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "User-Agent": "dynv6-release",
    },
    method="PATCH",
)
with urllib.request.urlopen(req, timeout=30) as resp:
    r = json.load(resp)
print("Release 说明已更新，最终长度:", len(r["body"]), "字符")
print("assets:", [a["name"] for a in r["assets"]])
