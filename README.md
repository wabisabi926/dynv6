# Dynv6 管家

dynv6 动态域名（DDNS）自动更新 + Let's Encrypt 证书自动签发、续期与分发的单二进制工具。

适配飞牛 fnOS（fpk）、Windows（免安装 exe）、通用 Linux 与 Docker，界面为内置的本地 Web UI，无需额外安装数据库或运行时。

## 功能

- **DDNS**：支持 IPv4 / IPv6，公网 IP 变化时自动调用 dynv6 API 更新记录，支持强制更新与手动触发。
- **证书**：内置纯 Go ACME 客户端（lego），通过 dynv6 DNS-01 签发 Let's Encrypt 证书并自动续期，不依赖 sh / curl / openssl；支持泛域名、EC/RSA 密钥长度切换。
- **分发**：证书可导出 PEM，并自动生成 Emby 使用的 PFX、Plex 使用的 P12，输出路径与文件名均可自定义。
- **通知**：支持 Telegram 等通知渠道，任务成功/失败均可推送。
- **调度**：内置定时任务，IP 探测、DDNS、证书检查按设定间隔运行；日志自动轮转。
- **鉴权**：所有部署形态统一使用本地管理员账号（PBKDF2-SHA256 加盐存储）；飞牛网关注入的身份仅用于界面显示用户名，不作为权限凭据。

## 端口

所有平台统一使用 **8092**：

| 平台 | 监听方式 | 访问方式 |
| --- | --- | --- |
| 飞牛 fnOS | 固定 8092，由飞牛网关反向代理 | 飞牛桌面打开应用，无需端口映射 |
| Windows | `127.0.0.1:8092` | 托盘图标打开，或访问 `http://127.0.0.1:8092/` |
| 通用 Linux | `127.0.0.1:8092` | 本机浏览器访问 `http://127.0.0.1:8092/` |
| Docker | 容器内 `0.0.0.0:8092` | compose 默认只映射 `127.0.0.1:8092`，本机访问 `http://127.0.0.1:8092/` |

可用 `DYNV6_DEV_PORT`（本地模式）或 `DYNV6_LISTEN`（服务模式）覆盖默认端口。

## 安装

### 飞牛 fnOS

1. 按设备架构下载 `dynv6_<版本>_x86.fpk`（x86_64）或 `dynv6_<版本>_arm.fpk`（ARM64）；
2. 飞牛「应用中心 → 手动安装」，选择 fpk；
3. 安装后在飞牛桌面打开「Dynv6 管家」。

应用固定监听 8092 并由飞牛网关反向代理，**不需要开放防火墙端口，也不需要做端口映射**。

### Windows

下载 `dynv6_<版本>_windows.exe` 双击运行，托盘图标右键可打开界面或数据目录。首次启动会自动生成一次性本地访问令牌，请从托盘打开，不要直接访问裸端口。

### 通用 Linux

```bash
chmod +x dynv6_<版本>_linux_amd64
./dynv6_<版本>_linux_amd64
```

默认监听 `127.0.0.1:8092`，控制台会打印带一次性令牌的访问地址。

### Docker

镜像以固定非 root 用户 `10001` 运行，宿主机挂载目录需先授权：

```bash
mkdir -p ./data && sudo chown -R 10001:10001 ./data
docker run -d --name dynv6 --restart unless-stopped \
  -p 127.0.0.1:8092:8092 \
  -v ./data:/data \
  ghcr.io/wabisabi926/dynv6:1.0.2
```

或使用仓库内的 `docker-compose.yml`（固定版本标签 `1.0.2`，默认只绑定本机、非 root、日志限制 10MB×3）：

```bash
docker compose up -d
```

然后访问 `http://127.0.0.1:8092/`，首次进入创建管理员账号。服务模式（Docker / 反向代理）会生成一次性初始化令牌，先取回：

```bash
docker logs dynv6 2>&1 | grep "首次初始化令牌"
# 或查看数据目录中的 setup-token 文件（0600）
```

在初始化页面填入该令牌即可，成功后文件自动删除。配置、状态、`admin.json` 与证书均在 `/data`，升级前请备份该目录；需要局域网或公网访问时请在容器前加 HTTPS 反向代理，不要直接把 8092 暴露到公网。

## 首次使用

1. 首次打开界面先创建管理员账号（所有部署形态都需要）；Docker / 反向代理等「服务模式」还需输入启动日志里的一次性初始化令牌，防止他人抢注。Windows / 通用 Linux 绑定回环，无需令牌；
2. 在「设置」中填写 dynv6 域名与 HTTP Token（DDNS 与证书签发共用同一个 Token），按需调整证书机构、密钥类型、输出路径与通知方式；
3. 保存后可手动执行一次「立即更新」与「立即签发」验证链路。

所有部署形态首次进入都需要创建管理员账号；飞牛网关注入的用户名只用于显示，权限以本地管理员会话为准。

## 安全说明

- 应用不申请 root，不修改系统定时任务，不改动飞牛系统证书目录。
- 服务监听 8092 时请置于网关 / HTTPS 反向代理之后，不要直接把端口暴露到公网；所有 API 都需要本地管理员会话，网关注入的身份头不作为凭据。
- dynv6 Update API 要求把 Token 放在 URL 查询参数中；HTTPS 下链路加密，但请勿使用不可信的 TLS 中间人代理，避免完整 URL 被记录。
- Token、邮箱、密码保存在权限 `0600` 的配置文件中，接口不回显，日志自动脱敏。
- 证书默认输出到应用私有数据目录（`${APPDATA}/certs`），不落在 SMB/WebDAV 共享目录；主输出的私钥（`.key`）与 PFX/P12 固定 `0600`，公钥证书使用主输出权限（默认 `0600`），分发到目标目录的文件为 `0644` 以便 Emby/Plex 读取。
- Windows / Linux 本地模式使用一次性令牌 + HttpOnly Cookie + Host/Origin/CSRF 校验。
- Docker 服务模式下除健康检查、登录与首次初始化外，所有 API 都要求管理员会话。
- 忘记密码：停止应用，删除数据目录下的 `admin.json`，重启后重新初始化。
- 如果 `admin.json` 损坏或不可读，应用会锁定初始化并提示人工处理，避免被他人重新接管。
- 下载后先校验哈希：`sha256sum -c SHA256SUMS.txt`。Release 同时提供 `SHA256SUMS.txt.sigstore.json`（cosign keyless 签名），可用 `cosign verify-blob --bundle SHA256SUMS.txt.sigstore.json --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp 'https://github.com/wabisabi926/dynv6/.*' SHA256SUMS.txt` 验证来源；Docker 镜像请固定版本标签，不要用 `latest`。

## 常见问题

### 提示端口被占用

应用升级或卸载时会自动清理旧实例。如果仍提示占用，请在飞牛 SSH 中确认占用者：

```bash
sudo ss -ltnp | grep 8092
sudo ps -eo pid,args | grep '/dynv6/bin/dynv6'
```

如果是旧版本残留进程，结束它后重启应用：

```bash
sudo pkill -f '/vol1/@appcenter/dynv6/bin/dynv6'
```

### 忘记管理员密码

停止应用，删除数据目录下的 `admin.json`，重启后重新初始化。

## 构建

需要 Go 1.21+ 与 Python 3.9+：

```bash
python scripts/build.py          # 编译并生成 fpk / Windows exe / Linux 二进制
python scripts/release.py --version 1.0.0 --tag v1.0.0
```

发布流程由 `.github/workflows/release.yml` 完成：推送 `v*` tag 后自动执行 `go vet`、`go test`，使用飞牛官方 fnpack 打包 fpk，构建 Windows / Linux 产物，生成 SHA256SUMS 并创建 GitHub Release，同时推送多架构 Docker 镜像。

发布前请在 `.changes/v<版本>.md` 写好中文更新日志。

## 目录结构

```
app/        飞牛应用资源（ui/config、图标）
cmd/        飞牛安装包生命周期脚本（start/stop/status 等）
config/     飞牛应用权限与资源声明
manifest    飞牛应用清单（service_port=8092）
wizard/     飞牛安装向导
src/        Go 源码与前端静态资源
scripts/    构建、图标、预览与发布脚本
```

## 第三方组件

- [lego](https://github.com/go-acme/lego)：MIT，纯 Go 的 ACME 客户端，用于证书签发。
- [go-pkcs12](https://github.com/SSLMate/go-pkcs12)：BSD-3-Clause，用于生成 PFX/P12。
- Let's Encrypt、Emby、Plex、dynv6 为各自所有者的商标或服务，本项目与其无隶属关系。

## 许可证

本项目源码采用 [MIT License](LICENSE)。
