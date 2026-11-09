# Dynv6 管家

dynv6 动态域名（DDNS）自动更新 + Let's Encrypt 证书自动签发、续期与分发的单二进制工具。

适配飞牛 fnOS（fpk）、Windows（免安装 exe）、通用 Linux 与 Docker，界面为内置的本地 Web UI，无需额外安装数据库或运行时。

## 功能

- **DDNS**：支持 IPv4 / IPv6，公网 IP 变化时自动调用 dynv6 API 更新记录，支持强制更新与手动触发。
- **证书**：基于 acme.sh + DNS-01（`dns_dynv6`）签发 Let's Encrypt 证书，自动续期；支持泛域名、EC/RSA 密钥长度切换。
- **分发**：证书可导出 PEM，并自动生成 Emby 使用的 PFX、Plex 使用的 P12，输出路径与文件名均可自定义。
- **通知**：支持 Telegram 等通知渠道，任务成功/失败均可推送。
- **调度**：内置定时任务，IP 探测、DDNS、证书检查按设定间隔运行；日志自动轮转。
- **鉴权**：飞牛由网关注入身份；Windows / Linux / Docker 使用本地管理员账号（PBKDF2-SHA256 加盐存储）。

## 端口

所有平台统一使用 **8092**：

| 平台 | 监听方式 | 访问方式 |
| --- | --- | --- |
| 飞牛 fnOS | 固定 8092，由飞牛网关反向代理 | 飞牛桌面打开应用，无需端口映射 |
| Windows | `127.0.0.1:8092` | 托盘图标打开，或访问 `http://127.0.0.1:8092/` |
| 通用 Linux | `127.0.0.1:8092` | 本机浏览器访问 `http://127.0.0.1:8092/` |
| Docker | `0.0.0.0:8092` | `http://宿主机IP:8092/` |

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

```bash
docker run -d --name dynv6 --restart unless-stopped \
  -p 8092:8092 \
  -v ./data:/data \
  ghcr.io/wabisabi926/dynv6:latest
```

或使用仓库内的 `docker-compose.yml`：

```bash
docker compose up -d
```

然后访问 `http://宿主机IP:8092/`，首次进入创建管理员账号。配置、状态、`admin.json` 与证书均在 `/data`，升级前请备份该目录；公网使用建议在容器前加 HTTPS 反向代理。

## 首次使用

1. 打开界面，在「设置」中填写 dynv6 域名与 HTTP Token（DDNS 与证书签发共用同一个 Token）；
2. 按需调整 IP 探测、证书机构、密钥类型、输出路径与通知方式；
3. 保存后可手动执行一次「立即更新」与「立即签发」验证链路。

Windows / Linux / Docker 首次进入需创建管理员账号；飞牛环境由网关注入身份，一般无需单独登录。

## 安全说明

- 应用不申请 root，不修改系统定时任务，不改动飞牛系统证书目录。
- Token、邮箱、密码保存在权限 `0600` 的配置文件中，接口不回显，日志自动脱敏。
- 私钥固定 `0600`，PEM 私钥 `0600`，PFX/P12 与证书 `0644`。
- Windows / Linux 本地模式使用一次性令牌 + HttpOnly Cookie + Host/Origin/CSRF 校验。
- Docker 服务模式下除健康检查、登录与首次初始化外，所有 API 都要求管理员会话。
- 忘记密码：停止应用，删除数据目录下的 `admin.json`，重启后重新初始化。
- 如果 `admin.json` 损坏或不可读，应用会锁定初始化并提示人工处理，避免被他人重新接管。

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
app/        飞牛应用资源（ui/config、图标、内置 acme.sh）
cmd/        飞牛安装包生命周期脚本（start/stop/status 等）
config/     飞牛应用权限与资源声明
manifest    飞牛应用清单（service_port=8092）
wizard/     飞牛安装向导
src/        Go 源码与前端静态资源
scripts/    构建、图标、预览与发布脚本
```

## 第三方组件

- [acme.sh](https://github.com/acmesh-official/acme.sh)：GPLv3，随安装包内置并在运行时调用，其许可证以项目上游为准。
- Let's Encrypt、Emby、Plex、dynv6 为各自所有者的商标或服务，本项目与其无隶属关系。

## 许可证

本项目源码采用 [MIT License](LICENSE)。内置的 acme.sh 等第三方组件遵循各自许可证。
