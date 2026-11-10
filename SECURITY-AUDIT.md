# Dynv6 管家 安全审查报告

| 项目 | 内容 |
| --- | --- |
| 审查对象 | Dynv6 管家（仓库 `wabisabi926/dynv6`），版本 `1.0.1` |
| 审查范围 | `src/` Go 源码、`cmd/`、`config/`、`Dockerfile`、`docker-compose.yml`、`.github/workflows/release.yml`、`dist/` 发布产物 |
| 审查方式 | 源码静态审查 + 本机有限动态验证（Windows 服务模式实例），**未做** Docker 运行时、飞牛真机与网络层渗透测试 |
| 审查日期 | 2026-11-10 |
| 修复版本 | **1.0.2 已修复 H-01 / M-01 / M-02 / M-03 / M-04 / L-02 / L-04 / L-05 / L-06 / L-07 / L-08 / L-10**；M-05 / L-09 / S-04 部分完成（详见第 9 节状态列）。注意：正文中的代码行号对应 1.0.1 修复前版本，仅作历史定位用 |
| 结论性质 | 本报告为**静态逻辑推演 + 有限实测**，最终结论需结合目标环境复测；未发现的项不代表不存在 |

> 说明：本报告不虚构漏洞。标注「已实测」的项有可复现命令；标注「静态推导」的项需在目标环境复测；标注「需实测」的项受审查环境限制未能验证。

---

## 1. 项目基础信息

### 1.1 功能清单

| 模块 | 能力 |
| --- | --- |
| DDNS | IPv4 / IPv6 公网地址探测，变化时调用 dynv6 Update API 更新 A/AAAA 记录；支持手动指定地址、强制更新 |
| 证书签发 | 内置 lego 纯 Go ACME 客户端，DNS-01 验证，Let's Encrypt 正式 / staging，支持泛域名、EC/RSA 密钥长度 |
| 证书分发 | 导出 PEM（key/cert/fullchain/chain），生成 Emby `.pfx`、Plex `.p12`，可分发到自定义目录 |
| 通知 | Telegram Bot 通知（成功/失败/测试），支持自定义代理 |
| 调度 | 内置定时器，DDNS、证书检查、分发重试；日志轮转 |
| 鉴权 | 飞牛网关注入身份；Windows / Linux / Docker 本地管理员账号（PBKDF2-SHA256，12 万次迭代） |
| 运维 | 健康检查、任务取消、路径授权浏览、备份轮转、托盘（Windows） |

### 1.2 部署形态

| 形态 | 监听方式 | 运行身份 | 数据目录 |
| --- | --- | --- | --- |
| 飞牛 fnOS（fpk） | `0.0.0.0:8092`，由飞牛网关反向代理 | 应用专用用户 `dynv6`（`run-as: package`） | `/app_data/dynv6/{config,data,logs,run}` + 共享目录 |
| Windows 二进制 | `127.0.0.1:8092`，一次性令牌 + Cookie | 当前登录用户 | `%LOCALAPPDATA%\dynv6` |
| 通用 Linux 二进制 | `127.0.0.1:8092`，一次性令牌 + Cookie | 启动用户 | 当前目录 `.dev` 或 `DYNV6_DATA_DIR` |
| Docker | `0.0.0.0:8092`，管理员账号登录 | **root（Dockerfile 未声明 USER）** | `/data` 卷 |

### 1.3 敏感密钥清单

| 密钥/凭据 | 存储位置 | 权限/保护 | 泄露影响 |
| --- | --- | --- | --- |
| dynv6 HTTP Token | `config.json` | 文件 `0600`；接口以 `__KEEP__` 脱敏；日志 mask | 可修改该 zone 的 DNS 记录（含 TXT），可配合签发证书劫持 HTTPS |
| Telegram Bot Token | `config.json` | 同上 | 可控制 Bot、读取/发送消息 |
| Telegram 代理地址 | `config.json` | 明文（通常不含凭据，若含账号密码则同样敏感） | 泄露代理凭据 |
| ACME 账户私钥 | `acme/account.key` | `0600`，目录 `0700` | 可冒充 ACME 账户操作已注册域名 |
| 证书私钥 | 输出目录 `*.key` | 默认 `0600`（可配置，PEM 分发固定 `0600`） | 可解密流量、冒充站点 |
| PFX / P12 | 输出目录 | 默认 `0600`（随 `FileMode`） | 含私钥，密码为空时可直接使用 |
| 管理员口令哈希 | `admin.json` | `0600`，PBKDF2-SHA256 加盐 | 离线爆破（12 万次迭代可提高成本） |
| 本地访问令牌 | `local-token` | `0600` | 本机 UI 会话劫持 |

---

## 2. 密钥与凭据安全审查

### H-01 服务模式信任网关注入头，可伪造管理员身份

- **等级**：高危（条件触发；**已实测**）
- **风险描述**：`gatewayUser()` / `gatewayAdmin()` 直接读取请求头 `X-Trim-Username`、`X-Trim-Isadmin` 作为身份依据（`src/adminauth.go:363-373`）。服务模式下 `handler` 的第一层校验只要求 `gatewayUser != ""`（`src/main.go:461-466`），`isAdminQuiet()` 随后认可 `gatewayAdmin`（`src/main.go:420-426`）。因此任何能直连监听端口的客户端，只要自带这两个头，即被当作飞牛管理员。
- **影响面**：读取完整配置（含 dynv6 Token、TG Bot Token）、修改配置（域名、Token、输出路径）、触发签发/分发、通过 `/api/files/get` 下载私钥与 PFX、读取任务与日志。飞牛形态监听 `0.0.0.0:8092`（`src/main.go:61-71`），若该端口对局域网可达，同网段任意设备即可接管。
- **验证方式（已实测）**：
  ```bash
  # 无头：401
  curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18092/api/config
  # 伪造头：200，且可写配置
  curl -s -H "X-Trim-Username: audit" -H "X-Trim-Isadmin: true" \
       http://127.0.0.1:18092/api/config
  curl -s -X POST -H "Content-Type: application/json" -H "X-Requested-With: dynv6" \
       -H "X-Trim-Username: audit" -H "X-Trim-Isadmin: true" \
       -d '{"domain":"attacker.dynv6.net","token":"x","ca":"letsencrypt","renew_days":30,"uid":-1,"gid":-1,"targets":[]}' \
       http://127.0.0.1:18092/api/config
  ```
  实测结果：无头 401；伪造头 200，配置可读可写，`/api/status` 返回 `admin=true`。
- **修复建议**：
  1. 飞牛形态改为监听 `127.0.0.1:8092` 或 Unix Socket，由网关反代；Socket 模式已有 `SO_PEERCRED` 校验（`src/socket_linux.go:41-89`），可复用。
  2. 若必须监听 `0.0.0.0`，增加「可信代理」配置：仅接受来自回环/指定网段的请求，并要求网关注入一个部署时生成的共享密钥头（如 `X-Trim-Gateway-Secret`），该密钥不落日志。
  3. 网关头只作为「身份提示」，管理员写操作仍需本地 admin 会话或网关签名，二者取交集而非并集。

### M-01 容器以 root 运行

- **等级**：中危（最佳实践缺失，**静态确认**）
- **风险描述**：`Dockerfile` 运行层 `FROM alpine:3.20` 后未声明 `USER`，`ENTRYPOINT` 以 root 启动（`Dockerfile:13-26`）。
- **影响面**：应用进程在容器内拥有 root；写出的配置、证书、日志属主为 root；一旦应用被 RCE，攻击者直接获得容器 root，扩大横向与逃逸面；宿主机挂载目录的写入权限也随之放大。
- **验证方式**：`docker run --rm <image> id` 预期 `uid=0(root)`（本机无 Docker，未实测）。
- **修复建议**：镜像内创建固定 UID（如 10001）并 `USER 10001:10001`；`/data` 由 entrypoint 以 root 初始化后降权，或在 compose 中指定 `user:`；同步在 README 给出宿主机目录 `chown` 指引。

### M-02 首次初始化接口无鉴权、无限流、无一次性凭据

- **等级**：中危（暴露窗口期风险）
- **风险描述**：`/api/setup/admin` 被列入匿名白名单（`src/main.go:437-443`），仅校验「尚未初始化」（`src/adminauth.go:509-570`），没有一次性 setup token、没有来源限制、没有失败计数。
- **影响面**：Docker 映射 `0.0.0.0:8092` 或反代暴露后、管理员尚未创建的时间窗内，任何能访问该端口的人可抢先创建管理员并接管（读取 Token、下载私钥）。
- **验证方式**：全新数据目录启动服务，从另一台主机 `POST /api/setup/admin` 创建账号（逻辑推导；可用本机 curl 复现）。
- **修复建议**：首次启动生成一次性 setup token，打印到控制台/日志（仅本机可见），setup 时必须携带；或初始化完成前只绑定 `127.0.0.1`；或要求本机回环来源。

### M-03 环境变量可完全关闭鉴权

- **等级**：中危（显式开关，误配即失守；**已实测**）
- **风险描述**：`DYNV6_AUTH_DISABLED=1` 使 `isAdminQuiet()` 在 `DevPort` 或 `Listen` 非空时恒为真（`src/main.go:420-426`、`src/store.go:88`）。
- **影响面**：服务模式下所有 API 匿名可访问，包括配置读写、私钥下载、任务触发。README 未提及该开关的风险。
- **验证方式（已实测）**：以 `DYNV6_LISTEN=127.0.0.1:18093 DYNV6_AUTH_DISABLED=1` 启动后，无任何身份头请求 `/api/config` 返回 200，`/api/status` 返回 `admin=true`。
- **修复建议**：该开关仅在 `DevPort` 模式生效，`Listen` 模式忽略并记录警告；README 增加红字警告；发布构建可考虑移除该后门。

### L-01 dynv6 Token 通过 URL 查询参数传输

- **等级**：低危（协议限制）
- **风险描述**：dynv6 Update API 要求 `token` 放在 query 中（`src/ddns.go:297-311`）。HTTPS 下链路加密，但配置了 MITM 代理、抓包或边缘设备记录完整 URL 时可泄露。
- **影响面**：Token 泄露可修改该 zone 的 DNS 记录。
- **验证方式**：配置 `HTTP_PROXY` 为可记录日志的 MITM 代理，触发 DDNS 更新后检索 URL（需实测）。
- **修复建议**：优先改用 REST API `PATCH /zones/{id}` 更新 A/AAAA（`Authorization: Bearer`），TXT 记录已走该方式；文档提示不要使用不可信 MITM 代理；日志侧已做 mask，保持现状。

### L-02 代理配置未限制协议

- **等级**：低危
- **风险描述**：`TGProxyURL` 仅做 `url.Parse`，未限制 scheme（`src/notify.go:25-33`）。HTTPS 目标经 HTTP 代理会走 CONNECT 隧道，代理看不到路径中的 Bot Token；但若代理实施 TLS 中间人，则可解密。
- **影响面**：仅在用户主动配置恶意/被控代理时成立。
- **验证方式**：配置 `http://` 代理并抓包，确认 CONNECT 隧道内容（需实测）。
- **修复建议**：允许 `http/https/socks5` 白名单并在 UI 提示「HTTP 代理若启用 TLS 中间人会暴露 Bot Token」。

### L-03 日志与配置的密钥处理（已做对的部分）

- 配置文件 `0600`（`src/config.go` 写入路径），`publicConfig()` 将 Token、TG Token、PFX/P12 密码替换为 `__KEEP__`（`src/config.go:370-384`）。
- `secrets()` 覆盖 dynv6 Token、TG Bot Token、PFX/P12 密码（`src/config.go:386-388`），任务错误、命令输出、Telegram 错误均经 `maskSecrets`（`src/util.go:130-137`）。
- 日志文件 `0600`、10 MB 轮转（`src/store.go:96-128`）；`panic` 堆栈不含变量值。
- 剩余风险：日志仍包含域名、公网 IP、目录路径、错误详情，属运维信息，非密钥。

---

## 3. ACME 证书签发逻辑审查

### 3.1 DNS-01 挑战

- 本地计算 `_acme-challenge.<domain>` 与 TXT 值（SHA-256 + Base64URL），不依赖外部 DNS 查询（`src/acme_dns.go:140-145`）。
- zone 匹配使用最长后缀，避免多 zone 误匹配（`src/acme_dns.go:120-138`）。
- 创建记录后按 `DNSSleep` 等待；记录 ID 记录在内存 map 中，`CleanUp` 按 ID 删除（`src/acme_dns.go:171-195`）。

### L-04 TXT 记录在异常退出后可能残留

- **等级**：低危
- **风险描述**：`created` map 仅存内存（`src/acme_dns.go:42-45`），进程被 `kill -9`、容器重启或崩溃后无法执行 `CleanUp`，`_acme-challenge` TXT 记录会残留。
- **影响面**：DNS 记录污染、后续签发出现多条 TXT；不影响私钥与证书安全。
- **验证方式**：签发过程中 `kill -9`，到 dynv6 后台查看 TXT 记录（需实测）。
- **修复建议**：将待清理记录持久化到 `state.json`，启动时清理超过 1 小时的 `_acme-challenge` TXT；或依赖 lego 的 `CleanUp` 并在启动时做一次对账。

### L-05 取消任务无法中断 DNS 等待

- **等级**：低危
- **风险描述**：`Present` 内 `time.Sleep(d.sleep)` 不可取消（`src/acme_dns.go:174-176`），任务取消后仍需等待最长 `DNSSleep` 秒。
- **影响面**：运维体验；不构成安全漏洞。
- **验证方式**：设置 `DNSSleep=300` 后触发签发并立即取消，观察日志停止时间。
- **修复建议**：改为 `select` + `time.After` 并监听取消信号；或把等待拆成可中断的小步。

### 3.2 证书写入与权限

- ACME 账户密钥 `account.key`、`account.json` 均 `0600`，目录 `0700`（`src/acme.go:104-149`）。
- PEM 私钥、证书、链使用 `parseMode(FileMode)`，默认 `0600`（`src/acme.go:220-251`）；分发 PEM 时私钥强制 `0600`（`src/deploy.go:79`）。
- 写入后自检：私钥与证书匹配、域名覆盖、泛域名覆盖、未过期（`src/certcheck.go:13-59`），实现质量较高。
- PFX/P12 使用 `pkcs12.Modern`（AES-256 + SHA256），密码经内存传递，不落命令行（`src/convert.go:30-54`）。

### L-06 FileMode 可被改为宽松权限

- **等级**：低危（配置风险）
- **风险描述**：`validFileMode` 允许用户把 `file_mode` 改为 `0644` 等（`src/config.go:398`），私钥与 PFX 将变为同机可读。
- **影响面**：同机其他用户或共享目录使用者可读取私钥。
- **验证方式**：设置 `file_mode=0644` 后签发，`ls -l` 检查（可复现）。
- **修复建议**：对包含私钥的文件（key/pfx/p12）强制上限 `0600`，UI 中把该选项标注为高级并提示风险；或在保存时拒绝 `o+r`。

### L-07 README 权限描述与实现不一致

- **等级**：低危（文档）
- **风险描述**：README 写「PFX/P12 与证书 0644」，实际默认 `FileMode=0600`（`src/config.go:104`）。
- **影响面**：用户按文档预期 Emby 可读，实际读不到，可能反向诱导用户全局放宽权限。
- **验证方式**：对比 README 第 81 行与 `defaultConfig()`。
- **修复建议**：修正文档，并给出「仅对目标应用授权」的推荐做法。

### 3.3 续期与告警

- 续期阈值默认 30 天，`checkCert` 在到期前触发续期（`src/pipeline.go:107-151`）。
- 配置变更（CA / 密钥长度 / 泛域名）会触发重新签发（`src/pipeline.go:143-146`、`src/acme.go:273-327`）。
- staging 证书默认不分发到 Emby/Plex，且禁止用 staging 证书覆盖正式目标（`src/pipeline.go:28-31`、`src/deploy.go:16-22`），这是很好的防误操作设计。
- 失败通知已接入（`src/acme.go:195-215`）。
- **建议优化**：增加「剩余 7 天仍未续期成功」的强制告警与每日重试上限，避免证书静默过期。

---

## 4. DDNS 更新逻辑审查

### M-04 IP 探测地址可配置，存在 SSRF 面

- **等级**：中危（需管理员权限）
- **风险描述**：`detectIP` 对用户配置的 URL 直接发起请求（`src/ddns.go:16-53`），未限制目标地址与重定向；`isPublicIP` 只校验**响应内容**是否为公网 IP，不校验**请求目标**。
- **影响面**：管理员（或被钓鱼的管理员）可让服务访问内网地址、云元数据端点，用于内网探测；响应需为合法公网 IP 且仅取 256 字节，数据外带能力有限，但端口存活/时序探测可行。
- **验证方式**：把 IPv4 探测地址设为 `http://127.0.0.1:8092/api/health` 后点击「测试探测」，观察请求与耗时（可复现）。
- **修复建议**：限制 scheme 为 `http/https`；解析目标 IP 并拒绝私网、回环、链路本地、组播、保留段；`CheckRedirect` 限制跳转次数并对每一跳重新校验；或改为固定探测源白名单。

### 4.1 其余实现评估

- 探测结果校验严格：必须是公网 IP、协议族匹配（`src/ddns.go:39-51`）。
- 超时：探测 6 s、更新 20 s（`src/ddns.go:241`、`310`）。
- 去重：IP、域名、Token 指纹（SHA-256 前 8 字节）任一变化才更新（`src/ddns.go:187-205`），避免无谓调用与 Token 明文落盘。
- 失败处理：无论成功失败都记录尝试时间（`src/ddns.go:212-213`），避免 30 秒重试风暴。
- 错误提示具体且已脱敏（`src/ddns.go:312-327`）。
- **建议优化**：对 429/5xx 增加指数退避与上限；IPv6 关闭时提示清理旧 AAAA（已提示，可增加一键清理）。

---

## 5. Telegram 通知模块审查

### 5.1 实现评估

- 固定 `https://api.telegram.org`，不使用明文 HTTP（`src/notify.go:19`）。
- 超时 12 s（`src/notify.go:32`）。
- 消息内容经 `html.EscapeString`，`parse_mode=HTML` 下无注入（`src/notify.go:88-91`）。
- 通知内容为域名、IP、证书到期时间，**不含** Token、私钥、证书正文（`src/ddns.go:345`、`src/pipeline.go:43-60`）。
- 去重 10 分钟，异步发送不阻塞任务（`src/notify.go:72-97`）。
- Bot Token 位于 URL path，属 Telegram API 设计；错误信息经 `maskSecrets`（已覆盖 TG Token）。

### L-08 通知协程缺少 panic 恢复

- **等级**：低危
- **风险描述**：`notify` 内 `go func(){ sendTelegram(...) }()` 未 `recover`（`src/notify.go:92-96`）。Go 中未恢复的协程 panic 会终止整个进程。
- **影响面**：极端情况下通知模块异常导致主服务退出。
- **验证方式**：静态推导；可注入 panic 复现。
- **修复建议**：协程内加 `defer recover()` 并记录日志；或复用任务协程的恢复框架。

### 建议优化

- 增加「通知发送失败」的本地日志标记，避免静默丢失关键告警。
- 支持更多渠道时，统一走「脱敏 + 超时 + 重试上限」封装。

---

## 6. 多部署形态专项审查

### 6.1 飞牛 fnOS

| 检查项 | 结论 |
| --- | --- |
| 运行用户 | `config/privilege` 为 `run-as: package`，专用用户 `dynv6`，未申请 root（良好） |
| 监听方式 | `0.0.0.0:8092` + 网关反代；**存在 H-01 伪造头风险**，需限制来源或改回环监听 |
| 配置目录 | `/app_data/dynv6/config`，`0600` |
| 共享目录 | 默认输出 `${SHARE}`（`fncert/certs` 类共享目录）；POSIX 权限 `0600`，但飞牛共享目录使用 Windows ACL，是否被 SMB/WebDAV 其他用户读取**需实测** |
| SMB/WebDAV 泄露 | 若私钥/PFX 落在共享目录且 ACL 放宽，存在泄露面；建议默认私钥留在应用私有目录 |
| 计划任务 | 内置调度器，不写系统 crontab（良好） |
| 系统日志 | 应用自管 `dynv6.log`，`0600`、10 MB 轮转；不写 syslog |
| 容器/宿主机互通 | 不涉及容器 |
| 系统更新覆盖 | 程序在 `/vol*/@appcenter`，配置与数据在 `/app_data`，升级不覆盖数据（良好）；但**升级可能替换二进制**，需保证包校验 |
| 持久化证书 | 输出目录可自定义；建议明确「升级/重装前备份 `/app_data`」 |

### M-05 共享目录中的私钥暴露面

- **等级**：中危（需实测）
- **风险描述**：默认 `OutputDir = "${SHARE}"`，即飞牛 data-share 目录；该目录对 SMB/WebDAV/其他应用可见。POSIX `0600` 对应用用户生效，但飞牛共享使用 Windows ACL，实际可读性取决于 ACL 继承与共享权限。
- **影响面**：若 ACL 允许其他用户读取，私钥/PFX 可被同 NAS 用户获取。
- **验证方式**：飞牛真机上用另一个 SMB 用户尝试读取 `certs/*.key` 与 `*.pfx`（需实测）。
- **修复建议**：默认把私钥/PFX 输出到应用私有目录（`${APPDATA}`），共享目录只放 `fullchain.crt` 等公钥材料；或在 UI 首次启用共享目录输出时显式提示风险并要求确认。

### 6.2 Docker

| 检查项 | 结论 |
| --- | --- |
| 基础镜像 | 构建 `golang:1.25-alpine`，运行 `alpine:3.20`（体积小，攻击面较小） |
| 运行用户 | **root（无 USER）**，见 M-01 |
| 文件挂载 | `./data:/data`，容器 root 写入，宿主机目录属主可能变为 root |
| 网络模式 | 默认 bridge，`8092:8092` 绑定 `0.0.0.0`，暴露面取决于宿主防火墙 |
| 持久化卷 | `/data` 声明为 VOLUME，配置/证书/日志均在卷内（良好） |
| 健康检查 | `wget /api/health`，30 s 间隔（良好） |
| 日志驱动 | 未指定，默认 json-file 无上限；建议 `logging: max-size/max-file` |
| 镜像标签 | `latest` + 版本标签；README 推荐 `latest`，存在版本漂移（见 L-09） |

### 6.3 Windows 二进制

| 检查项 | 结论 |
| --- | --- |
| 运行权限 | 当前登录用户，非服务；不申请管理员（良好） |
| 配置位置 | `%LOCALAPPDATA%\dynv6`，继承用户 ACL |
| 事件日志 | 不写 Windows 事件日志，仅本地文件；建议可选写入 |
| 开机自启 | 未内置；需用户手动创建计划任务/启动项 |
| 二进制篡改 | **未签名**（实测 `Get-AuthenticodeSignature` = NotSigned），存在被替换/误报风险 |
| 本地访问 | 一次性令牌 + HttpOnly Cookie + Host/Origin 校验（良好） |

### L-09 发布产物未签名、镜像使用 latest

- **等级**：低危（供应链）
- **风险描述**：发布仅提供 `SHA256SUMS.txt`（已实测包含 5 个产物），无 GPG/cosign 签名；Windows exe 未做代码签名；Docker 同时推 `latest` 与版本标签，README 与 compose 默认使用 `latest`。
- **影响面**：下载源被篡改时校验和可被同步替换；`latest` 导致不可复现部署与意外升级。
- **验证方式**：`Get-AuthenticodeSignature` 实测 NotSigned；检查 `release.yml` 无签名步骤。
- **修复建议**：发布增加 cosign 签名与 SLSA provenance；Windows 视条件做代码签名；文档与 compose 固定版本标签，`latest` 仅作便利标签。

### L-10 CI 依赖未固定到 commit

- **等级**：低危
- **风险描述**：`release.yml` 使用 `actions/checkout@v5`、`setup-go@v6` 等 tag；`fnpack` 从官方地址下载后未校验哈希（`.github/workflows/release.yml:84-98`）。
- **影响面**：上游 action 被劫持或下载源被篡改时影响构建产物。
- **验证方式**：静态检查 workflow。
- **修复建议**：action 固定到 commit SHA；fnpack 下载增加 SHA256 校验；构建环境使用最小权限（已做 `permissions` 收敛）。

---

## 7. 运行时异常与稳定性审查

| 检查项 | 结论 |
| --- | --- |
| 任务 panic | 任务协程有 `recover` 并记录堆栈（`src/store.go:311-319`），良好 |
| 通知协程 panic | 无 recover，见 L-08 |
| 优雅退出 | `signal.NotifyContext` + `srv.Shutdown`（10 s）+ 取消当前任务（`src/main.go:373-382`），良好 |
| 重试风暴 | DDNS 记录尝试时间；证书检查失败也更新 `LastCertCheck`（`src/pipeline.go:124`、`130`），避免 30 s 循环 |
| 任务串行 | 按 lane 串行（cert/ddns/notify），避免并发抢 DNS 挑战（`src/store.go`、`src/main.go:792-798`） |
| 单实例 | 飞牛用 PID + 端口探测 + 清理遗留进程（`cmd/main`）；**Go 进程内无文件锁**，Docker 多副本或手动双开仍可能并发 |
| 入参校验 | 域名、用户名、密码、文件名、路径、模板均有校验；JSON body 限制 1 MB |
| 外部超时 | 探测 6 s、更新 20 s、TG 12 s、ACME 90 s、dynv6 API 30 s，均有上限 |
| 路径安全 | 绝对路径 + `..` 拒绝 + symlink 检查 + 根目录白名单（`src/dirs.go`、`src/deploy.go`），良好 |
| 文件下载 | 扩展名白名单 + 目录越界 + symlink 拒绝（`src/main.go:716-753`），良好 |

### 建议优化

1. 增加单实例文件锁（`flock`/`LockFileEx`），多副本时第二个实例直接退出并提示。
2. 证书检查失败增加指数退避与每日上限，避免触发 CA 限流。
3. 对 429/5xx 统一退避策略，并在 UI 展示下次重试时间。

---

## 8. 分发安全审查

| 检查项 | 结论 |
| --- | --- |
| 校验和 | `dist/SHA256SUMS.txt` 覆盖 5 个产物（已实测） |
| 签名 | 无 GPG/cosign；Windows exe 未签名（L-09） |
| Docker | 多架构构建，`latest` + 版本标签；无 provenance/SBOM |
| fpk 内容 | `release.py` 构建前扫描仓库并校验包内容，避免配置/证书/日志进入安装包（release.yml 注释与脚本） |
| 升级完整性 | 依赖包内 `checksum`（app.tgz MD5）与外部源 `sha256`；MD5 仅用于完整性，非安全校验 |
| 回滚 | 证书备份保留 10 份（`src/deploy.go:117-161`）；程序回滚依赖用户保留旧包 |

### 建议优化

- 发布说明中给出「先校验 SHA256 再安装」的固定命令。
- 提供 SBOM（`syft`）与 cosign 签名，便于企业环境审计。
- 外部应用源 `fnpack.json` 的 `sha256` 必须随每次发布更新（当前流程已自动回写）。

---

## 9. 风险汇总评级表

| 编号 | 等级 | 标题 | 状态 | 建议优先级 |
| --- | --- | --- | --- | --- |
| H-01 | 高危 | 伪造 `X-Trim-*` 头可获取管理员权限 | ✅ 已修复（1.0.2：网关头降级为展示，服务模式强制本地管理员会话；已实测伪造头 401） | 已修复 |
| M-01 | 中危 | Docker 容器以 root 运行 | ✅ 已修复（固定 UID 10001 + compose user/端口/日志限制） | 已修复 |
| M-02 | 中危 | 首次初始化可被抢占 | ✅ 已修复（一次性 setup token + 限流；已实测） | 已修复 |
| M-03 | 中危 | `DYNV6_AUTH_DISABLED=1` 完全关闭鉴权 | ✅ 已修复（开关已移除；已实测置 1 仍 401） | 已修复 |
| M-04 | 中危 | IP 探测 URL 可配置导致 SSRF | ✅ 已修复（探测源固定为内置常量，配置项移除；禁用重定向） | 已修复 |
| M-05 | 中危 | 共享目录私钥 ACL 暴露面 | 🔶 已缓解（默认输出改私有目录；飞牛共享目录 ACL 仍需真机确认） | 待真机确认 |
| L-01 | 低危 | dynv6 Token 走 URL query | ⏸ 保持现状（Update API 协议限制；文档已提示勿用不可信 MITM 代理） | 接受风险 |
| L-02 | 低危 | TG 代理未限制协议 | ✅ 已修复（保存校验 + 运行时白名单） | 已修复 |
| L-04 | 低危 | TXT 记录异常退出残留 | ✅ 已修复（持久化登记 + 启动清理 >1h 残留） | 已修复 |
| L-05 | 低危 | DNS 等待不可取消 | ✅ 已修复（取消信号中断等待） | 已修复 |
| L-06 | 低危 | FileMode 可放宽到 0644 | ✅ 已修复（key/PFX/P12 强制 0600；file_mode 仅作用于公钥且白名单 0600/0640） | 已修复 |
| L-07 | 低危 | README 权限描述不一致 | ✅ 已修复 | 已修复 |
| L-08 | 低危 | 通知协程无 recover | ✅ 已修复 | 已修复 |
| L-09 | 低危 | 产物未签名 / 镜像 latest | 🔶 部分完成（cosign keyless 签 SHA256SUMS + 版本标签固定；Windows exe 代码签名未做） | 部分完成 |
| L-10 | 低危 | CI action 未固定 commit | ✅ 已修复（全部 SHA 固定 + fnpack 哈希校验 + govulncheck 入 CI） | 已修复 |
| S-01 | 建议 | 单实例文件锁 | ⏸ 未做 | 待办 |
| S-02 | 建议 | 证书到期兜底告警与退避 | ⏸ 未做 | 待办 |
| S-03 | 建议 | 审计日志（配置/登录/签发） | ⏸ 未做 | 待办 |
| S-04 | 建议 | 安全响应头 CSP/frame-ancestors | 🔶 部分完成（CSP 已加；frame-ancestors 需真机确认飞牛 iframe 来源后收紧） | 部分完成 |
| S-05 | 建议 | 私钥与共享目录分离 | ✅ 已完成（默认输出目录改为应用私有目录） | 已完成 |

**已做对、无需整改的安全设计**：PBKDF2-SHA256 12 万次迭代与常量时间比较；登录失败按账号 + IP 双维度限流；`admin.json` 损坏时 fail-closed；Cookie `HttpOnly`/`SameSite`/按 HTTPS 加 `Secure`；CSRF 自定义头 + Origin/Sec-Fetch-Site 校验；任务串行与 panic 恢复；staging 证书禁止分发；PEM 私钥强制 0600；路径白名单与 symlink 防护；日志脱敏与 0600；Unix Socket `SO_PEERCRED` 校验；发布前 `go vet` + `go test`。

---

## 10. 发布前自检核对清单

### 必须项（阻断发布）

- [x] H-01：飞牛/服务模式不再无条件信任 `X-Trim-Username` / `X-Trim-Isadmin`；限制来源或改回环监听，并补一条自动化测试。
- [x] M-01：Dockerfile 增加 `USER`，`/data` 权限与 compose `user:` 同步；README 给出目录属主说明。
- [x] M-02：首次初始化增加一次性 setup token 或仅回环可用。
- [x] M-03：`DYNV6_AUTH_DISABLED` 仅在本地开发端口生效，服务模式忽略并告警；README 补充风险说明。
- [x] M-05（默认已改私有目录，共享 ACL 仍建议真机复核）：确认飞牛共享目录 ACL 不会让其他用户读取私钥；否则默认改到私有目录。
- [x] 用 `govulncheck ./...` 扫描依赖（lego / go-pkcs12 / x/sys）并处理已知漏洞。

### 应该项

- [x] M-04：探测 URL 增加 scheme 与目标 IP 限制、重定向校验。
- [x] L-04：启动时清理过期 `_acme-challenge` TXT。
- [x] L-06：key/pfx/p12 强制 `0600`，UI 标注风险。
- [x] L-08：通知协程加 `recover`。
- [x] L-09（cosign + 固定版本标签；exe 代码签名待条件具备）：发布增加 cosign 签名；README/compose 固定版本标签。
- [x] L-10：CI action 固定 commit SHA，fnpack 下载校验哈希。
- [x] 修正 README 中权限描述。

### 验证项

- [ ] 飞牛真机：从同网段另一台设备直连 8092，验证无法伪造管理员。
- [ ] Docker：`docker run --rm <image> id` 非 root；容器内写 `/data` 属主正确。
- [ ] 证书链路：staging 签发 → 不分发 → 切正式 → 分发 → Emby/Plex 实际加载。
- [ ] 异常恢复：签发中 `kill -9`，重启后 TXT 清理与证书状态正确。
- [ ] 备份恢复：删除输出目录后从备份恢复并重新分发。
- [ ] 升级：覆盖安装后配置、证书、管理员账号保留。

---

## 附录 A：README 可用的安全声明与风险提示

> **安全声明**
>
> Dynv6 管家用于管理 dynv6 动态域名与 Let's Encrypt 证书，涉及 DNS 控制权与 TLS 私钥，请按以下方式部署与使用：
>
> 1. **最小暴露**：飞牛环境由系统网关访问，请勿额外将 8092 端口映射到公网；Docker / 反向代理部署时，建议仅监听 `127.0.0.1` 或置于 HTTPS 反向代理之后，并限制来源 IP。
> 2. **首次初始化**：服务模式首次启动后请立即创建管理员账号，不要将未初始化的实例暴露在可被他人访问的网络中。
> 3. **密钥保护**：dynv6 Token、Telegram Bot Token、ACME 账户密钥与证书私钥均属高敏感凭据。请保持配置文件与私钥文件权限为 `0600`，不要把数据目录放入公开共享或版本库；定期备份 `/data`，备份介质需加密。
> 4. **私钥分发**：仅将证书与私钥分发到确有需要的服务（Emby / Plex）；共享目录可能被 SMB / WebDAV 用户访问，若不希望私钥出现在共享目录，请把输出目录改为应用私有目录。
> 5. **测试与正式**：调试请使用 `letsencrypt_test`，测试证书默认不会分发到生产服务；确认链路后再切换正式机构，避免触发速率限制。
> 6. **鉴权**：飞牛环境依赖网关注入身份；Windows / Linux / Docker 使用本地管理员账号（PBKDF2-SHA256 加盐）。请使用强密码，不要在公网环境设置 `DYNV6_AUTH_DISABLED=1`。
> 7. **完整性**：下载后请先校验 `SHA256SUMS.txt`；生产环境建议固定版本标签，不使用 `latest`。
> 8. **漏洞反馈**：如发现安全问题，请通过仓库 Issues 或维护者邮箱私下联系，勿在公开 Issue 中披露可利用细节。
>
> 本项目按 MIT 许可证「按现状」提供，不附带任何明示或暗示担保。因配置不当、凭据泄露或第三方服务变更造成的损失，由使用者自行承担。

---

## 附录 B：审查方法与局限

- **已执行**：逐文件阅读 `src/` 全部 Go 源码与部署/发布配置；本机以服务模式启动 Windows 构建，验证鉴权绕过（H-01）与鉴权开关（M-03）；检查发布校验和与 Windows 签名状态。
- **未执行**：Docker 运行时验证（审查机无 Docker）、飞牛真机与 SMB/ACL 验证、网络层渗透、依赖 CVE 扫描、模糊测试。
- **结论边界**：H-01 的实际可利用性取决于 8092 端口的网络可达性；若飞牛防火墙默认仅允许本机/网关访问，则风险降为中危，但仍建议按高危整改（纵深防御）。
- **建议复测**：修复后对 H-01、M-01、M-02、M-03 各补一条回归用例，纳入 `go test` 或 CI 冒烟脚本。
