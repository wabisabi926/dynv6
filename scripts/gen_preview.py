#!/usr/bin/env python3
"""把真实 UI 页面 + 演示数据打包成单文件离线效果图 build/ui-preview.html。

浏览器直接打开即可点击所有页签查看界面，无需飞牛、无需后端。
"""
import base64
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "src", "web")
OUT = os.path.join(ROOT, "build", "ui-preview.html")

DEMO = r"""
<script>
const DEMO_STATUS = {
  ok: true, version: '1.0.0', demo: true, configured: true, env: 'fnOS', domain: 'example.dynv6.net',
  paths_check: {output: true, backup: true, acme_home: true},
  authorized_paths: ['/vol1/1000/media'],
  state: {
    last_ipv4: '203.0.113.10', last_ipv6: '', last_ddns_at: '2026-11-09 11:25:03',
    last_ddns_attempt: '2026-11-09 11:25:03',
    last_ddns_result: '更新成功', last_cert_check: '2026-11-09 09:00:12',
    last_issue_at: '2026-10-12 03:12:44', last_renew_at: '',
    last_deploy_at: '2026-10-12 03:14:02', cert_not_after: '2027-01-10 03:12:44',
    cert_days_left: 62, last_error: ''
  },
  tasks: [
    {started_at:'2026-11-09 11:25:03', name:'ddns', status:'ok', message:'完成'},
    {started_at:'2026-11-09 09:00:12', name:'cert-check', status:'ok', message:'完成'},
    {started_at:'2026-10-12 03:14:02', name:'deploy', status:'ok', message:'完成'},
    {started_at:'2026-10-12 03:12:44', name:'issue', status:'ok', message:'完成'}
  ],
  busy: false, current: '',
  paths: {
    output: '/vol1/1000/dynv6/certs', backup: '/vol1/1000/dynv6/backup',
    acme_home: '/vol1/@appdata/dynv6/acme', config: '/vol1/@appconf/dynv6/config.json'
  },
  options: {auto_ddns:true, auto_renew:true, auto_issue:false, renew_days:30, ca:'letsencrypt', allow_test_deploy:false}
};
const DEMO_CONFIG = {
  ok: true, config: {
    domain:'example.dynv6.net', token:'__KEEP__',
    email:'me@example.com', wildcard:true, ca:'letsencrypt', key_length:'ec-256',
    dns_sleep:120, renew_days:30, ddns_interval_min:5, cert_check_hours:12,
    enable_ipv4:true, enable_ipv6:false, ipv4_probe_url:'https://api.ipify.org',
    ipv6_probe_url:'https://api6.ipify.org', ipv6_prefix:false,
    acme_home:'${APPDATA}/acme', output_dir:'/vol1/1000/dynv6/certs',
    backup_dir:'/vol1/1000/dynv6/backup', file_prefix:'${DOMAIN}',
    pfx_password:'', p12_password:'', file_mode:'0600',
    auto_ddns:true, auto_renew:true, auto_issue:false, allow_test_deploy:false,
    tg_enabled:false, tg_bot_token:'', tg_chat_id:'', tg_proxy_url:'',
    targets:[
      {id:'emby', name:'Emby（.pfx）', kind:'emby', enabled:true, dir:'${OUTPUT}', filename:'${DOMAIN}.pfx', mode:'0644'},
      {id:'plex', name:'Plex（.p12）', kind:'plex', enabled:true, dir:'${OUTPUT}', filename:'${DOMAIN}.p12', mode:'0644'},
      {id:'pem', name:'自定义目录（PEM 全套）', kind:'pem', enabled:false, dir:'', filename:'${DOMAIN}', mode:'0644'}
    ]
  }
};
const DEMO_DIRS = {ok:true, path:'/vol1/1000/media', parent:'/vol1/1000',
  roots:[{name:'证书共享目录', path:'/vol1/1000/dynv6/certs'}, {name:'已授权路径', path:'/vol1/1000/media'}],
  dirs:[{name:'certs', path:'/vol1/1000/media/certs'}, {name:'photos', path:'/vol1/1000/media/photos'}]};
const DEMO_FILES = {ok:true, dir:'/vol1/1000/dynv6/certs', files:[
  {name:'example.dynv6.net.key', size:241, mod_time:'2026-10-12 03:12:44'},
  {name:'example.dynv6.net.crt', size:1834, mod_time:'2026-10-12 03:12:44'},
  {name:'example.dynv6.net.chain.crt', size:1286, mod_time:'2026-10-12 03:12:44'},
  {name:'example.dynv6.net.fullchain.crt', size:3120, mod_time:'2026-10-12 03:12:44'},
  {name:'example.dynv6.net.p12', size:4210, mod_time:'2026-10-12 03:14:02'},
  {name:'example.dynv6.net.pfx', size:4210, mod_time:'2026-10-12 03:14:02'}
]};
const DEMO_LOGS = {ok:true, lines:[
  '[2026-11-09 11:20:01] dynv6 1.0.0 启动，配置=/vol1/@appconf/dynv6/config.json 数据=/vol1/@appdata/dynv6',
  '[2026-11-09 11:20:02] 服务已就绪（/var/apps/dynv6/target/dynv6.sock）',
  '[2026-11-09 11:25:03] DDNS 更新成功 zone=example.dynv6.net ipv4=203.0.113.10 ipv6= 响应=updated',
  '[2026-11-09 09:00:12] 证书检查：剩余 62 天（阈值 30 天）',
  '[2026-10-12 03:14:02] 分发完成，共 2 个文件',
  '[2026-10-12 03:14:02] 任务 issue 完成'
]};
window.fetch = async function (url, opts) {
  const u = String(url);
  let data = {ok:true};
  if (u.indexOf('api/auth/status') >= 0) data = {ok:true, authenticated:true, setupRequired:false, gateway:false, admin:true, username:'admin', authDisabled:false};
  else if (u.indexOf('api/status') >= 0) data = DEMO_STATUS;
  else if (u.indexOf('api/config') >= 0) data = (opts && opts.method === 'POST') ? {ok:true} : DEMO_CONFIG;
  else if (u.indexOf('api/files/get') >= 0) data = {ok:true};
  else if (u.indexOf('api/files') >= 0) data = DEMO_FILES;
  else if (u.indexOf('api/dirs') >= 0) data = DEMO_DIRS;
  else if (u.indexOf('api/logs') >= 0) data = DEMO_LOGS;
  else if (u.indexOf('api/tasks') >= 0) data = {ok:true, tasks:DEMO_STATUS.tasks};
  else if (u.indexOf('api/health') >= 0) data = {ok:true, version:'1.0.0'};
  return {ok:true, status:200, json: async () => data};
};
</script>
"""

BANNER = ('<div style="background:#fff5e0;color:#a16207;text-align:center;'
          'padding:8px 12px;font-size:12px;border-bottom:1px solid #f2e2bb">'
          '界面效果图 · 以下为演示数据，可点击页签查看各页面；实际数据需安装到飞牛后由应用提供</div>')


def main():
    html = open(os.path.join(WEB, "index.html"), encoding="utf-8").read()
    css = open(os.path.join(WEB, "style.css"), encoding="utf-8").read()
    js = open(os.path.join(WEB, "app.js"), encoding="utf-8").read()
    html = html.replace('<link rel="stylesheet" href="static/style.css">', '<style>\n' + css + '\n</style>')
    html = html.replace('<script src="static/app.js"></script>', DEMO + '\n<script>\n' + js + '\n</script>')
    html = html.replace('<div class="wrap">', BANNER + '\n<div class="wrap">', 1)
    icon = os.path.join(ROOT, "app", "ui", "images", "ICON_64.PNG")
    b64 = base64.b64encode(open(icon, "rb").read()).decode()
    html = html.replace('src="static/images/ICON_64.PNG"', 'src="data:image/png;base64,' + b64 + '"')
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(html)
    print("界面效果图已生成:", OUT, len(html), "字节")


if __name__ == "__main__":
    main()
