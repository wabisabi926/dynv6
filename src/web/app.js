const BASE = (() => { const b = document.baseURI; return b.endsWith('/') ? b : b + '/'; })();
const NUM = new Set(['dns_sleep', 'renew_days', 'cert_check_hours', 'ddns_interval_min']);
const BOOL = new Set(['wildcard', 'auto_renew', 'auto_issue', 'auto_ddns', 'enable_ipv4', 'enable_ipv6', 'ipv6_prefix', 'tg_enabled', 'allow_test_deploy']);
const PASS = new Set(['token', 'pfx_password', 'p12_password', 'tg_bot_token']);
const MASK = '**************';
let cfg = null;
let envName = '';
let isAdmin = true;
let authInfo = null;
let appStarted = false;
let refreshTimer = null;

async function api(path, opts) {
  const options = Object.assign({}, opts || {});
  options.headers = Object.assign({ 'X-Requested-With': 'dynv6' }, options.headers || {});
  const r = await fetch(BASE + path, options);
  let j = {};
  try { j = await r.json(); } catch (e) { j = { ok: false, error: 'HTTP ' + r.status }; }
  j.status = r.status;
  if (!r.ok && !j.error) j.error = 'HTTP ' + r.status;
  if ((r.status === 401 || r.status === 403) && !j.error) j.error = '无权限或本地登录已失效，请从托盘「打开界面」重新进入';
  return j;
}
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function msg(text, ok) { const el = document.getElementById('save-msg'); el.textContent = text; el.className = 'msg ' + (ok ? 'ok' : 'err'); setTimeout(() => { el.textContent = ''; }, 5000); }

document.querySelectorAll('.tab').forEach(btn => btn.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  if (btn.dataset.tab === 'logs') loadLogs();
  if (btn.dataset.tab === 'certs') loadFiles();
}));

async function loadConfig() {
  if (!appStarted) return;
  if (!isAdmin) {
    cfg = null;
    renderTargets();
    return;
  }
  const r = await api('api/config');
  if (!r.ok) {
    cfg = null;
    const err = '读取配置失败：' + (r.error || '未知错误') + '（请刷新页面；若持续失败，多半是管理员权限或网关身份头问题）';
    msg(err, false);
    const notice = document.getElementById('notice');
    if (notice) { notice.textContent = err; notice.classList.remove('hidden'); }
    return;
  }
  cfg = r.config;
  document.querySelectorAll('[data-k]').forEach(el => {
    const k = el.dataset.k, v = cfg[k];
    if (BOOL.has(k)) { el.checked = !!v; return; }
    if (PASS.has(k)) {
      el.dataset.saved = v === '__KEEP__' ? '1' : '0';
      el.placeholder = v === '__KEEP__' ? '' : '未设置';
      if (v === '__KEEP__') {
        el.type = 'text';
        el.value = MASK;
        el.dataset.mode = 'saved';
        setSecretState(k, '已保存', 'ok');
        toggleSecretClear(k, true);
      } else {
        el.type = 'password';
        el.value = '';
        el.dataset.mode = 'empty';
        setSecretState(k, '未填写', '');
        toggleSecretClear(k, false);
      }
      return;
    }
    el.value = v == null ? '' : v;
  });
  updateTestDeploy();
  updateTgBadge();
  renderTargets();
}

function updateTestDeploy() {
  const box = document.getElementById('ca-test-box');
  if (!box) return;
  const sel = document.querySelector('select[data-k="ca"]');
  const isTest = !!cfg && !!sel && sel.value === 'letsencrypt_test';
  box.classList.toggle('hidden', !isTest);
}

function updateTgBadge() {
  const el = document.getElementById('tg-status');
  if (!el) return;
  const on = !!cfg && !!cfg.tg_enabled;
  el.textContent = on ? '已启用' : '未启用';
  el.className = 'pill' + (on ? ' ok' : '');
}

function setSecretState(k, text, cls) {
  const el = document.getElementById(k + '-state');
  if (!el) return;
  el.textContent = text;
  el.className = 'field-state' + (cls ? ' ' + cls : '');
}

function toggleSecretClear(k, show) {
  const b = document.getElementById(k + '-clear');
  if (b) b.classList.toggle('hidden', !show);
}

function restoreSecret(k) {
  const el = document.querySelector('input[data-k="' + k + '"]');
  if (!el) return;
  if (el.dataset.saved === '1') {
    el.type = 'text';
    el.value = MASK;
    el.dataset.mode = 'saved';
    setSecretState(k, '已保存', 'ok');
    toggleSecretClear(k, true);
  } else {
    el.type = 'password';
    el.value = '';
    el.dataset.mode = 'empty';
    setSecretState(k, '未填写', '');
    toggleSecretClear(k, false);
  }
}

function clearSecret(k) {
  const el = document.querySelector('input[data-k="' + k + '"]');
  if (!el) return;
  el.dataset.mode = 'clear';
  el.type = 'password';
  el.value = '';
  setSecretState(k, '待清除', 'bad');
  toggleSecretClear(k, false);
}

function collectConfig() {
  const out = JSON.parse(JSON.stringify(cfg));
  document.querySelectorAll('[data-k]').forEach(el => {
    const k = el.dataset.k;
    if (BOOL.has(k)) { out[k] = el.checked; return; }
    if (NUM.has(k)) { out[k] = parseInt(el.value, 10) || 0; return; }
    if (PASS.has(k)) {
      const mode = el.dataset.mode || 'empty';
      if (mode === 'clear') out[k] = '__CLEAR__';
      else if (mode === 'saved') out[k] = '__KEEP__';
      else if (el.value === '') out[k] = '__KEEP__';
      else out[k] = el.value;
      return;
    }
    out[k] = el.value;
  });
  return out;
}

async function saveConfig() {
  if (!cfg) { alert('配置尚未加载，请刷新页面后再保存。'); return; }
  const prevDomain = cfg.domain || '';
  const body = collectConfig();
  const r = await api('api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (r.ok) {
    msg('设置已保存并立即生效（密钥不回显，留空表示保持原值）', true);
    await loadConfig();
    refreshAll();
    // 域名变更后旧证书不再匹配，主动引导重新签发
    const newDomain = cfg.domain || '';
    if (prevDomain && prevDomain !== newDomain) {
      if (confirm('域名已从 ' + prevDomain + ' 变更为 ' + newDomain + '：现有证书仍属于旧域名，需要重新签发并重新分发。\n\n是否立即签发？')) act('issue');
    }
  } else {
    msg('保存失败：' + (r.error || '未知错误'), false);
    const el = document.getElementById('save-msg');
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

async function testProbe() {
  const pre = document.getElementById('probe-result');
  pre.classList.remove('hidden');
  pre.textContent = '探测中…（每个源最多 4 秒）';
  const r = await api('api/probe');
  if (!r.ok) { pre.textContent = '探测失败：' + (r.error || '未知错误'); return; }
  const lines = [];
  if (cfg && cfg.ipv4_override) lines.push('已手动指定 IPv4：' + cfg.ipv4_override + '（实际 DDNS 更新将直接使用该值，不探测）');
  if (cfg && cfg.ipv6_override) lines.push('已手动指定 IPv6：' + cfg.ipv6_override + '（实际 DDNS 更新将直接使用该值，不探测）');
  if (r.network_hint) lines.push('网络提示：检测到 ' + r.network_hint + '（如果有出口节点，可能探测到出口 IP）');
  const add = (name, list) => {
    lines.push(name + '：');
    (list || []).forEach(x => lines.push('  ' + x.url + '  ' + (x.ip ? x.ip : '失败：' + x.error) + '  ' + x.ms + 'ms'));
  };
  add('IPv4', r.ipv4);
  add('IPv6', r.ipv6);
  pre.textContent = lines.join('\n');
}

async function testTG() {
  const r = await api('api/actions/test-tg', { method: 'POST' });
  if (!r.ok) { alert('测试失败：' + (r.error || '未知错误')); return; }
  for (let i = 0; i < 40; i++) {
    await new Promise(x => setTimeout(x, 1000));
    const s = await api('api/status');
    const t = (s.tasks || []).find(x => x.name === 'test-tg');
    if (t && t.status !== 'running') {
      refreshAll();
      if (t.status === 'ok') alert('测试消息已发送，请到 Telegram 查看。');
      else alert('测试失败：' + t.message);
      return;
    }
  }
  alert('测试超时，请到日志页查看原因。');
}

async function act(name) {
  if ((name === 'issue' || name === 'renew') && !confirm(name === 'issue' ? '确认立即向证书机构申请新证书？频繁申请可能被限流。' : '确认强制续期？频繁续期可能被限流。')) return;
  if (name === 'cancel') {
    const r = await api('api/actions/cancel', { method: 'POST' });
    alert(r.canceled ? '已请求取消当前任务' : '当前没有可取消的外部命令');
    refreshAll();
    return;
  }
  const r = await api('api/actions/' + name, { method: 'POST' });
  if (!r.ok) { alert('操作未执行：' + (r.error || '未知错误')); return; }
  const taskMsg = (r.task && r.task.message) || '';
  if (taskMsg.indexOf('演示') >= 0 || taskMsg.indexOf('不执行真实任务') >= 0) {
    alert('当前是演示模式（DYNV6_DEMO=1），只显示示例数据，不会执行真实任务。');
    return;
  }
  await refreshAll();
  await waitIdle(name);
}

const TASK_LABEL = { ddns: 'DDNS 更新', issue: '证书签发', renew: '证书续期', check: '证书检查', convert: '格式转换', deploy: '分发', 'deploy-retry': '自动重试分发' };

// 按任务名等待结束：DDNS 与证书分属不同 lane，不能再等全局空闲
async function waitIdle(name) {
  const limit = (name === 'issue' || name === 'renew') ? 600000 : 120000;
  const start = Date.now();
  while (Date.now() - start < limit) {
    await new Promise(r => setTimeout(r, 1200));
    const s = await api('api/status');
    if (!s.ok) continue;
    const t = (s.tasks || []).find(x => x.name === name);
    if (!t || t.status === 'running') {
      await refreshAll();
      continue;
    }
    await refreshAll();
    if (t.status !== 'ok') alert((TASK_LABEL[name] || name) + '失败：' + (t.message || '未知错误'));
    return;
  }
  await refreshAll();
  alert('任务仍在运行，请稍后点「刷新」或到日志页查看结果。');
}

function showAuthGate(mode, errorText) {
  appStarted = false;
  const shell = document.getElementById('app-shell');
  const gate = document.getElementById('auth-gate');
  const setupForm = document.getElementById('setup-form');
  const loginForm = document.getElementById('login-form');
  const title = document.getElementById('auth-title');
  const desc = document.getElementById('auth-desc');
  const error = document.getElementById('auth-error');
  if (!gate || !shell) return;
  shell.classList.add('hidden');
  gate.classList.remove('hidden');
  const isSetup = mode === 'setup';
  setupForm.classList.toggle('hidden', !isSetup);
  loginForm.classList.toggle('hidden', isSetup);
  const tokenRequired = !!(authInfo && authInfo.setupTokenRequired);
  const tokenRow = document.getElementById('setup-token-row');
  if (tokenRow) tokenRow.classList.toggle('hidden', !isSetup || !tokenRequired);
  title.textContent = isSetup ? '创建管理员账号' : '登录 Dynv6 管家';
  desc.textContent = isSetup
    ? (tokenRequired ? '首次启动需要创建管理员；初始化令牌见应用启动日志（Docker 用 docker logs 查看）。' : '首次启动需要创建管理员，完成后即可进入。')
    : '请输入管理员用户名和密码。';
  error.textContent = errorText || '';
  if (isSetup) {
    const u = document.getElementById('setup-username');
    if (u && !u.value) u.value = 'admin';
    const p = document.getElementById('setup-password');
    if (p) setTimeout(() => p.focus(), 50);
  } else {
    const u = document.getElementById('login-username');
    if (u && authInfo && authInfo.username) u.value = authInfo.username;
    const p = document.getElementById('login-password');
    if (p) setTimeout(() => p.focus(), 50);
  }
}

function updateAuthUI() {
  const username = (authInfo && authInfo.username) || '';
  const adminUser = document.getElementById('admin-user');
  if (adminUser) {
    adminUser.textContent = username ? ('账号：' + username) : '';
    adminUser.classList.toggle('hidden', !username);
  }
  const logout = document.getElementById('logout-btn');
  if (logout) logout.classList.remove('hidden');
  const box = document.getElementById('admin-account-box');
  if (box) box.classList.remove('hidden');
  const adminName = document.getElementById('admin-username');
  if (adminName) adminName.textContent = username || '—';
}

async function initAuth() {
  const r = await api('api/auth/status');
  if (!r.ok) {
    showAuthGate('login', r.error || '无法连接服务，请稍后重试');
    return;
  }
  authInfo = r;
  if (r.adminBroken) {
    showAuthGate('login', '管理员配置损坏，请删除数据目录下的 admin.json 后重启应用');
    return;
  }
  if (r.setupRequired) {
    showAuthGate('setup');
    return;
  }
  if (!r.authenticated) {
    showAuthGate('login');
    return;
  }
  startApp();
}

function startApp() {
  appStarted = true;
  const shell = document.getElementById('app-shell');
  const gate = document.getElementById('auth-gate');
  if (shell) shell.classList.remove('hidden');
  if (gate) gate.classList.add('hidden');
  updateAuthUI();
  refreshAll().then(() => loadConfig()).then(() => { loadFiles(); loadLogs(); });
  if (!refreshTimer) {
    refreshTimer = setInterval(() => {
      if (!appStarted) return;
      const logsTab = document.querySelector('.tab[data-tab="logs"]').classList.contains('active');
      if (document.getElementById('autolog').checked && logsTab) loadLogs();
      refreshAll();
    }, 5000);
  }
}

async function submitSetup(event) {
  event.preventDefault();
  const error = document.getElementById('auth-error');
  const username = (document.getElementById('setup-username').value || '').trim() || 'admin';
  const password = document.getElementById('setup-password').value || '';
  const confirm = document.getElementById('setup-confirm').value || '';
  if (password.length < 8) { error.textContent = '密码至少 8 位'; return; }
  if (password !== confirm) { error.textContent = '两次输入的密码不一致'; return; }
  const setupToken = (document.getElementById('setup-token').value || '').trim();
  const r = await api('api/setup/admin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, setupToken })
  });
  if (r.ok) {
    authInfo = { authenticated: true, username: r.username || username };
    document.getElementById('setup-password').value = '';
    document.getElementById('setup-confirm').value = '';
    const tokenInput = document.getElementById('setup-token');
    if (tokenInput) tokenInput.value = '';
    startApp();
    return;
  }
  if (r.code === 'SETUP_ALREADY_COMPLETED') {
    showAuthGate('login', '管理员账号已初始化，请登录');
    return;
  }
  error.textContent = r.error || '初始化失败，请重试';
}

async function submitLogin(event) {
  event.preventDefault();
  const error = document.getElementById('auth-error');
  const username = (document.getElementById('login-username').value || '').trim();
  const password = document.getElementById('login-password').value || '';
  if (!username || !password) { error.textContent = '请输入用户名和密码'; return; }
  const r = await api('api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (r.ok) {
    authInfo = { authenticated: true, username: r.username || username };
    document.getElementById('login-password').value = '';
    startApp();
    return;
  }
  if (r.code === 'SETUP_REQUIRED') {
    showAuthGate('setup', '首次启动请先创建管理员账号');
    return;
  }
  error.textContent = r.error || '登录失败，请检查用户名或密码';
}

async function logoutAdmin() {
  const r = await api('api/auth/logout', { method: 'POST' });
  authInfo = null;
  cfg = null;
  if (!r.ok) { showAuthGate('login', r.error || '退出失败'); return; }
  showAuthGate('login', '已退出登录');
}

async function changeAdminPassword() {
  const el = document.getElementById('admin-password-msg');
  const current = document.getElementById('admin-current-password').value || '';
  const next = document.getElementById('admin-new-password').value || '';
  const confirm = document.getElementById('admin-confirm-password').value || '';
  if (next.length < 8) { el.textContent = '新密码至少 8 位'; el.className = 'hint err'; return; }
  if (next !== confirm) { el.textContent = '两次输入的新密码不一致'; el.className = 'hint err'; return; }
  const r = await api('api/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword: current, newPassword: next, confirmPassword: confirm })
  });
  if (r.ok) {
    el.textContent = '密码修改成功，旧会话已失效';
    el.className = 'hint ok';
    document.getElementById('admin-current-password').value = '';
    document.getElementById('admin-new-password').value = '';
    document.getElementById('admin-confirm-password').value = '';
    return;
  }
  el.textContent = r.error || '修改失败';
  el.className = 'hint err';
}

async function refreshAll() {
  if (!appStarted) return;
  const r = await api('api/status');
  const pill = document.getElementById('health');
  if (!r.ok) {
    if (r.status === 401) { showAuthGate('login', '登录已失效，请重新登录'); return; }
    pill.textContent = '服务未连接'; pill.className = 'pill bad';
    return;
  }
  if (r.auth_required === 'setup') { showAuthGate('setup'); return; }
  if (r.auth_required === 'login') { showAuthGate('login'); return; }
  pill.textContent = '服务正常'; pill.className = 'pill ok';
  // 演示模式与旧版本没有 admin 字段，视为管理员
  isAdmin = r.admin !== false;
  ['settings', 'certs', 'logs'].forEach(name => {
    const btn = document.querySelector('.tab[data-tab="' + name + '"]');
    if (btn) btn.classList.toggle('hidden', !isAdmin);
  });
  if (!isAdmin) {
    const active = document.querySelector('.tab.active');
    if (active && !['overview', 'help'].includes(active.dataset.tab)) {
      const overview = document.querySelector('.tab[data-tab="overview"]');
      if (overview) overview.click();
    }
  }
  const qa = document.getElementById('quick-actions');
  if (qa) {
    qa.classList.toggle('hidden', !isAdmin);
    const h = qa.previousElementSibling;
    if (h && h.tagName === 'H2') h.classList.toggle('hidden', !isAdmin);
  }
  const notice = document.getElementById('notice');
  if (!isAdmin) {
    notice.textContent = '当前账号非管理员：仅能查看概览。配置、任务记录与快捷操作需要管理员账号打开应用。';
    notice.classList.remove('hidden');
  } else if (r.demo) {
    notice.textContent = '演示模式（DYNV6_DEMO=1）：只显示示例数据，不会真实执行 DDNS / 签发 / 分发。';
    notice.classList.remove('hidden');
  } else if (!r.configured) {
    notice.textContent = '尚未完成配置：请到「设置」填写域名与 dynv6 HTTP Token。';
    notice.classList.remove('hidden');
  } else if (r.options && r.options.ca === 'letsencrypt_test') {
    notice.textContent = '当前使用 Let\'s Encrypt 测试环境：证书不被客户端信任，默认只导出不分发；调试完成后请切回正式环境。';
    notice.classList.remove('hidden');
  } else {
    notice.classList.add('hidden');
  }
  envName = r.env || '';
  const ENV = { fnOS: '飞牛 fnOS', windows: 'Windows', docker: 'Docker', generic: '通用 Linux' };
  document.getElementById('env-pill').textContent = ENV[envName] || envName || '未知环境';
  document.getElementById('s-config').textContent = r.configured ? '已配置' : '待配置';
  document.getElementById('s-domain').textContent = r.domain || '未填写域名';
  const s = r.state || {};
  document.getElementById('s-ddns').textContent = s.last_ddns_result || '尚未运行';
  let ipLine = 'IPv4 ' + (s.last_ipv4 || '—') + ' / IPv6 ' + (s.last_ipv6 || '—');
  if (s.last_ddns_attempt) ipLine += ' · 尝试 ' + s.last_ddns_attempt;
  if (r.options && !r.options.auto_ddns) ipLine += ' · 自动更新已关闭';
  if (r.network_hint) ipLine += ' · 网络：' + r.network_hint;
  document.getElementById('s-ip').textContent = ipLine;
  const days = s.cert_days_left || 0;
  document.getElementById('s-days').textContent = s.cert_not_after ? days + ' 天' : '无证书';
  document.getElementById('s-expire').textContent = s.cert_not_after || '请先签发证书';
  document.getElementById('s-busy').textContent = r.busy ? ('运行中：' + r.current + (r.stage ? ' · ' + r.stage : '')) : '空闲';
  document.getElementById('s-last').textContent = s.last_error ? ('上次错误：' + s.last_error) : (s.last_deploy_at ? '上次分发 ' + s.last_deploy_at : '—');
  const p = r.paths || {};
  const pc = r.paths_check || {};
  const mark = k => pc[k] === true ? '<span class="pill ok">可写</span>' : pc[k] === false ? '<span class="pill bad">不可写</span>' : '';
  document.getElementById('paths').innerHTML = !isAdmin
    ? '<tr><td>路径详情</td><td>需要管理员权限查看</td><td></td></tr>'
    : [
      ['证书输出目录', p.output, mark('output')], ['备份目录', p.backup, mark('backup')],
      ['ACME 数据目录', p.acme_home, mark('acme_home')], ['配置文件', p.config, '']
    ].map(x => '<tr><td>' + esc(x[0]) + '</td><td><code>' + esc(x[1]) + '</code></td><td>' + x[2] + '</td></tr>').join('');
  const ap = r.authorized_paths || [];
  const apEl = document.getElementById('auth-paths');
  if (envName === 'fnOS' && isAdmin) {
    apEl.textContent = ap.length ? '已授权路径：' + ap.join('、') : '尚未授权额外路径；分发到共享目录以外的位置前，请先在飞牛「应用设置 → 授权路径」中授权。';
    apEl.classList.remove('hidden');
  } else {
    apEl.classList.add('hidden');
  }
  const tasks = r.tasks || [];
  document.getElementById('tasklist').innerHTML = !isAdmin
    ? '<tr><td colspan="4">任务记录需要管理员权限查看</td></tr>'
    : (tasks.length ? tasks.slice(0, 12).map(t =>
      '<tr><td>' + esc(t.started_at) + '</td><td>' + esc(t.name) + '</td><td>' + (t.status === 'ok' ? '<span class="pill ok">成功</span>' : t.status === 'running' ? '<span class="pill">运行中</span>' : '<span class="pill bad">失败</span>') + '</td><td>' + esc(t.status === 'running' ? (t.stage || '运行中…') : t.message) + '</td></tr>'
    ).join('') : '<tr><td colspan="4">暂无任务</td></tr>');
}

const DESC = {
  '.key': '私钥（飞牛后台「私钥文件」）', '.crt': '单域名证书', '.fullchain.crt': '完整证书链（飞牛后台「证书文件」）',
  '.chain.crt': '中间证书', '.pfx': 'Emby 专用 PKCS#12', '.p12': 'Plex 专用 PKCS#12'
};
async function loadFiles() {
  if (!appStarted || !isAdmin) return;
  const r = await api('api/files');
  document.getElementById('cert-dir').textContent = r.dir || '';
  const list = r.files || [];
  document.getElementById('filelist').innerHTML = list.length ? list.map(f => {
    let use = '';
    for (const k in DESC) if (f.name.endsWith(k)) use = DESC[k];
    return '<tr><td><code>' + esc(f.name) + '</code></td><td>' + f.size + ' B</td><td>' + esc(f.mod_time) + '</td><td>' + esc(use) + '</td><td><a class="btn" href="' + BASE + 'api/files/get?name=' + encodeURIComponent(f.name) + '">下载</a></td></tr>';
  }).join('') : '<tr><td colspan="5">还没有生成证书，请先在概览页点击「立即签发证书」。</td></tr>';
}

async function loadLogs() {
  if (!appStarted || !isAdmin) return;
  const r = await api('api/logs?n=400');
  const el = document.getElementById('logs');
  el.textContent = (r.lines || []).join('\n') || '暂无日志';
  el.scrollTop = el.scrollHeight;
}

const KINDS = { emby: 'Emby（.pfx）', plex: 'Plex（.p12）', pem: 'PEM 全套' };
function dirPlaceholder() {
  if (envName === 'windows') return '例如 D:\\certs';
  if (envName === 'docker') return '容器内挂载路径，如 /certs';
  return '例如 /vol1/1000/media/certs';
}
function targetHint(kind) {
  if (kind === 'emby') return '生成 .pfx（含完整证书链），权限固定 0644；Emby 自定义证书路径填这个文件。';
  if (kind === 'plex') return '生成 .p12（AES-256-CBC / SHA256），权限固定 0644；Plex 自定义证书位置填这个文件。';
  return 'PEM 类型生成 域名.key / .crt / .fullchain.crt / .chain.crt 四个文件；私钥 0600，证书 0644。';
}
function renderTargets() {
  const box = document.getElementById('targets');
  if (!cfg || !cfg.targets) return;
  box.innerHTML = cfg.targets.map((t, i) => `
    <div class="target">
      <div class="target-head">
        <label class="check"><input type="checkbox" data-ti="${i}" data-tk="enabled" ${t.enabled ? 'checked' : ''}> <b>启用</b></label>
        <span class="target-kind">${esc(KINDS[t.kind] || t.kind)}</span>
        <button class="btn ghost" onclick="delTarget(${i})">删除</button>
      </div>
      <div class="grid">
        <label>类型<select data-ti="${i}" data-tk="kind">${Object.keys(KINDS).map(k => '<option value="' + k + '"' + (t.kind === k ? ' selected' : '') + '>' + KINDS[k] + '</option>').join('')}</select></label>
        <label>目标目录<div class="path-row"><input data-ti="${i}" data-tk="dir" value="${esc(t.dir)}" placeholder="${esc(dirPlaceholder())}"><button type="button" class="btn ghost" onclick="openDirPicker(this.previousElementSibling)">选择</button></div><small class="field-hint">支持 \${OUTPUT} 等变量；需 Emby / Plex 用户可读，飞牛上还需在「应用设置 → 授权路径」授权。</small></label>
      </div>
      <p class="hint">${esc(targetHint(t.kind))}</p>
    </div>`).join('') || '<p class="hint">暂无分发目标，点击「添加目标」。</p>';
}
function addTarget() {
  if (!cfg || !Array.isArray(cfg.targets)) { alert('配置尚未加载，请刷新页面后再添加目标。'); return; }
  cfg.targets.push({ id: 't' + Date.now(), name: '自定义目标', kind: 'emby', enabled: false, dir: '', filename: '${DOMAIN}.pfx' });
  renderTargets();
}
function delTarget(i) { cfg.targets.splice(i, 1); renderTargets(); }

let dpTarget = null;
let dpParent = '';

function openDirPicker(input) {
  dpTarget = input;
  dpParent = '';
  document.getElementById('dp-path').textContent = '—';
  document.getElementById('dp-list').innerHTML = '';
  document.getElementById('dir-picker').classList.remove('hidden');
  dpLoad(input.value || '');
}
function closeDirPicker() {
  document.getElementById('dir-picker').classList.add('hidden');
  dpTarget = null;
}
function dpHint(text) {
  document.getElementById('dp-hint').textContent = text ||
    '只显示应用可访问的目录；如需其他位置，请先在飞牛「应用设置 → 授权路径」中授权。';
}
function renderDirList(dirs) {
  const list = document.getElementById('dp-list');
  list.innerHTML = '';
  if (!dirs.length) {
    const empty = document.createElement('div');
    empty.className = 'dp-empty';
    empty.textContent = '没有子目录';
    list.appendChild(empty);
    return;
  }
  dirs.forEach(d => {
    const row = document.createElement('div');
    row.className = 'dp-item';
    row.textContent = '▸ ' + d.name;
    row.addEventListener('click', () => dpLoad(d.path));
    list.appendChild(row);
  });
}
async function dpLoad(path) {
  const r = await api('api/dirs' + (path ? '?path=' + encodeURIComponent(path) : ''));
  if (!r.ok) { dpHint(r.error || '无法读取目录'); return; }
  const rootSel = document.getElementById('dp-root');
  rootSel.innerHTML = '';
  (r.roots || []).forEach(x => rootSel.add(new Option(x.name + ' — ' + x.path, x.path)));
  if (r.error) {
    dpHint(r.error);
    const cur = r.path || '';
    const isRoot = (r.roots || []).some(x => x.path === cur);
    if (!isRoot && (r.roots || []).length) {
      rootSel.value = r.roots[0].path;
      const msg = r.error;
      await dpLoad(r.roots[0].path);
      dpHint(msg);
    } else {
      document.getElementById('dp-path').textContent = cur || '—';
      dpParent = r.parent || '';
      document.getElementById('dp-up').disabled = !dpParent;
      renderDirList([]);
    }
    return;
  }
  const cur = r.path || '';
  if (!cur) {
    if ((r.roots || []).length) {
      rootSel.value = r.roots[0].path;
      await dpLoad(r.roots[0].path);
    }
    return;
  }
  dpHint('');
  const match = (r.roots || []).find(x => x.path === cur);
  if (match) rootSel.value = match.path;
  dpParent = r.parent || '';
  document.getElementById('dp-up').disabled = !dpParent;
  document.getElementById('dp-path').textContent = cur;
  renderDirList(r.dirs || []);
}
function dpRootChange() {
  const v = document.getElementById('dp-root').value;
  if (v) dpLoad(v);
}
function dpUp() {
  if (dpParent) dpLoad(dpParent);
}
function dpChoose() {
  const p = document.getElementById('dp-path').textContent;
  if (!dpTarget || !p || p === '—') { alert('请先进入一个目录'); return; }
  dpTarget.value = p;
  dpTarget.dispatchEvent(new Event('input', { bubbles: true }));
  closeDirPicker();
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDirPicker(); });
document.querySelectorAll('input[data-k]').forEach(el => {
  const k = el.dataset.k;
  if (!PASS.has(k)) return;
  el.addEventListener('focus', () => {
    if (el.dataset.mode === 'saved') {
      el.type = 'password';
      el.value = '';
      el.dataset.mode = 'editing';
    }
  });
  el.addEventListener('input', () => {
    el.dataset.mode = 'editing';
    setSecretState(k, '待保存', 'warn');
    toggleSecretClear(k, false);
  });
  el.addEventListener('blur', () => {
    if (el.dataset.mode === 'editing' && el.value === '') restoreSecret(k);
  });
});
const caSelect = document.querySelector('select[data-k="ca"]');
if (caSelect) caSelect.addEventListener('change', updateTestDeploy);
const tgToggle = document.querySelector('input[data-k="tg_enabled"]');
if (tgToggle) tgToggle.addEventListener('change', () => {
  const el = document.getElementById('tg-status');
  if (!el) return;
  el.textContent = tgToggle.checked ? '已启用' : '未启用';
  el.className = 'pill' + (tgToggle.checked ? ' ok' : '');
});
document.getElementById('targets').addEventListener('input', e => {
  const el = e.target;
  if (el.dataset.ti === undefined) return;
  const i = +el.dataset.ti, k = el.dataset.tk;
  if (!cfg.targets[i]) return;
  if (k === 'enabled') cfg.targets[i][k] = el.checked;
  else cfg.targets[i][k] = el.value;
});
document.getElementById('targets').addEventListener('change', e => {
  e.target.dispatchEvent(new Event('input', { bubbles: true }));
  if (e.target.dataset.tk === 'kind') renderTargets();
});

initAuth();
