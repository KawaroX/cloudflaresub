// Admin panel logic

const $ = (id) => document.getElementById(id);

let globalConfig = {};
let profiles = [];
let authToken = '';

function headers() {
  const h = { 'content-type': 'application/json' };
  if (authToken) h['authorization'] = `Bearer ${authToken}`;
  return h;
}

function showStatus(elId, message, ok = true) {
  const el = $(elId);
  if (!el) return;
  el.innerHTML = `<div class="status-msg ${ok ? 'success' : 'error'}">${escapeHtml(message)}</div>`;
  setTimeout(() => { el.innerHTML = ''; }, 4000);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// --- Load all data ---

async function loadAll() {
  authToken = $('authToken').value.trim();
  try {
    const [configRes, profilesRes] = await Promise.all([
      fetch('/api/admin/config', { headers: headers() }),
      fetch('/api/admin/profiles', { headers: headers() }),
    ]);
    const configData = await configRes.json();
    const profilesData = await profilesRes.json();

    if (!configData.ok) throw new Error(configData.error || 'Failed to load config');
    if (!profilesData.ok) throw new Error(profilesData.error || 'Failed to load profiles');

    globalConfig = configData.config || {};
    profiles = profilesData.profiles || [];

    renderConfig();
    renderProfiles();
    renderUuidFields();
    showStatus('statusGlobal', '配置加载成功', true);
  } catch (e) {
    showStatus('statusGlobal', e.message, false);
  }
}

// --- Render global config ---

function renderConfig() {
  $('preferredIps').value = globalConfig.preferredIps || '';
  $('sharedExtraNodesYaml').value = globalConfig.sharedExtraNodesYaml || '';
  renderTemplates();
}

function renderTemplates() {
  const container = $('templatesContainer');
  const templates = globalConfig.extraNodeTemplates || [];
  container.innerHTML = '';

  templates.forEach((tpl, idx) => {
    const card = document.createElement('div');
    card.className = 'template-card';
    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
        <h3>模板 #${idx + 1}: ${escapeHtml(tpl.nameLabel || tpl.id || '')}</h3>
        <button type="button" class="secondary small btn-danger" data-remove-tpl="${idx}">删除</button>
      </div>
      <div class="form-row three-col">
        <div class="form-group">
          <label>ID</label>
          <input type="text" data-tpl="${idx}" data-field="id" value="${escapeHtml(tpl.id || '')}" />
        </div>
        <div class="form-group">
          <label>名称标签</label>
          <input type="text" data-tpl="${idx}" data-field="nameLabel" value="${escapeHtml(tpl.nameLabel || '')}" />
        </div>
        <div class="form-group">
          <label>国家代码</label>
          <input type="text" data-tpl="${idx}" data-field="countryCode" value="${escapeHtml(tpl.countryCode || 'US')}" placeholder="US" />
        </div>
      </div>
      <div class="form-row three-col">
        <div class="form-group">
          <label>类型</label>
          <input type="text" data-tpl="${idx}" data-field="type" value="${escapeHtml(tpl.type || 'vless')}" />
        </div>
        <div class="form-group">
          <label>服务器</label>
          <input type="text" data-tpl="${idx}" data-field="server" value="${escapeHtml(tpl.server || '')}" />
        </div>
        <div class="form-group">
          <label>端口</label>
          <input type="number" data-tpl="${idx}" data-field="port" value="${tpl.port || ''}" />
        </div>
      </div>
      <div class="form-row three-col">
        <div class="form-group">
          <label>网络</label>
          <input type="text" data-tpl="${idx}" data-field="network" value="${escapeHtml(tpl.network || 'tcp')}" placeholder="tcp / grpc" />
        </div>
        <div class="form-group">
          <label>安全</label>
          <input type="text" data-tpl="${idx}" data-field="security" value="${escapeHtml(tpl.security || 'reality')}" placeholder="reality / tls" />
        </div>
        <div class="form-group">
          <label>伪装域名 (servername)</label>
          <input type="text" data-tpl="${idx}" data-field="servername" value="${escapeHtml(tpl.servername || '')}" />
        </div>
      </div>
      <div class="form-row three-col">
        <div class="form-group">
          <label>指纹 (fp)</label>
          <input type="text" data-tpl="${idx}" data-field="fp" value="${escapeHtml(tpl.fp || 'chrome')}" />
        </div>
        <div class="form-group">
          <label>公钥 (publicKey)</label>
          <input type="text" data-tpl="${idx}" data-field="publicKey" value="${escapeHtml(tpl.publicKey || '')}" />
        </div>
        <div class="form-group">
          <label>短 ID (shortId)</label>
          <input type="text" data-tpl="${idx}" data-field="shortId" value="${escapeHtml(tpl.shortId || '')}" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>gRPC 服务名 (serviceName)</label>
          <input type="text" data-tpl="${idx}" data-field="serviceName" value="${escapeHtml(tpl.serviceName || '')}" />
        </div>
        <div class="form-group">
          <label>流控 (flow)</label>
          <input type="text" data-tpl="${idx}" data-field="flow" value="${escapeHtml(tpl.flow || '')}" placeholder="xtls-rprx-vision" />
        </div>
      </div>
      <div class="form-group">
        <label style="display:flex;align-items:center;gap:8px;">
          <input type="checkbox" data-tpl="${idx}" data-field="uuidPerUser" ${tpl.uuidPerUser !== false ? 'checked' : ''} style="width:18px;height:18px;" />
          每个用户使用独立 UUID
        </label>
      </div>
    `;
    container.appendChild(card);
  });
}

function collectTemplates() {
  const templates = [];
  const cards = $('templatesContainer').querySelectorAll('.template-card');
  cards.forEach((card, idx) => {
    const get = (field) => {
      const el = card.querySelector(`[data-tpl="${idx}"][data-field="${field}"]`);
      if (!el) return '';
      if (el.type === 'checkbox') return el.checked;
      if (el.type === 'number') return Number(el.value) || 0;
      return el.value.trim();
    };
    templates.push({
      id: get('id'),
      nameLabel: get('nameLabel'),
      countryCode: get('countryCode') || 'US',
      type: get('type') || 'vless',
      server: get('server'),
      port: get('port'),
      network: get('network') || 'tcp',
      security: get('security') || 'reality',
      servername: get('servername'),
      fp: get('fp') || 'chrome',
      publicKey: get('publicKey'),
      shortId: get('shortId'),
      serviceName: get('serviceName'),
      flow: get('flow'),
      uuidPerUser: get('uuidPerUser'),
    });
  });
  return templates;
}

// --- Save global config ---

async function saveConfig() {
  const config = {
    ...globalConfig,
    preferredIps: $('preferredIps').value,
    sharedExtraNodesYaml: $('sharedExtraNodesYaml').value,
    extraNodeTemplates: collectTemplates(),
  };

  try {
    const res = await fetch('/api/admin/config', {
      method: 'PUT',
      headers: headers(),
      body: JSON.stringify({ config }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Save failed');
    globalConfig = config;
    renderUuidFields();
    showStatus('configStatus', '全局配置已保存', true);
  } catch (e) {
    showStatus('configStatus', e.message, false);
  }
}

// --- Render profiles ---

function renderProfiles() {
  const container = $('profilesList');
  if (!profiles.length) {
    container.innerHTML = '<div class="empty-state">暂无用户配置。请在下方添加。</div>';
    return;
  }

  container.innerHTML = profiles.map((p) => {
    const origin = location.origin;
    const tokenParam = authToken ? `token=${encodeURIComponent(authToken)}` : '';
    const fileParam = p.subscriptionName ? `&filename=${encodeURIComponent(p.subscriptionName)}` : '';
    const baseUrl = `${origin}/sub/${p.subId}${tokenParam ? '?' + tokenParam : ''}`;
    const clashUrl = `${origin}/sub/${p.subId}?${tokenParam}&target=clash${fileParam}`;
    const autoUrl = baseUrl + fileParam;

    return `
      <div class="profile-card">
        <div class="profile-header">
          <h3>${escapeHtml(p.name || p.id)} <span style="color:var(--muted);font-size:13px;">(${escapeHtml(p.id)})</span></h3>
          <div style="display:flex;gap:8px;">
            <button type="button" class="secondary small" data-edit-profile="${escapeHtml(p.id)}">编辑</button>
            <button type="button" class="secondary small btn-danger" data-delete-profile="${escapeHtml(p.id)}">删除</button>
          </div>
        </div>
        <div class="profile-urls">
          <div class="profile-url-row">
            <span>自动识别</span>
            <input readonly value="${escapeHtml(autoUrl)}" />
            <button type="button" class="secondary small" data-copy-val="${escapeHtml(autoUrl)}">复制</button>
          </div>
          <div class="profile-url-row">
            <span>Clash</span>
            <input readonly value="${escapeHtml(clashUrl)}" />
            <button type="button" class="secondary small" data-copy-val="${escapeHtml(clashUrl)}">复制</button>
          </div>
        </div>
      </div>`;
  }).join('');
}

// --- UUID fields for profile form ---

function renderUuidFields() {
  const container = $('profileUuidsFields');
  const templates = globalConfig.extraNodeTemplates || [];
  if (!templates.length) {
    container.innerHTML = '<p class="hint">暂无额外节点模板。请先在全局配置中添加模板。</p>';
    return;
  }
  container.innerHTML = templates
    .filter(t => t.uuidPerUser)
    .map(t => `
      <div class="uuid-row">
        <span>${escapeHtml(t.nameLabel || t.id)}</span>
        <input type="text" data-uuid-tpl="${escapeHtml(t.id)}" placeholder="此用户在 ${escapeHtml(t.nameLabel || t.id)} 的 UUID" />
      </div>
    `).join('');
}

// --- Save profile ---

async function saveProfile() {
  const templates = globalConfig.extraNodeTemplates || [];
  const extraUuids = {};
  templates.filter(t => t.uuidPerUser).forEach(t => {
    const el = document.querySelector(`[data-uuid-tpl="${t.id}"]`);
    if (el && el.value.trim()) {
      extraUuids[t.id] = el.value.trim();
    }
  });

  const body = {
    id: $('pId').value.trim() || undefined,
    name: $('pName').value.trim(),
    wsNodeLink: $('pWsNodeLink').value.trim(),
    subscriptionName: $('pSubName').value.trim(),
    keepOriginalHost: $('pKeepHost').checked,
    addFlagEmoji: $('pFlagEmoji').checked,
    extraUuids,
  };

  try {
    const res = await fetch('/api/admin/profiles', {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Save failed');
    showStatus('profileStatus', `用户 ${data.profileId} 已保存`, true);
    clearProfileForm();
    await loadAll();
  } catch (e) {
    showStatus('profileStatus', e.message, false);
  }
}

async function deleteProfile(profileId) {
  if (!confirm(`确定删除用户 ${profileId}？`)) return;
  try {
    const res = await fetch(`/api/admin/profiles/${encodeURIComponent(profileId)}`, {
      method: 'DELETE',
      headers: headers(),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Delete failed');
    showStatus('profileStatus', `用户 ${profileId} 已删除`, true);
    await loadAll();
  } catch (e) {
    showStatus('profileStatus', e.message, false);
  }
}

function editProfile(profileId) {
  const p = profiles.find(pr => pr.id === profileId);
  if (!p) return;
  $('pId').value = p.id;
  $('pName').value = p.name || '';
  $('pWsNodeLink').value = p.wsNodeLink || '';
  $('pSubName').value = p.subscriptionName || '';
  $('pKeepHost').checked = p.keepOriginalHost !== false;
  $('pFlagEmoji').checked = p.addFlagEmoji === true;

  // Fill UUID fields
  const templates = globalConfig.extraNodeTemplates || [];
  templates.filter(t => t.uuidPerUser).forEach(t => {
    const el = document.querySelector(`[data-uuid-tpl="${t.id}"]`);
    if (el) el.value = (p.extraUuids && p.extraUuids[t.id]) || '';
  });

  $('pId').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function clearProfileForm() {
  $('pId').value = '';
  $('pName').value = '';
  $('pWsNodeLink').value = '';
  $('pSubName').value = '';
  $('pKeepHost').checked = true;
  $('pFlagEmoji').checked = false;
  document.querySelectorAll('[data-uuid-tpl]').forEach(el => { el.value = ''; });
}

// --- Copy helper ---

async function copyToClipboard(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = '已复制';
    setTimeout(() => { btn.textContent = orig; }, 1200);
  } catch {
    // fallback
    const input = document.createElement('input');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
  }
}

// --- Event listeners ---

$('loadBtn').addEventListener('click', loadAll);
$('saveConfigBtn').addEventListener('click', saveConfig);
$('saveProfileBtn').addEventListener('click', saveProfile);
$('clearProfileBtn').addEventListener('click', clearProfileForm);

$('addTemplateBtn').addEventListener('click', () => {
  if (!globalConfig.extraNodeTemplates) globalConfig.extraNodeTemplates = [];
  globalConfig.extraNodeTemplates.push({
    id: '', nameLabel: '', countryCode: 'US', type: 'vless',
    server: '', port: 443, network: 'tcp', security: 'reality',
    servername: '', fp: 'chrome', publicKey: '', shortId: '',
    serviceName: '', flow: '', uuidPerUser: true,
  });
  renderTemplates();
  renderUuidFields();
});

// Delegated events
document.addEventListener('click', (e) => {
  const removeTpl = e.target.closest('[data-remove-tpl]');
  if (removeTpl) {
    const idx = Number(removeTpl.dataset.removeTpl);
    if (globalConfig.extraNodeTemplates) {
      globalConfig.extraNodeTemplates.splice(idx, 1);
      renderTemplates();
      renderUuidFields();
    }
    return;
  }

  const editBtn = e.target.closest('[data-edit-profile]');
  if (editBtn) {
    editProfile(editBtn.dataset.editProfile);
    return;
  }

  const deleteBtn = e.target.closest('[data-delete-profile]');
  if (deleteBtn) {
    deleteProfile(deleteBtn.dataset.deleteProfile);
    return;
  }

  const copyBtn = e.target.closest('[data-copy-val]');
  if (copyBtn) {
    copyToClipboard(copyBtn.dataset.copyVal, copyBtn);
    return;
  }
});

// Allow pressing Enter in token field to load
$('authToken').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') loadAll();
});
