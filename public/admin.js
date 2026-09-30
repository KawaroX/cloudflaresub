const $ = id => document.getElementById(id);
let globalConfig = {}, profiles = [], nodeSources = [], authToken = '', editingId = null, dirty = false, loaded = false;
let savedIpCount = 0;
const escapeHtml = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');

function status(id, message, kind = 'success') {
  $(id).innerHTML = message ? `<div class="status-msg ${kind}">${escapeHtml(message)}</div>` : '';
}
async function api(path, method = 'GET', body) {
  const res = await fetch(path, { method, headers: { 'content-type': 'application/json', ...(authToken ? { authorization: `Bearer ${authToken}` } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || '请求失败');
  return data;
}
async function busy(button, action, statusId) {
  if (button.disabled) return;
  // Keep a pending import/save attached to the user whose editor submitted it.
  const locked = button.closest('#editorSection')
    ? [...document.querySelectorAll('#editorSection input, #editorSection textarea, #editorSection select, #editorSection button, #profilesList button, #newProfileBtn, #loadBtn')].map(el => [el, el.disabled])
    : [];
  locked.forEach(([el]) => { el.disabled = true; });
  button.disabled = true;
  try { await action(); } catch (error) { status(statusId, error.message, 'error'); }
  finally {
    locked.forEach(([el, disabled]) => { if (el.isConnected) el.disabled = disabled; });
    button.disabled = false;
  }
}
function markDirty() {
  dirty = true;
  $('draftState').textContent = '有未保存的修改';
  $('preview').hidden = true;
}
function allowDiscard() { return !dirty || confirm('当前用户有未保存的修改，确定放弃吗？'); }
function subUrl(profile, target) {
  const url = new URL(`/sub/${profile.subId}`, location.origin);
  if (authToken) url.searchParams.set('token', authToken);
  url.searchParams.set('target', target);
  if (profile.subscriptionName) url.searchParams.set('filename', profile.subscriptionName);
  return url.toString();
}
function renderProfiles() {
  $('profilesList').innerHTML = profiles.length ? profiles.map((p, i) => {
    const formats = [['Clash', 'clash']];
    if ((p.nodeSources || []).every(n => n.format === 'link')) formats.push(['原始链接', 'raw']);
    return `<article class="profile-card ${editingId === p.id ? 'active' : ''}">
      <div class="profile-header"><h3>${escapeHtml(p.name || p.id)} <span class="muted">${escapeHtml(p.subscriptionName || p.id)} · ${(p.nodeSources || []).length} 个节点</span></h3>
      <div class="actions"><button class="secondary small" type="button" data-edit="${i}">编辑</button><button class="secondary small btn-danger" type="button" data-delete="${i}">删除</button></div></div>
      ${formats.map(([label, target]) => `<div class="profile-url-row"><label for="url-${i}-${target}">${label}</label><input id="url-${i}-${target}" readonly value="${escapeHtml(subUrl(p, target))}" /><button type="button" class="secondary small" data-copy="url-${i}-${target}">复制</button></div>`).join('')}
      ${formats.length === 1 ? '<p class="hint">包含 YAML 节点，请使用 Clash 订阅，完整保留各协议参数。</p>' : ''}
    </article>`;
  }).join('') : '<p class="empty-state">暂无用户。点击“新建用户”开始配置。</p>';
}
async function loadAll() {
  if (!allowDiscard()) return;
  authToken = $('authToken').value.trim();
  // Load sequentially so legacy migration finishes before listing profiles.
  const configResult = await api('/api/admin/config');
  const profileResult = await api('/api/admin/profiles');
  globalConfig = configResult.config;
  savedIpCount = configResult.preferredIpCount;
  profiles = profileResult.profiles;
  loaded = true;
  $('preferredIps').value = globalConfig.preferredIps || '';
  $('ipCount').textContent = `${savedIpCount} 个已保存`;
  $('saveConfigBtn').disabled = false;
  $('newProfileBtn').disabled = false;
  closeEditor();
  renderProfiles();
  status('statusGlobal', '配置已加载');
}
async function saveConfig() {
  const result = await api('/api/admin/config', 'PUT', { preferredIps: $('preferredIps').value });
  globalConfig = result.config;
  savedIpCount = result.preferredIpCount;
  $('ipCount').textContent = `${savedIpCount} 个已保存`;
  refreshNodeSummaries();
  $('preview').hidden = true;
  status('configStatus', `已保存 ${savedIpCount} 个优选地址，各用户刷新订阅后生效`);
}
function renderNodes() {
  $('nodeCount').textContent = `${nodeSources.length} 个`;
  $('nodesList').innerHTML = nodeSources.map((source, i) => `<article class="node-card" data-node="${i}">
    <div class="profile-header"><h3>节点 ${i + 1} <span class="badge">${source.format === 'link' ? '链接' : 'YAML'}</span></h3><button type="button" class="secondary small btn-danger" data-remove="${i}">移除</button></div>
    <div class="form-group"><label for="node-content-${i}">${source.format === 'link' ? '节点链接' : '节点 YAML'}</label><textarea id="node-content-${i}" data-field="content" rows="${source.format === 'link' ? 3 : 9}" spellcheck="false">${escapeHtml(source.content)}</textarea></div>
    <div class="node-options">
      <label class="check-label" for="node-preferred-${i}"><input id="node-preferred-${i}" data-field="usePreferredIps" type="checkbox" ${source.usePreferredIps ? 'checked' : ''} />使用优选 IP</label>
      <div class="count-settings"><label for="node-mode-${i}">数量</label><select id="node-mode-${i}" data-field="countMode" ${source.usePreferredIps ? '' : 'disabled'}><option value="all" ${source.preferredIpCount == null ? 'selected' : ''}>全部</option><option value="first" ${source.preferredIpCount != null ? 'selected' : ''}>前 N 个</option></select>
      <input id="node-count-${i}" aria-label="节点 ${i + 1} 的优选 IP 数量" data-field="preferredIpCount" type="number" min="1" step="1" value="${escapeHtml(source.preferredIpCount ?? 5)}" ${source.preferredIpCount == null ? 'hidden' : ''} ${source.usePreferredIps ? '' : 'disabled'} /></div>
    </div><p id="node-summary-${i}" class="node-summary"></p>
  </article>`).join('') || '<p class="empty-state">还没有节点。在上方粘贴链接或 YAML 添加。</p>';
  refreshNodeSummaries();
}
function refreshNodeSummaries() {
  nodeSources.forEach((source, i) => {
    const amount = Math.min(savedIpCount, source.preferredIpCount ?? savedIpCount);
    $(`node-summary-${i}`).textContent = source.usePreferredIps
      ? `生成 1 个原始节点 + ${Number.isFinite(amount) ? amount : 0} 个优选节点（按已保存的公共列表顺序）${source.preferredIpCount > savedIpCount ? '；公共 IP 不足，使用全部可用地址' : ''}`
      : '只生成原始节点';
  });
}
function openEditor(profile = null) {
  if (!allowDiscard()) return;
  editingId = profile?.id ?? null;
  nodeSources = structuredClone(profile?.nodeSources || []);
  $('pId').value = profile?.id || '';
  $('pId').readOnly = !!profile;
  $('pName').value = profile?.name || '';
  $('pSubName').value = profile?.subscriptionName || '';
  $('importContent').value = '';
  $('editorHeading').textContent = profile ? `编辑 ${profile.name || profile.id}` : '新建用户';
  $('draftState').textContent = profile ? '已保存' : '未保存';
  $('editorSection').hidden = false;
  $('preview').hidden = true;
  status('importStatus', ''); status('profileStatus', '');
  dirty = false;
  renderNodes(); renderProfiles();
  $('editorSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function closeEditor() {
  dirty = false; editingId = null; nodeSources = [];
  $('editorSection').hidden = true;
  renderProfiles();
}
async function importSources() {
  const { nodeSources: imported } = await api('/api/admin/import', 'POST', { format: $('importFormat').value, content: $('importContent').value });
  nodeSources.push(...imported);
  $('importContent').value = '';
  markDirty(); renderNodes();
  status('importStatus', `已添加 ${imported.length} 个节点，请分别设置优选方式并保存`);
}
async function saveProfile() {
  if ($('importContent').value.trim()) throw new Error('上方还有未添加的节点内容，请先点击“添加到此用户”或清空输入框');
  const requestedId = $('pId').value.trim();
  if (!editingId && requestedId && profiles.some(p => p.id === requestedId)) throw new Error('该用户 ID 已存在，请在用户列表点击“编辑”');
  const result = await api('/api/admin/profiles', 'POST', {
    id: editingId || requestedId || undefined, name: $('pName').value.trim(),
    subscriptionName: $('pSubName').value.trim(), nodeSources,
  });
  const profile = { ...result.profile, id: result.profileId };
  const index = profiles.findIndex(p => p.id === profile.id);
  if (index < 0) profiles.push(profile); else profiles[index] = profile;
  dirty = false;
  openEditor(profile);
  status('profileStatus', `用户 ${profile.name || profile.id} 已保存。${(result.warnings || []).join('；')}`);
}
async function preview() {
  const result = await api('/api/admin/preview', 'POST', { nodeSources });
  $('preview').innerHTML = `<h3>生成预览 · ${result.nodes.length} 个节点</h3>
    ${result.warnings.map(w => `<p class="status-msg warning">${escapeHtml(w)}</p>`).join('')}
    <div class="table-scroll"><table class="preview-table"><thead><tr><th>节点名称</th><th>协议</th><th>连接地址</th></tr></thead><tbody>${result.nodes.map(n => `<tr><td>${escapeHtml(n.name)}</td><td>${escapeHtml([n.type, n.network].filter(Boolean).join(' / '))}</td><td>${escapeHtml(n.server)}:${n.port}</td></tr>`).join('')}</tbody></table></div>`;
  $('preview').hidden = false;
}
function changeImportFormat() {
  const yaml = $('importFormat').value === 'yaml';
  $('importLabel').textContent = yaml ? '节点 YAML（支持单个节点、节点列表或含 proxies 的配置）' : '节点链接（每行一个）';
  $('importHint').textContent = yaml ? '保留完整 Reality、XHTTP、Hy2 等参数；导入后拆成独立节点。YAML 节点使用 Clash 订阅。' : '支持 VLESS、VMess、Trojan、Hysteria2 链接。批量导入后，每个节点可以分别设置优选数量。';
  $('importContent').placeholder = yaml ? "- name: '美国节点'\n  type: vless\n  server: example.com\n  port: 443\n  uuid: your-uuid\n  network: xhttp\n  tls: true" : 'vless://uuid@server:443?type=xhttp&security=tls&path=%2Fxhttp%2F#美国节点';
}
$('loadBtn').addEventListener('click', () => busy($('loadBtn'), loadAll, 'statusGlobal'));
$('saveConfigBtn').addEventListener('click', () => busy($('saveConfigBtn'), saveConfig, 'configStatus'));
$('saveProfileBtn').addEventListener('click', () => busy($('saveProfileBtn'), saveProfile, 'profileStatus'));
$('previewBtn').addEventListener('click', () => busy($('previewBtn'), preview, 'profileStatus'));
$('importBtn').addEventListener('click', () => busy($('importBtn'), importSources, 'importStatus'));
$('newProfileBtn').addEventListener('click', () => openEditor());
$('clearProfileBtn').addEventListener('click', () => { if (allowDiscard()) closeEditor(); });
$('importFormat').addEventListener('change', changeImportFormat);
$('authToken').addEventListener('keydown', e => { if (e.key === 'Enter') $('loadBtn').click(); });
$('preferredIps').addEventListener('input', () => { if (loaded) $('ipCount').textContent = 'IP 列表尚未保存'; });
for (const id of ['pId', 'pName', 'pSubName', 'importContent']) $(id).addEventListener('input', markDirty);
$('nodesList').addEventListener('input', e => {
  const card = e.target.closest('[data-node]');
  if (!card || !e.target.dataset.field) return;
  const i = Number(card.dataset.node), source = nodeSources[i], field = e.target.dataset.field;
  if (field === 'content') source.content = e.target.value;
  else if (field === 'usePreferredIps') {
    source.usePreferredIps = e.target.checked;
    $(`node-mode-${i}`).disabled = !source.usePreferredIps;
    $(`node-count-${i}`).disabled = !source.usePreferredIps;
  } else if (field === 'countMode') {
    source.preferredIpCount = e.target.value === 'all' ? null : $(`node-count-${i}`).value;
    $(`node-count-${i}`).hidden = e.target.value === 'all';
  } else if (field === 'preferredIpCount') source.preferredIpCount = e.target.value || 'invalid';
  markDirty(); refreshNodeSummaries();
});
document.addEventListener('click', async e => {
  const button = e.target.closest('button');
  if (!button) return;
  if (button.dataset.edit !== undefined) openEditor(profiles[Number(button.dataset.edit)]);
  if (button.dataset.remove !== undefined) { nodeSources.splice(Number(button.dataset.remove), 1); markDirty(); renderNodes(); }
  if (button.dataset.delete !== undefined) {
    const profile = profiles[Number(button.dataset.delete)];
    if (!confirm(`确定删除用户 ${profile.name || profile.id}？对应订阅链接也将失效。`)) return;
    await busy(button, async () => {
      await api(`/api/admin/profiles/${encodeURIComponent(profile.id)}`, 'DELETE');
      profiles = profiles.filter(p => p.id !== profile.id);
      if (editingId === profile.id) closeEditor();
      renderProfiles(); status('statusGlobal', '用户已删除');
    }, 'statusGlobal');
  }
  if (button.dataset.copy) {
    const input = $(button.dataset.copy);
    try { await navigator.clipboard.writeText(input.value); button.textContent = '已复制'; }
    catch { input.select(); button.textContent = document.execCommand('copy') ? '已复制' : '请手动复制'; }
    setTimeout(() => { button.textContent = '复制'; }, 1800);
  }
});
window.addEventListener('beforeunload', e => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
