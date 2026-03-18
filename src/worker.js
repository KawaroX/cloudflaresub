
import { CLASH_RULES_B64 } from "./rules.js";

// Cloudflare Worker: KV short link subscription
function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, { status, headers: { 'content-type': contentType, 'access-control-allow-origin': '*' } });
}

function b64EncodeUtf8(str) { return btoa(unescape(encodeURIComponent(str))); }
function b64DecodeUtf8(str) { return decodeURIComponent(escape(atob(str))); }

function parsePreferredEndpoints(input) {
  return String(input || '').split('\n').map(l => l.trim()).filter(Boolean).map(line => {
    const forceReplace = line.endsWith('#');
    const parts = line.split('#').filter((p, i) => i < 2 || (i === 2 && p === ''));
    const raw = parts[0] || '';
    const remark = parts[1] || '';
    const match = raw.trim().match(/^(.*?)(?::(\d+))?$/);
    return { server: match?.[1] || raw.trim(), port: match?.[2] ? Number(match[2]) : undefined, remark: remark.trim(), forceReplace };
  });
}

function parseVmess(link) {
  const obj = JSON.parse(b64DecodeUtf8(link.slice(8)));
  return { type: 'vmess', name: obj.ps || 'vmess', server: obj.add, port: Number(obj.port), uuid: obj.id, cipher: obj.scy || 'auto', network: obj.net || 'ws', tls: obj.tls === 'tls', host: obj.host || '', path: obj.path || '/', sni: obj.sni || obj.host || '' };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return { type, name: decodeURIComponent(u.hash.replace(/^#/, '')) || type, server: u.hostname, port: Number(u.port || 443), password: type === 'trojan' ? decodeURIComponent(u.username) : undefined, uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined, network: u.searchParams.get('type') || 'tcp', tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls', host: u.searchParams.get('host') || u.searchParams.get('sni') || '', path: u.searchParams.get('path') || '/', sni: u.searchParams.get('sni') || u.searchParams.get('host') || '' };
}

function parseRawLinks(input) {
  const result = [];
  for (const line of String(input).split('\n').map(l => l.trim()).filter(Boolean)) {
    if (line.startsWith('vmess://')) result.push(parseVmess(line));
    else if (line.startsWith('vless://')) result.push(parseUrlLike(line, 'vless'));
    else if (line.startsWith('trojan://')) result.push(parseUrlLike(line, 'trojan'));
    else { try { const d = b64DecodeUtf8(line); if (/^(vmess|vless|trojan):\/\//m.test(d)) result.push(...parseRawLinks(d)); } catch(e){} }
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter++;
      let name = ep.forceReplace && ep.remark ? ep.remark : [node.name, options.namePrefix, ep.remark || String(counter)].filter(Boolean).join(' | ');
      output.push({ ...node, name, server: ep.server, port: ep.port || node.port, host: options.keepOriginalHost ? node.host : '', sni: options.keepOriginalHost ? node.sni : '' });
    }
  }
  return output;
}

function encodeVmess(n) { return 'vmess://' + b64EncodeUtf8(JSON.stringify({ v: '2', ps: n.name, add: n.server, port: String(n.port), id: n.uuid, aid: '0', scy: n.cipher || 'auto', net: n.network || 'ws', type: 'none', host: n.host || '', path: n.path || '/', tls: n.tls ? 'tls' : '', sni: n.sni || '' })); }
function encodeVless(n) { const u = new URL('vless://' + n.uuid + '@' + n.server + ':' + n.port); u.searchParams.set('type', n.network || 'ws'); if (n.tls) u.searchParams.set('security', 'tls'); if (n.host) u.searchParams.set('host', n.host); if (n.path) u.searchParams.set('path', n.path); u.hash = n.name; return u.toString(); }
function encodeTrojan(n) { const u = new URL('trojan://' + n.password + '@' + n.server + ':' + n.port); u.searchParams.set('type', n.network || 'ws'); if (n.tls) u.searchParams.set('security', 'tls'); if (n.host) u.searchParams.set('host', n.host); u.hash = n.name; return u.toString(); }

function renderRaw(nodes) { return b64EncodeUtf8(nodes.map(n => n.type==='vmess'?encodeVmess(n):n.type==='vless'?encodeVless(n):encodeTrojan(n)).filter(Boolean).join('\n')); }

function renderClash(nodes) {
  const CLASH_RULES = atob(CLASH_RULES_B64);
  const proxyList = nodes.map(n => ({ name: n.name, type: n.type, server: n.server, port: n.port, uuid: n.uuid, password: n.password, alterId: 0, cipher: 'auto', tls: n.tls, servername: n.sni || '', network: n.network || 'ws', 'ws-opts': { path: n.path || '/', headers: { Host: n.host || '' } }, udp: true, 'skip-cert-verify': true }));
  const names = proxyList.map(p => p.name);
  
  let yaml = 'mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: warning\nunified-delay: true\nglobal-client-fingerprint: chrome\n\nproxies:\n';
  yaml += proxyList.map(p => '  - ' + JSON.stringify(p)).join('\n') + '\n\n';
  
  yaml += 'proxy-groups:\n';
  yaml += '  - name: 🚀 节点选择\n    type: select\n    proxies: ["♻️ 自动选择", "DIRECT", ' + names.map(n => JSON.stringify(n)).join(', ') + ']\n';
  yaml += '  - name: ♻️ 自动选择\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies: [' + names.map(n => JSON.stringify(n)).join(', ') + ']\n';
  yaml += '  - name: 🌍 国外媒体\n    type: select\n    proxies: ["🚀 节点选择", "♻️ 自动选择", "🎯 全球直连", ' + names.map(n => JSON.stringify(n)).join(', ') + ']\n';
  yaml += '  - name: 📲 电报信息\n    type: select\n    proxies: ["🚀 节点选择", "🎯 全球直连", ' + names.map(n => JSON.stringify(n)).join(', ') + ']\n';
  yaml += '  - name: Ⓜ️ 微软服务\n    type: select\n    proxies: ["🎯 全球直连", "🚀 节点选择", ' + names.map(n => JSON.stringify(n)).join(', ') + ']\n';
  yaml += '  - name: 🍎 苹果服务\n    type: select\n    proxies: ["🚀 节点选择", "🎯 全球直连", ' + names.map(n => JSON.stringify(n)).join(', ') + ']\n';
  yaml += '  - name: 📢 谷歌FCM\n    type: select\n    proxies: ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择", ' + names.map(n => JSON.stringify(n)).join(', ') + ']\n';
  yaml += '  - name: 🎯 全球直连\n    type: select\n    proxies: ["DIRECT", "🚀 节点选择", "♻️ 自动选择"]\n';
  yaml += '  - name: 🛑 全球拦截\n    type: select\n    proxies: ["REJECT", "DIRECT"]\n';
  yaml += '  - name: 🍃 应用净化\n    type: select\n    proxies: ["REJECT", "DIRECT"]\n';
  yaml += '  - name: 🐟 漏网之鱼\n    type: select\n    proxies: ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择", ' + names.map(n => JSON.stringify(n)).join(', ') + ']\n\n';
  
  yaml += 'rules:\n' + CLASH_RULES;
  return yaml;
}

function renderSurge(nodes, baseUrl, token) {
  const p = nodes.map(n => n.name + ' = ' + (n.type==='vmess'?'vmess':'trojan') + ', ' + n.server + ', ' + n.port + ', ' + (n.type==='vmess'?'username='+n.uuid:'password='+n.password) + ', ws=true, tls=' + n.tls + ', sni=' + (n.sni||'')).join('\n');
  return '[General]\nskip-proxy = 127.0.0.1, localhost\n\n[Proxy]\n' + p + '\n\n[Proxy Group]\nProxy = select, ' + nodes.map(n => n.name).join(', ') + '\n\n[Rule]\nFINAL,Proxy';
}

function createShortId(len = 10) {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const b = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(b).map(x => c[x % c.length]).join('');
}

async function handleGenerate(req, env, url) {
  try {
    if (!env?.SUB_STORE) {
      return json({ ok: false, error: '未绑定 KV：请在 Cloudflare Workers 里配置 SUB_STORE（KV namespace binding）。' }, 500);
    }
    const body = await req.json();
    const baseNodes = parseRawLinks(body.nodeLinks);
    const eps = parsePreferredEndpoints(body.preferredIps);
    if (!baseNodes.length || !eps.length) return json({ ok: false, error: '没有识别到节点或优选地址' }, 400);
    const nodes = buildNodes(baseNodes, eps, { namePrefix: body.namePrefix, keepOriginalHost: body.keepOriginalHost !== false });
    const id = createShortId();
    await env.SUB_STORE.put('sub:' + id, JSON.stringify({ nodes }));
    const hasAccessToken = Boolean(env.SUB_ACCESS_TOKEN && String(env.SUB_ACCESS_TOKEN).trim());
    const withToken = (t) => {
      const link = new URL(url.origin + '/sub/' + id);
      if (hasAccessToken) link.searchParams.set('token', String(env.SUB_ACCESS_TOKEN).trim());
      if (t) link.searchParams.set('target', t);
      return link.toString();
    };

    return json({
      ok: true,
      urls: {
        auto: withToken(''),
        raw: withToken(''),
        clash: withToken('clash'),
        surge: withToken('surge'),
      },
      counts: {
        inputNodes: baseNodes.length,
        preferredEndpoints: eps.length,
        outputNodes: nodes.length,
      },
      preview: nodes.slice(0, 20).map((node) => ({
        name: node.name,
        type: node.type,
        server: node.server,
        port: node.port,
        host: node.host || '',
        sni: node.sni || '',
      })),
      warnings: [],
    });
  } catch(e) { return json({ ok: false, error: e.message }, 500); }
}

async function handleSub(url, env) {
  const token = url.searchParams.get('token');
  if (env.SUB_ACCESS_TOKEN && token !== env.SUB_ACCESS_TOKEN) return text('Forbidden', 403);
  const id = url.pathname.split('/').pop();
  const raw = await env.SUB_STORE.get('sub:' + id);
  if (!raw) return text('Not Found', 404);
  await env.SUB_STORE.put('sub:' + id, raw); // 自动续命
  const { nodes } = JSON.parse(raw);
  const target = url.searchParams.get('target') || 'raw';
  if (target === 'clash') return text(renderClash(nodes), 200, 'text/yaml');
  if (target === 'surge') return text(renderSurge(nodes), 200, 'text/plain');
  return text(renderRaw(nodes));
}

export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);
      if (req.method === 'OPTIONS') return new Response(null, { headers: { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'content-type' } });
      if (req.method === 'POST' && url.pathname === '/api/generate') return await handleGenerate(req, env, url);
      if (url.pathname.startsWith('/sub/')) return await handleSub(url, env);
      return await env.ASSETS.fetch(req);
    } catch (e) { return json({ ok: false, error: e.message }, 500); }
  }
};
