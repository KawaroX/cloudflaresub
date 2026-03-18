
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

function stripControlChars(value, { keepNewlines = false } = {}) {
  const text = String(value ?? '');
  const withoutC0 = text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  if (keepNewlines) {
    return withoutC0.replace(/\r\n?/g, '\n').replace(/\t/g, '  ');
  }
  return withoutC0.replace(/[\r\n\t]+/g, ' ');
}

function sanitizeLabel(value) {
  return stripControlChars(value).trim();
}

function yamlQuote(value) {
  const text = stripControlChars(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').trim();
  return `"${text}"`;
}

function codeToFlagEmoji(code) {
  const normalized = String(code || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(normalized)) return '';
  const base = 0x1f1e6;
  const chars = [...normalized].map((ch) => String.fromCodePoint(base + ch.charCodeAt(0) - 65));
  return chars.join('');
}

function detectCountryCodeFromName(name) {
  const raw = String(name || '');
  const upper = raw.toUpperCase();

  const tests = [
    { code: 'CN', target: 'upper', re: /(^|[^A-Z])CN(H)?([^A-Z]|$)/ },
    { code: 'CN', target: 'raw', re: /CHINA/i },
    { code: 'CN', target: 'raw', re: /(中国|中國|大陆|大陸)/ },
    { code: 'HK', target: 'upper', re: /(^|[^A-Z])HK(G)?([^A-Z]|$)/ },
    { code: 'HK', target: 'raw', re: /香港/ },
    { code: 'TW', target: 'upper', re: /(^|[^A-Z])TW(N)?([^A-Z]|$)/ },
    { code: 'TW', target: 'raw', re: /(台湾|台灣)/ },
    { code: 'SG', target: 'upper', re: /(^|[^A-Z])SG(P)?([^A-Z]|$)/ },
    { code: 'SG', target: 'raw', re: /新加坡/ },
    { code: 'JP', target: 'upper', re: /(^|[^A-Z])JP(N)?([^A-Z]|$)/ },
    { code: 'JP', target: 'raw', re: /日本/ },
    { code: 'KR', target: 'upper', re: /(^|[^A-Z])KR([^A-Z]|$)/ },
    { code: 'KR', target: 'raw', re: /(韩国|韓國)/ },
    { code: 'KR', target: 'raw', re: /KOREA/i },
    { code: 'US', target: 'upper', re: /(^|[^A-Z])USA([^A-Z]|$)/ },
    { code: 'US', target: 'upper', re: /(^|[^A-Z])US([^A-Z]|$)/ },
    { code: 'US', target: 'raw', re: /(UNITED STATES|AMERICA)/i },
    { code: 'US', target: 'raw', re: /(美国|美國)/ },
    { code: 'GB', target: 'upper', re: /(^|[^A-Z])(UK|GB|GBR)([^A-Z]|$)/ },
    { code: 'GB', target: 'raw', re: /(UNITED KINGDOM|ENGLAND)/i },
    { code: 'GB', target: 'raw', re: /(英国|英國)/ },
    { code: 'DE', target: 'upper', re: /(^|[^A-Z])(DE|GER)([^A-Z]|$)/ },
    { code: 'DE', target: 'raw', re: /(GERMANY|DEUTSCHLAND)/i },
    { code: 'DE', target: 'raw', re: /德国/ },
    { code: 'FR', target: 'upper', re: /(^|[^A-Z])(FR|FRA)([^A-Z]|$)/ },
    { code: 'FR', target: 'raw', re: /FRANCE/i },
    { code: 'FR', target: 'raw', re: /法国/ },
    { code: 'CA', target: 'upper', re: /(^|[^A-Z])CA([^A-Z]|$)/ },
    { code: 'CA', target: 'raw', re: /CANADA/i },
    { code: 'CA', target: 'raw', re: /加拿大/ },
    { code: 'AU', target: 'upper', re: /(^|[^A-Z])AUS([^A-Z]|$)/ },
    { code: 'AU', target: 'upper', re: /(^|[^A-Z])AU([^A-Z]|$)/ },
    { code: 'AU', target: 'raw', re: /AUSTRALIA/i },
    { code: 'AU', target: 'raw', re: /(澳大利亚|澳洲)/ },
    { code: 'RU', target: 'upper', re: /(^|[^A-Z])RU(S)?([^A-Z]|$)/ },
    { code: 'RU', target: 'raw', re: /(RUSSIA|RUSSIAN)/i },
    { code: 'RU', target: 'raw', re: /俄罗斯/ },
    { code: 'IN', target: 'upper', re: /(^|[^A-Z])IN(D)?([^A-Z]|$)/ },
    { code: 'IN', target: 'raw', re: /INDIA/i },
    { code: 'IN', target: 'raw', re: /印度/ },
    { code: 'BR', target: 'upper', re: /(^|[^A-Z])BR([^A-Z]|$)/ },
    { code: 'BR', target: 'raw', re: /BRAZIL/i },
    { code: 'BR', target: 'raw', re: /巴西/ },
    { code: 'NL', target: 'upper', re: /(^|[^A-Z])NL(D)?([^A-Z]|$)/ },
    { code: 'NL', target: 'raw', re: /NETHERLANDS/i },
    { code: 'NL', target: 'raw', re: /荷兰/ },
    { code: 'IT', target: 'upper', re: /(^|[^A-Z])IT([^A-Z]|$)/ },
    { code: 'IT', target: 'raw', re: /ITALY/i },
    { code: 'IT', target: 'raw', re: /意大利/ },
    { code: 'ES', target: 'upper', re: /(^|[^A-Z])ES([^A-Z]|$)/ },
    { code: 'ES', target: 'raw', re: /SPAIN/i },
    { code: 'ES', target: 'raw', re: /西班牙/ },
    { code: 'TR', target: 'upper', re: /(^|[^A-Z])TR([^A-Z]|$)/ },
    { code: 'TR', target: 'raw', re: /TURKEY/i },
    { code: 'TR', target: 'raw', re: /土耳其/ },
    { code: 'VN', target: 'upper', re: /(^|[^A-Z])VN([^A-Z]|$)/ },
    { code: 'VN', target: 'raw', re: /VIETNAM/i },
    { code: 'VN', target: 'raw', re: /越南/ },
    { code: 'TH', target: 'upper', re: /(^|[^A-Z])TH([^A-Z]|$)/ },
    { code: 'TH', target: 'raw', re: /THAILAND/i },
    { code: 'TH', target: 'raw', re: /泰国/ },
    { code: 'MY', target: 'upper', re: /(^|[^A-Z])MY([^A-Z]|$)/ },
    { code: 'MY', target: 'raw', re: /MALAYSIA/i },
    { code: 'MY', target: 'raw', re: /马来西亚/ },
    { code: 'ID', target: 'upper', re: /(^|[^A-Z])ID([^A-Z]|$)/ },
    { code: 'ID', target: 'raw', re: /INDONESIA/i },
    { code: 'ID', target: 'raw', re: /(印尼|印度尼西亚|印度尼西亞)/ },
    { code: 'PH', target: 'upper', re: /(^|[^A-Z])PH([^A-Z]|$)/ },
    { code: 'PH', target: 'raw', re: /PHILIPPINES/i },
    { code: 'PH', target: 'raw', re: /菲律宾/ },
  ];

  let bestIndex = Number.POSITIVE_INFINITY;
  let bestCode = '';
  for (const test of tests) {
    const target = test.target === 'upper' ? upper : raw;
    const match = target.match(test.re);
    if (!match) continue;
    const index = match.index ?? Number.POSITIVE_INFINITY;
    if (index < bestIndex) {
      bestIndex = index;
      bestCode = test.code;
    }
  }
  return bestCode;
}

function maybeAddFlagEmojiToName(name) {
  const clean = sanitizeLabel(name);
  if (!clean) return clean;
  if (/[\u{1F1E6}-\u{1F1FF}]{2}/u.test(clean)) return clean;
  const code = detectCountryCodeFromName(clean);
  if (!code) return clean;
  const flagCode = code === 'TW' ? 'CN' : code;
  const flag = codeToFlagEmoji(flagCode);
  return flag ? `${flag} ${clean}` : clean;
}

function parsePreferredEndpoints(input) {
  return String(input || '').split('\n').map(l => l.trim()).filter(Boolean).map(line => {
    const forceReplace = line.endsWith('#');
    const parts = line.split('#').filter((p, i) => i < 2 || (i === 2 && p === ''));
    const raw = parts[0] || '';
    const remark = parts[1] || '';
    const match = raw.trim().match(/^(.*?)(?::(\d+))?$/);
    return {
      server: sanitizeLabel(match?.[1] || raw.trim()),
      port: match?.[2] ? Number(match[2]) : undefined,
      remark: sanitizeLabel(remark),
      forceReplace,
    };
  });
}

function parseVmess(link) {
  const obj = JSON.parse(b64DecodeUtf8(link.slice(8)));
  return {
    type: 'vmess',
    name: sanitizeLabel(obj.ps || 'vmess'),
    server: sanitizeLabel(obj.add),
    port: Number(obj.port),
    uuid: sanitizeLabel(obj.id),
    cipher: sanitizeLabel(obj.scy || 'auto'),
    network: sanitizeLabel(obj.net || 'ws'),
    tls: obj.tls === 'tls',
    host: sanitizeLabel(obj.host || ''),
    path: sanitizeLabel(obj.path || '/') || '/',
    sni: sanitizeLabel(obj.sni || obj.host || ''),
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  const name = sanitizeLabel(decodeURIComponent(u.hash.replace(/^#/, '')) || type);
  const server = sanitizeLabel(u.hostname);
  const port = Number(u.port || 443);
  const network = sanitizeLabel(u.searchParams.get('type') || 'tcp');
  const tls = sanitizeLabel(u.searchParams.get('security') || '').toLowerCase() === 'tls';
  const host = sanitizeLabel(u.searchParams.get('host') || u.searchParams.get('sni') || '');
  const path = sanitizeLabel(u.searchParams.get('path') || '/') || '/';
  const sni = sanitizeLabel(u.searchParams.get('sni') || u.searchParams.get('host') || '');
  return {
    type,
    name,
    server,
    port,
    password: type === 'trojan' ? sanitizeLabel(decodeURIComponent(u.username)) : undefined,
    uuid: type === 'vless' ? sanitizeLabel(decodeURIComponent(u.username)) : undefined,
    network,
    tls,
    host,
    path,
    sni,
  };
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
      let name = ep.forceReplace && ep.remark
        ? ep.remark
        : [node.name, sanitizeLabel(options.namePrefix), ep.remark || String(counter)].filter(Boolean).join(' | ');

      name = sanitizeLabel(name);
      if (options.addFlagEmoji) {
        name = maybeAddFlagEmojiToName(name);
      }

      const keepOriginalHost = options.keepOriginalHost !== false;
      output.push({
        ...node,
        name,
        server: ep.server,
        port: ep.port || node.port,
        host: keepOriginalHost ? sanitizeLabel(node.host) : '',
        sni: keepOriginalHost ? sanitizeLabel(node.sni) : '',
        path: sanitizeLabel(node.path || '/') || '/',
        network: sanitizeLabel(node.network || 'ws') || 'ws',
      });
    }
  }
  return output;
}

function encodeVmess(n) { return 'vmess://' + b64EncodeUtf8(JSON.stringify({ v: '2', ps: n.name, add: n.server, port: String(n.port), id: n.uuid, aid: '0', scy: n.cipher || 'auto', net: n.network || 'ws', type: 'none', host: n.host || '', path: n.path || '/', tls: n.tls ? 'tls' : '', sni: n.sni || '' })); }
function encodeVless(n) { const u = new URL('vless://' + n.uuid + '@' + n.server + ':' + n.port); u.searchParams.set('type', n.network || 'ws'); if (n.tls) u.searchParams.set('security', 'tls'); if (n.host) u.searchParams.set('host', n.host); if (n.path) u.searchParams.set('path', n.path); u.hash = n.name; return u.toString(); }
function encodeTrojan(n) { const u = new URL('trojan://' + n.password + '@' + n.server + ':' + n.port); u.searchParams.set('type', n.network || 'ws'); if (n.tls) u.searchParams.set('security', 'tls'); if (n.host) u.searchParams.set('host', n.host); u.hash = n.name; return u.toString(); }

function renderRaw(nodes) { return b64EncodeUtf8(nodes.map(n => n.type==='vmess'?encodeVmess(n):n.type==='vless'?encodeVless(n):encodeTrojan(n)).filter(Boolean).join('\n')); }

function sanitizeForYamlValue(value) {
  return stripControlChars(value).trim();
}

function renderClashProxyYaml(node) {
  const lines = [];
  lines.push(`  - name: ${yamlQuote(sanitizeForYamlValue(node.name))}`);
  lines.push(`    type: ${sanitizeForYamlValue(node.type)}`);
  lines.push(`    server: ${yamlQuote(sanitizeForYamlValue(node.server))}`);
  lines.push(`    port: ${Number(node.port) || 443}`);
  lines.push('    udp: true');
  lines.push('    skip-cert-verify: true');

  if (node.type === 'vmess') {
    lines.push(`    uuid: ${yamlQuote(sanitizeForYamlValue(node.uuid))}`);
    lines.push('    alterId: 0');
    lines.push(`    cipher: ${yamlQuote(sanitizeForYamlValue(node.cipher || 'auto'))}`);
  } else if (node.type === 'vless') {
    lines.push(`    uuid: ${yamlQuote(sanitizeForYamlValue(node.uuid))}`);
  } else if (node.type === 'trojan') {
    lines.push(`    password: ${yamlQuote(sanitizeForYamlValue(node.password))}`);
  }

  if (node.tls) {
    lines.push('    tls: true');
    const servername = sanitizeForYamlValue(node.sni || '');
    if (servername) {
      lines.push(`    servername: ${yamlQuote(servername)}`);
    }
  } else {
    lines.push('    tls: false');
  }

  const network = sanitizeForYamlValue(node.network || 'ws') || 'ws';
  lines.push(`    network: ${network}`);

  if (network === 'ws') {
    lines.push('    ws-opts:');
    lines.push(`      path: ${yamlQuote(sanitizeForYamlValue(node.path || '/'))}`);
    const host = sanitizeForYamlValue(node.host || '');
    if (host) {
      lines.push('      headers:');
      lines.push(`        Host: ${yamlQuote(host)}`);
    }
  }

  return lines;
}

function renderClash(nodes) {
  const CLASH_RULES = stripControlChars(atob(CLASH_RULES_B64), { keepNewlines: true });
  const safeNodes = Array.isArray(nodes) ? nodes : [];
  const names = safeNodes.map((n) => sanitizeForYamlValue(n.name)).filter(Boolean);

  const yamlArray = (values) => `[${values.map((v) => yamlQuote(v)).join(', ')}]`;

  const lines = [];
  lines.push('mixed-port: 7890');
  lines.push('allow-lan: false');
  lines.push('mode: rule');
  lines.push('log-level: warning');
  lines.push('unified-delay: true');
  lines.push('global-client-fingerprint: chrome');
  lines.push('');
  lines.push('proxies:');
  safeNodes.forEach((node) => {
    lines.push(...renderClashProxyYaml(node));
  });
  lines.push('');
  lines.push('proxy-groups:');
  lines.push(`  - name: ${yamlQuote('🚀 节点选择')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['♻️ 自动选择', 'DIRECT', ...names])}`);
  lines.push(`  - name: ${yamlQuote('♻️ 自动选择')}`);
  lines.push('    type: url-test');
  lines.push(`    url: ${yamlQuote('http://www.gstatic.com/generate_204')}`);
  lines.push('    interval: 300');
  lines.push('    tolerance: 50');
  lines.push(`    proxies: ${yamlArray(names)}`);
  lines.push(`  - name: ${yamlQuote('🌍 国外媒体')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['🚀 节点选择', '♻️ 自动选择', '🎯 全球直连', ...names])}`);
  lines.push(`  - name: ${yamlQuote('📲 电报信息')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['🚀 节点选择', '🎯 全球直连', ...names])}`);
  lines.push(`  - name: ${yamlQuote('Ⓜ️ 微软服务')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['🎯 全球直连', '🚀 节点选择', ...names])}`);
  lines.push(`  - name: ${yamlQuote('🍎 苹果服务')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['🚀 节点选择', '🎯 全球直连', ...names])}`);
  lines.push(`  - name: ${yamlQuote('📢 谷歌FCM')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['🚀 节点选择', '🎯 全球直连', '♻️ 自动选择', ...names])}`);
  lines.push(`  - name: ${yamlQuote('🎯 全球直连')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['DIRECT', '🚀 节点选择', '♻️ 自动选择'])}`);
  lines.push(`  - name: ${yamlQuote('🛑 全球拦截')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['REJECT', 'DIRECT'])}`);
  lines.push(`  - name: ${yamlQuote('🍃 应用净化')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['REJECT', 'DIRECT'])}`);
  lines.push(`  - name: ${yamlQuote('🐟 漏网之鱼')}`);
  lines.push('    type: select');
  lines.push(`    proxies: ${yamlArray(['🚀 节点选择', '🎯 全球直连', '♻️ 自动选择', ...names])}`);
  lines.push('');
  lines.push('rules:');
  lines.push(CLASH_RULES.trimEnd());
  lines.push('');

  return lines.join('\n');
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
    const nodes = buildNodes(baseNodes, eps, {
      namePrefix: body.namePrefix,
      keepOriginalHost: body.keepOriginalHost !== false,
      addFlagEmoji: body.addFlagEmoji === true,
    });
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
