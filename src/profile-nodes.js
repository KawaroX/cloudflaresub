import { parseDocument, stringify } from 'yaml';
import { parseNodeLinks } from './core.js';

export class ConfigError extends Error {
  constructor(message) { super(message); this.status = 400; }
}
const fail = message => { throw new ConfigError(message); };
const clone = value => structuredClone(value);
const encode64 = text => btoa(unescape(encodeURIComponent(text)));
const decode64 = text => decodeURIComponent(escape(atob(text.replaceAll('-', '+').replaceAll('_', '/'))));
const cleanHost = host => host.replace(/^\[|\]$/g, '');
const urlHost = host => host.includes(':') ? `[${cleanHost(host)}]` : host;
const boolean = value => ['true', '1'].includes(String(value).toLowerCase());
const reservedNames = new Set(['DIRECT', 'REJECT', '🚀 节点选择', '♻️ 自动选择', '🌍 国外媒体', '📲 电报信息', 'Ⓜ️ 微软服务', '🍎 苹果服务', '📢 谷歌FCM', '🎯 全球直连', '🛑 全球拦截', '🍃 应用净化', '🐟 漏网之鱼']);

export function parsePreferredIps(input = '') {
  if (typeof input !== 'string') fail('优选 IP 列表必须是文本');
  return input.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#')).map((line, index) => {
    const address = line.split('#')[0].trim();
    let server = address, port;
    if (address.startsWith('[')) {
      const match = address.match(/^\[([^\]]+)\](?::(\d+))?$/);
      if (!match) fail(`第 ${index + 1} 个优选地址格式错误`);
      server = match[1]; port = match[2];
    } else if ((address.match(/:/g) || []).length === 1) {
      [server, port] = address.split(':');
      if (!/^\d+$/.test(port)) fail(`第 ${index + 1} 个优选地址端口错误`);
    }
    if (!server || /[\s/?@#]/.test(server)) fail(`第 ${index + 1} 个优选地址格式错误`);
    try { new URL(`https://${urlHost(server)}`); } catch { fail(`第 ${index + 1} 个优选地址格式错误`); }
    if (port !== undefined && (!Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535)) fail(`第 ${index + 1} 个优选地址端口错误`);
    return { server, ...(port !== undefined ? { port: Number(port) } : {}) };
  });
}

function validateProxy(proxy) {
  if (!proxy || typeof proxy !== 'object' || Array.isArray(proxy)) fail('YAML 中的每个节点必须是对象');
  for (const key of ['name', 'type', 'server']) {
    if (typeof proxy[key] !== 'string' || !proxy[key].trim() || /[\x00-\x1f\x7f]/.test(proxy[key])) fail(`节点缺少有效的 ${key}`);
  }
  proxy.name = proxy.name.trim();
  if (reservedNames.has(proxy.name)) fail(`节点名称「${proxy.name}」与策略组重名，请改名`);
  if (typeof proxy.port !== 'number' && typeof proxy.port !== 'string') fail('节点端口必须是 1–65535 的整数');
  if (!Number.isInteger(Number(proxy.port)) || Number(proxy.port) < 1 || Number(proxy.port) > 65535) fail('节点端口必须是 1–65535 的整数');
  proxy.port = Number(proxy.port);
  return proxy;
}

export function parseYamlNodes(content) {
  if (typeof content !== 'string' || !content.trim()) fail('请粘贴节点 YAML');
  let value;
  try {
    const document = parseDocument(content, { uniqueKeys: true, prettyErrors: false });
    if (document.errors.length || document.warnings.length) fail('YAML 格式错误，请检查缩进、重复字段和标签');
    value = document.toJS({ maxAliasCount: 50 });
  } catch { fail('YAML 格式错误，请检查缩进、重复字段和标签'); }
  const nodes = Array.isArray(value) ? value : Array.isArray(value?.proxies) ? value.proxies : [value];
  if (!nodes.length) fail('YAML 中没有节点');
  // JSON copy rejects recursive YAML aliases and normalizes plain data.
  try { value = JSON.parse(JSON.stringify(nodes)); } catch { fail('节点 YAML 不能包含循环引用'); }
  return value.map(validateProxy);
}

function linkToProxy(link) {
  if (/^(hy2|hysteria2):\/\//i.test(link)) {
    const u = new URL(link), p = u.searchParams;
    const proxy = {
      name: decodeURIComponent(u.hash.slice(1)) || 'Hysteria2', type: 'hysteria2',
      server: cleanHost(u.hostname), port: Number(u.port || 443),
      password: decodeURIComponent(u.username + (u.password ? ':' + u.password : '')),
      sni: p.get('sni') || cleanHost(u.hostname), 'skip-cert-verify': boolean(p.get('insecure')), udp: true,
    };
    if (!proxy.password) fail('Hysteria2 链接缺少密码');
    for (const key of ['obfs', 'obfs-password']) if (p.has(key)) proxy[key] = p.get(key);
    if (p.has('pinSHA256')) proxy.fingerprint = p.get('pinSHA256');
    return validateProxy(proxy);
  }
  const { nodes, warnings } = parseNodeLinks(link);
  if (warnings.length || nodes.length !== 1) fail('节点链接解析失败');
  const n = nodes[0], p = n.params || {};
  const proxy = {
    name: n.name, type: n.type, server: cleanHost(n.server), port: n.port,
    network: n.network, tls: n.tls, udp: true, 'skip-cert-verify': n.allowInsecure === true,
  };
  if (n.type === 'trojan') proxy.password = n.password;
  else proxy.uuid = n.uuid;
  if (n.type === 'vmess') { proxy.alterId = n.alterId; proxy.cipher = n.cipher; }
  if (n.sni) proxy.servername = n.sni;
  if (n.fp) proxy['client-fingerprint'] = n.fp;
  if (n.alpn?.length) proxy.alpn = n.alpn;
  if (n.flow) proxy.flow = n.flow;
  if (n.security === 'reality') {
    proxy['reality-opts'] = { 'public-key': p.pbk || '', 'short-id': p.sid || '' };
    if (p['support-x25519mlkem768'] !== undefined) proxy['reality-opts']['support-x25519mlkem768'] = boolean(p['support-x25519mlkem768']);
  }
  if (n.network === 'ws') proxy['ws-opts'] = { path: n.path || '/', ...(n.hostHeader ? { headers: { Host: n.hostHeader } } : {}) };
  if (n.network === 'grpc') proxy['grpc-opts'] = { 'grpc-service-name': n.serviceName || '' };
  if (['http', 'h2'].includes(n.network)) proxy['http-opts'] = { path: [n.path || '/'], ...(n.hostHeader ? { headers: { Host: [n.hostHeader] } } : {}) };
  if (['xhttp', 'splithttp'].includes(n.network)) {
    proxy.network = 'xhttp';
    proxy['xhttp-opts'] = { path: n.path || '/', ...(n.hostHeader ? { host: n.hostHeader } : {}), mode: p.mode || 'auto' };
    if (p.extra) {
      let extra;
      try { extra = JSON.parse(p.extra); } catch { fail('XHTTP extra 必须是有效 JSON'); }
      if (!extra || typeof extra !== 'object' || Array.isArray(extra)) fail('XHTTP extra 必须是对象');
      // Only translate parameters with a known Clash equivalent; never silently lose advanced options.
      if (Object.keys(extra).some(key => key !== 'xmux')) fail('此 XHTTP 链接含未支持的 extra 参数，请使用完整 Clash YAML 导入');
      if (extra.xmux) {
        const keys = { maxConnections: 'max-connections', maxConcurrency: 'max-concurrency', cMaxReuseTimes: 'c-max-reuse-times', hMaxRequestTimes: 'h-max-request-times', hMaxReusableSecs: 'h-max-reusable-secs', hKeepAlivePeriod: 'h-keep-alive-period' };
        const reuse = {};
        for (const [key, value] of Object.entries(extra.xmux)) {
          if (!keys[key]) fail('此 XHTTP 链接含未支持的复用参数，请使用 Clash YAML 导入');
          reuse[keys[key]] = value;
        }
        proxy['xhttp-opts']['reuse-settings'] = reuse;
      }
    }
  } else if (!['tcp', 'ws', 'grpc', 'http', 'h2'].includes(n.network)) {
    fail(`暂不支持从链接转换 ${n.network}，请使用 Clash YAML 导入`);
  }
  return validateProxy(proxy);
}

export function importNodes(format, content) {
  if (typeof content !== 'string' || !content.trim()) fail('请先输入节点内容');
  if (content.length > 500000) fail('一次导入内容不能超过 500 KB');
  if (format === 'yaml') return parseYamlNodes(content).map(proxy => ({ format: 'yaml', content: stringify(proxy), usePreferredIps: false, preferredIpCount: null }));
  if (format !== 'link') fail('请选择链接或 YAML 格式');
  const links = content.trim().split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  return links.map((link, index) => {
    try { linkToProxy(link); } catch (error) {
      if (error instanceof ConfigError) fail(`第 ${index + 1} 个节点：${error.message}`);
      fail(`第 ${index + 1} 个节点链接无效，支持 VLESS、VMess、Trojan、Hysteria2`);
    }
    return { format: 'link', content: link, usePreferredIps: false, preferredIpCount: null };
  });
}

export function normalizeSources(sources) {
  if (!Array.isArray(sources) || sources.length > 500) fail('节点列表必须是数组，最多 500 个节点');
  return sources.map((source, index) => {
    if (!source || typeof source !== 'object') fail(`第 ${index + 1} 个节点配置错误`);
    const imported = importNodes(source.format, source.content);
    if (imported.length !== 1) fail(`第 ${index + 1} 个编辑框只能配置一个节点，多个节点请使用批量导入`);
    let count = source.preferredIpCount;
    if (count === '' || count === null || count === undefined || count === 'all') count = null;
    else {
      if (!['number', 'string'].includes(typeof count)) fail(`第 ${index + 1} 个节点的优选数量必须是正整数或全部`);
      count = Number(count);
      if (!Number.isSafeInteger(count) || count < 1) fail(`第 ${index + 1} 个节点的优选数量必须是正整数或全部`);
    }
    return { ...imported[0], usePreferredIps: source.usePreferredIps === true, preferredIpCount: count };
  });
}

function preferredVersion(proxy, endpoint, name) {
  const result = clone(proxy);
  // Preserve effective handshake targets even when the input relied on the original server as its default.
  if (result.tls || ['trojan', 'hysteria2', 'tuic'].includes(result.type)) {
    const key = ['hysteria2', 'tuic'].includes(result.type) ? 'sni' : 'servername';
    result[key] ||= result['xhttp-opts']?.host || result['ws-opts']?.headers?.Host || result.server;
  }
  if (result.network === 'ws') {
    result['ws-opts'] ||= {};
    result['ws-opts'].headers ||= {};
    result['ws-opts'].headers.Host ||= result.server;
  }
  if (result.network === 'xhttp') {
    result['xhttp-opts'] ||= {};
    result['xhttp-opts'].host ||= result.server;
  }
  if (['http', 'h2'].includes(result.network)) {
    result['http-opts'] ||= {};
    result['http-opts'].headers ||= {};
    result['http-opts'].headers.Host ||= [result.server];
  }
  result.name = name;
  result.server = endpoint.server;
  if (endpoint.port !== undefined) result.port = endpoint.port;
  return result;
}

function rewriteLink(link, proxy) {
  if (link.startsWith('vmess://')) {
    const data = JSON.parse(decode64(link.slice(8)));
    Object.assign(data, { ps: proxy.name, add: proxy.server, port: String(proxy.port) });
    if (proxy.servername) data.sni = proxy.servername;
    if (proxy['ws-opts']?.headers?.Host) data.host = proxy['ws-opts'].headers.Host;
    return 'vmess://' + encode64(JSON.stringify(data));
  }
  const url = new URL(link);
  url.hostname = urlHost(proxy.server); url.port = String(proxy.port); url.hash = proxy.name;
  if (proxy.servername || proxy.sni) url.searchParams.set('sni', proxy.servername || proxy.sni);
  const host = proxy['xhttp-opts']?.host || proxy['ws-opts']?.headers?.Host;
  if (host) url.searchParams.set('host', host);
  return url.toString();
}

export function assembleProfile(sources, preferredIps = '') {
  const endpoints = parsePreferredIps(preferredIps);
  const normalized = normalizeSources(sources);
  const output = [], names = new Set(), warnings = [];
  for (const [index, source] of normalized.entries()) {
    const proxy = source.format === 'yaml' ? parseYamlNodes(source.content)[0] : linkToProxy(source.content);
    const variants = [clone(proxy)];
    if (source.usePreferredIps) {
      variants[0].name = `${proxy.name}-0`;
      const selected = endpoints.slice(0, source.preferredIpCount ?? endpoints.length);
      selected.forEach((endpoint, i) => variants.push(preferredVersion(proxy, endpoint, `${proxy.name}-${i + 1}`)));
      if (!selected.length) warnings.push(`「${proxy.name}」已开启优选，但公共列表为空，当前只生成原始节点`);
      else if (source.preferredIpCount > endpoints.length) warnings.push(`「${proxy.name}」设置前 ${source.preferredIpCount} 个，公共列表只有 ${endpoints.length} 个，已使用全部可用 IP`);
    }
    for (const variant of variants) {
      if (names.has(variant.name)) fail(`生成的节点名称「${variant.name}」重复，请修改节点名称`);
      names.add(variant.name);
      output.push({ proxy: variant, sourceIndex: index, rawLink: source.format === 'link' ? rewriteLink(source.content, variant) : null });
      if (output.length > 10000) fail('生成节点超过 10000 个，请减少优选数量或节点数量');
    }
  }
  return { nodes: output, warnings, sources: normalized, preferredIpCount: endpoints.length };
}

export function renderProfileRaw(nodes) {
  if (nodes.some(node => !node.rawLink)) fail('此订阅包含 YAML 节点，请使用 Clash 订阅以保留完整参数');
  return encode64(nodes.map(node => node.rawLink).join('\n'));
}

export function yamlProxyList(nodes) {
  return stringify(nodes, { lineWidth: 0, aliasDuplicateObjects: false }).trimEnd().split('\n').map(line => '  ' + line).join('\n');
}
