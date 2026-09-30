import assert from 'node:assert/strict';
import { parse, stringify } from 'yaml';
import worker from '../src/worker.js';
import { assembleProfile, importNodes, parsePreferredIps, parseYamlNodes, renderProfileRaw } from '../src/profile-nodes.js';

const uuid = '00000000-0000-4000-8000-000000000001';
const ips = Array.from({ length: 10 }, (_, i) => `192.0.2.${i + 1}${i === 1 ? ':2053' : ''}#IP-${i + 1}`).join('\n');
const xhttpLink = `vless://${uuid}@origin.example.com:443?type=xhttp&security=tls&path=%2Fxhttp%2F&host=front.example.com&sni=tls.example.com&mode=stream-up&alpn=h2&fp=chrome#XHTTP`;
const wsLink = `vless://${uuid}@ws.example.com:443?type=ws&security=tls&path=%2Fws#WS`;
const realityYaml = {
  name: 'Reality', type: 'vless', server: 'reality.example.com', port: 8443, uuid,
  network: 'tcp', tls: true, udp: true, servername: 'www.apple.com',
  'client-fingerprint': 'chrome', 'skip-cert-verify': false, 'dialer-proxy': 'DIRECT',
  'reality-opts': { 'public-key': 'test-public-key', 'short-id': 'eef01c22', 'support-x25519mlkem768': true },
  flow: 'xtls-rprx-vision',
};
const xhttpYaml = {
  ...realityYaml, name: 'XHTTP YAML', port: 8444, network: 'xhttp', alpn: ['h2'],
  'xhttp-opts': { path: '/xhttp/', host: 'www.apple.com', mode: 'stream-one', 'reuse-settings': { 'max-connections': '1', 'h-keep-alive-period': 30 } },
};
delete xhttpYaml.flow;
const hy2Yaml = { name: 'Hy2', type: 'hysteria2', server: 'hy.example.com', port: 443, password: 'test-pass', sni: 'hy.example.com', 'skip-cert-verify': false };
const source = (format, content, count = null, use = true) => ({ ...importNodes(format, content)[0], usePreferredIps: use, preferredIpCount: count });
const xhttp = source('link', xhttpLink, 5);
const ws = source('link', wsLink, 4);
const yamlSource = source('yaml', stringify(xhttpYaml), null);
const isolated = source('yaml', stringify(hy2Yaml), null, false);
const composition = [xhttp, ws, yamlSource, isolated];
let built = assembleProfile(composition, ips);
assert.equal(built.nodes.length, 6 + 5 + 11 + 1);
assert.deepEqual(built.nodes.slice(0, 6).map(n => n.proxy.name), ['XHTTP-0', 'XHTTP-1', 'XHTTP-2', 'XHTTP-3', 'XHTTP-4', 'XHTTP-5']);
assert.equal(built.nodes[0].proxy.server, 'origin.example.com');
assert.equal(built.nodes[1].proxy.server, '192.0.2.1');
assert.equal(built.nodes[2].proxy.port, 2053);
assert.equal(built.nodes[3].proxy.port, 443);
assert.equal(built.nodes[1].proxy.servername, 'tls.example.com');
assert.deepEqual(built.nodes[1].proxy['xhttp-opts'], { path: '/xhttp/', host: 'front.example.com', mode: 'stream-up' });
assert.equal(built.nodes[7].proxy['ws-opts'].headers.Host, 'ws.example.com');
assert.equal(built.nodes[7].proxy.servername, 'ws.example.com');
assert.equal(built.nodes[6].proxy['ws-opts'].headers, undefined, 'original node is not rewritten for CDN');
const expectedYaml = { ...xhttpYaml, name: 'XHTTP YAML-1', server: '192.0.2.1' };
assert.deepEqual(built.nodes[12].proxy, expectedYaml, 'all YAML options survive expansion');
assert.deepEqual(built.nodes.at(-1).proxy, hy2Yaml, 'disabled node stays unmodified');
assert.equal(composition[0].preferredIpCount, 5, 'inputs are not mutated');

const reordered = ips.split('\n').reverse().join('\n');
assert.equal(assembleProfile([xhttp], reordered).nodes[1].proxy.server, '192.0.2.10');
assert.equal(assembleProfile([xhttp], '192.0.2.99').nodes.length, 2);
assert.equal(assembleProfile([xhttp], '192.0.2.99').warnings.length, 1);
assert.equal(assembleProfile([xhttp], '').nodes.length, 1);
assert.equal(assembleProfile([xhttp], '').warnings.length, 1);
assert.equal(assembleProfile([{ ...xhttp, usePreferredIps: false }], ips).nodes.length, 1);
assert.equal(assembleProfile([{ ...xhttp, usePreferredIps: false }], ips).nodes[0].proxy.name, 'XHTTP');
for (const count of [-1, 0, 1.5, 'wrong', true]) assert.throws(() => assembleProfile([{ ...xhttp, preferredIpCount: count }], ips), /优选数量/);
assert.throws(() => assembleProfile([xhttp, xhttp], ips), /重复/);
assert.throws(() => importNodes('yaml', 'proxies:\n  - name: bad\n    name: duplicate'), /YAML 格式/);
assert.throws(() => importNodes('link', `${wsLink}\nnot-a-link`), /第 2 个/);
assert.equal(importNodes('yaml', stringify({ proxies: [xhttpYaml, hy2Yaml] })).length, 2);
assert.deepEqual(parseYamlNodes("- name: 'single ''quoted'''\n  type: vless\n  server: example.com\n  port: 443")[0].name, "single 'quoted'");
assert.deepEqual(parsePreferredIps('#comment\n\n[2001:db8::1]:8443\n2001:db8::2'), [{ server: '2001:db8::1', port: 8443 }, { server: '2001:db8::2' }]);
assert.throws(() => parsePreferredIps('example.com:nope'), /端口/);
assert.throws(() => parsePreferredIps('example.com:65536'), /端口/);
const rawBuilt = assembleProfile([xhttp, ws], ips).nodes;
const rawLinks = Buffer.from(renderProfileRaw(rawBuilt), 'base64').toString().split('\n');
assert.equal(rawLinks.length, 11);
const preferredUrl = new URL(rawLinks[2]);
assert.equal(preferredUrl.hostname, '192.0.2.2');
assert.equal(preferredUrl.port, '2053');
assert.equal(preferredUrl.searchParams.get('mode'), 'stream-up');
assert.equal(preferredUrl.searchParams.get('host'), 'front.example.com');
assert.equal(preferredUrl.searchParams.get('sni'), 'tls.example.com');
assert.equal(new URL(rawLinks[7]).searchParams.get('host'), 'ws.example.com');
assert.throws(() => renderProfileRaw(built.nodes), /Clash/);
const ipv6 = assembleProfile([xhttp], '[2001:db8::1]:8443').nodes[1];
assert.equal(new URL(ipv6.rawLink).hostname, '[2001:db8::1]');
assert.equal(new URL(ipv6.rawLink).port, '8443');
const hyLink = 'hysteria2://test%3Apass@hy.example.com:443?sni=front.example.com&obfs=salamander&obfs-password=demo#Hy2Link';
const hyNode = assembleProfile([source('link', hyLink, 1)], ips).nodes[1];
assert.equal(hyNode.proxy.password, 'test:pass');
assert.equal(hyNode.proxy.sni, 'front.example.com');
assert.equal(hyNode.proxy['obfs-password'], 'demo');
const extra = encodeURIComponent(JSON.stringify({ xmux: { maxConnections: '1', hKeepAlivePeriod: 30 } }));
assert.deepEqual(assembleProfile([source('link', xhttpLink.replace('#XHTTP', `&extra=${extra}#XHTTP`))], '').nodes[0].proxy['xhttp-opts']['reuse-settings'], { 'max-connections': '1', 'h-keep-alive-period': 30 });

const store = new Map();
const env = { SUB_ACCESS_TOKEN: 'test-admin-token', SUB_STORE: {
  async get(key) { return store.get(key) ?? null; },
  async put(key, value) { store.set(key, value); },
  async delete(key) { store.delete(key); },
} };
async function request(path, method = 'GET', body, auth = true, ua = '') {
  return worker.fetch(new Request(`https://sub.example.com${path}`, {
    method, headers: { 'content-type': 'application/json', ...(auth ? { authorization: 'Bearer test-admin-token' } : {}), 'user-agent': ua },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  }), env);
}
async function data(path, method, body) {
  const response = await request(path, method, body);
  const result = await response.json();
  assert.equal(response.status, 200, JSON.stringify(result));
  return result;
}
async function subscription(subId, target = 'clash', ua = '') {
  return request(`/sub/${subId}?token=test-admin-token${target ? '&target=' + target : ''}`, 'GET', undefined, true, ua);
}

// Migrate a realistic v1 setup: original links, per-user UUID templates, shared Hy2, personal YAML.
store.set('config:global', JSON.stringify({ preferredIps: ips, profileIds: ['awa', 'friend1', 'friend2', 'friend3'], sharedExtraNodesYaml: stringify([hy2Yaml]), extraNodeTemplates: [{ id: 'reality', nameLabel: 'Reality template', server: 'template.example.com', port: 8443, uuidPerUser: true }] }));
for (const id of ['awa', 'friend1', 'friend2', 'friend3']) {
  store.set('profile:' + id, JSON.stringify({ name: id, subscriptionName: id + '-sub', subId: id + '-fixed', wsNodeLink: wsLink, extraUuids: id === 'awa' ? { reality: uuid } : {}, extraNodesYaml: id === 'awa' ? stringify([realityYaml]) : '' }));
  store.set('sub:' + id + '-fixed', JSON.stringify({ profileId: id }));
}
const config = await data('/api/admin/config');
assert.equal(config.config.schemaVersion, 2);
assert.equal(config.config.sharedExtraNodesYaml, undefined);
assert.equal(config.config.extraNodeTemplates, undefined);
assert.ok(store.has('backup:v1:config:global'));
const migrated = (await data('/api/admin/profiles')).profiles;
assert.equal(migrated.find(p => p.id === 'awa').nodeSources.length, 4);
assert.equal(migrated.find(p => p.id === 'friend1').nodeSources.length, 2);
assert.equal(migrated.find(p => p.id === 'awa').subId, 'awa-fixed');
assert.equal(migrated.find(p => p.id === 'awa').wsNodeLink, undefined);
const snapshot = JSON.stringify([...store]);
await data('/api/admin/config');
assert.equal(JSON.stringify([...store]), snapshot, 'migration is idempotent');
const friendBefore = new Map(await Promise.all(['friend1', 'friend2', 'friend3'].map(async id => [id, await (await subscription(id + '-fixed')).text()])));

const saved = await data('/api/admin/profiles', 'POST', { id: 'awa', subscriptionName: 'awa-sub', nodeSources: composition });
assert.equal(saved.profile.subId, 'awa-fixed');
assert.match(saved.urls.clash, /target=clash/);
const response = await subscription('awa-fixed');
assert.equal(response.status, 200);
assert.match(response.headers.get('content-disposition'), /awa-sub/);
const yaml = parse(await response.text());
assert.equal(yaml.proxies.length, 23);
assert.deepEqual(yaml.proxies[12], expectedYaml);
for (const group of yaml['proxy-groups'].slice(0, 2)) for (const node of yaml.proxies) assert.ok(group.proxies.includes(node.name));
for (const id of ['friend1', 'friend2', 'friend3']) assert.equal(await (await subscription(id + '-fixed')).text(), friendBefore.get(id), 'other subscriptions remain isolated');
const autoResponse = await subscription('awa-fixed', '', 'Clash.Meta');
assert.match(autoResponse.headers.get('content-type'), /yaml/);
assert.equal((await subscription('awa-fixed', 'raw')).status, 400);
assert.equal((await subscription('awa-fixed', 'surge')).status, 400);
const preview = await data('/api/admin/preview', 'POST', { nodeSources: composition });
assert.equal(preview.nodes.length, 23);
assert.ok(preview.nodes.every(n => !('uuid' in n) && !('password' in n)));
const beforeInvalidSave = store.get('profile:awa');
assert.equal((await request('/api/admin/profiles', 'POST', { id: 'awa', nodeSources: [{ ...xhttp, preferredIpCount: -1 }] })).status, 400);
assert.equal(store.get('profile:awa'), beforeInvalidSave);
assert.equal((await request('/api/admin/import', 'POST', { format: 'link', content: wsLink }, false)).status, 403);
assert.equal((await request('/api/admin/profiles', 'POST', { id: 'awa', nodeSources: [] }, false)).status, 403);
assert.equal((await request('/sub/awa-fixed?target=clash', 'GET', undefined, false)).status, 403);

await data('/api/admin/config', 'PUT', { preferredIps: reordered, profileIds: [] });
assert.equal(JSON.parse(store.get('config:global')).profileIds.length, 4, 'global writes preserve profile index');
const refreshed = parse(await (await subscription('awa-fixed')).text());
assert.equal(refreshed.proxies[1].server, '192.0.2.10');
assert.equal(refreshed.proxies.length, 23);
const newProfile = await data('/api/admin/profiles', 'POST', { id: 'new-user', nodeSources: [ws] });
assert.equal(newProfile.profile.nodeSources.length, 1, 'new users never inherit shared Hy2');
const newRaw = await subscription(newProfile.profile.subId, 'raw');
assert.equal(newRaw.status, 200);
assert.equal(Buffer.from(await newRaw.text(), 'base64').toString().split('\n').length, 5);
await data('/api/admin/profiles', 'POST', { id: 'awa', name: 'Awa updated' });
assert.equal(JSON.parse(store.get('profile:awa')).nodeSources.length, 4, 'partial updates preserve sources');
await data('/api/admin/profiles', 'POST', { id: 'awa', nodeSources: [] });
const empty = parse(await (await subscription('awa-fixed')).text());
assert.deepEqual(empty.proxies, []);
assert.deepEqual(empty['proxy-groups'][1].proxies, ['DIRECT']);
await data('/api/admin/profiles/new-user', 'DELETE');
assert.equal((await subscription(newProfile.profile.subId)).status, 404);

// Old static links stay readable.
store.set('sub:old-static', JSON.stringify({ nodes: [{ type: 'vless', name: 'Old static', uuid, server: 'old.example.com', port: 443, network: 'ws', tls: true }] }));
assert.equal(parse(await (await subscription('old-static')).text()).proxies[0].name, 'Old static');

// Invalid legacy input must not partially migrate or erase existing records.
store.clear();
store.set('config:global', JSON.stringify({ preferredIps: ips, profileIds: ['legacy1', 'legacy2'], sharedExtraNodesYaml: stringify([hy2Yaml]) }));
store.set('profile:legacy1', JSON.stringify({ subId: 'legacy1-link', wsNodeLink: wsLink }));
store.set('profile:legacy2', JSON.stringify({ subId: 'legacy2-link', extraNodesYaml: 'proxies: [broken' }));
const beforeFailedMigration = JSON.stringify([...store]);
assert.equal((await request('/api/admin/config')).status, 400);
assert.equal(JSON.stringify([...store]), beforeFailedMigration);
console.log('profile tests passed: mixed sources, ordered counts, protocol preservation, isolation, migration, validation, raw links, static compatibility');
