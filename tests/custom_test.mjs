
import { parsePreferredEndpoints, buildNodes, renderClash } from '../src/worker.js';
import fs from 'fs';

// 模拟节点数据
const baseNodes = [
  {
    type: 'vmess',
    name: 'Original Node',
    server: '1.1.1.1',
    port: 443,
    uuid: 'test-uuid',
    tls: true,
    network: 'ws',
    path: '/',
    host: 'example.com'
  }
];

async function runTest() {
  console.log('--- 开始深度功能测试 ---');

  // 1. 测试“强制替换名称”功能 (#后缀#)
  console.log('\n测试 1: 强制替换名称 (#后缀#)');
  const preferredIps = '104.16.1.1#HK-Node#'; // 注意末尾有#
  const endpoints = parsePreferredEndpoints(preferredIps);
  const nodes = buildNodes(baseNodes, endpoints);
  
  if (nodes[0].name === 'HK-Node') {
    console.log('✅ 强制替换成功: ' + nodes[0].name);
  } else {
    console.error('❌ 强制替换失败: 预期 "HK-Node", 得到 "' + nodes[0].name + '"');
    process.exit(1);
  }

  // 2. 测试 Clash 规则注入
  console.log('\n测试 2: Clash 自定义规则注入');
  const yaml = renderClash(nodes);
  
  const hasProxyGroup = yaml.includes('🚀 节点选择');
  const hasAutoSelect = yaml.includes('♻️ 自动选择');
  const hasCustomRules = yaml.includes('DOMAIN-SUFFIX,acl4.ssr,🎯 全球直连');
  
  if (hasProxyGroup && hasAutoSelect) {
    console.log('✅ 策略组注入成功');
  } else {
    console.error('❌ 策略组缺失');
    process.exit(1);
  }

  if (hasCustomRules) {
    console.log('✅ 3600行分流规则注入成功');
  } else {
    console.error('❌ 分流规则缺失');
    process.exit(1);
  }

  console.log('\n--- 所有测试全部通过！ ---');
}

runTest().catch(err => {
  console.error(err);
  process.exit(1);
});
