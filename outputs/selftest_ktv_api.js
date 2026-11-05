/**
 * ktv_api.js 回归自测（Node，无需 Android）
 *   node outputs/selftest_ktv_api.js          离线逻辑用例
 *   REAL=1 node outputs/selftest_ktv_api.js  额外跑一次真实歌源取链
 *
 * 覆盖：远程 host 配置 404 兜底 / 恶意 host 过滤 / 整轮失败熔断 /
 *       成功节点优先 / 真实 do.php 取链。
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const SCRIPT = fs.readFileSync(path.join(ROOT, 'app/src/main/assets/mobile/ktv_api.js'), 'utf8');
const HOSTS_FILE = path.join(ROOT, 'song-hosts.json');
const BUILTIN = ['http://mm.kk456.top', 'http://gz.ac16.vip'];

let failures = 0;
function check(name, ok, extra) {
  console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (extra ? '  ' + extra : ''));
  if (!ok) failures++;
}

function loadApi(httpGet) {
  const sandbox = {
    console,
    android: {
      httpGet,
      httpPost: () => JSON.stringify({ status: 0, body: '' }),
      rsaEncryptPkcs1: () => '',
    },
    XMLHttpRequest: function () {},
    unescape: global.unescape,
    encodeURIComponent: encodeURIComponent,
  };
  sandbox.window = sandbox;
  vm.runInNewContext(SCRIPT, sandbox, { filename: 'ktv_api.js' });
  return sandbox;
}

async function main() {
  // ── 1. 配置 404 / 离线：静默沿用内置 HOSTS ──────────────────
  {
    const calls = [];
    const s = loadApi((url) => { calls.push(url); return JSON.stringify({ status: 404, body: '' }); });
    const api = new s.KtvApi({ maxDeviceRetries: 0 });
    await api.init();
    await new Promise((r) => setTimeout(r, 30));
    check('配置拉取失败沿内置 HOSTS',
      JSON.stringify(s.KtvApiConfig.HOSTS) === JSON.stringify(BUILTIN),
      s.KtvApiConfig.HOSTS.join(','));
    check('配置 URL 已请求（桥白名单需放行）', calls.some((u) => u.includes('song-hosts.json')));
  }

  // ── 2. 配置 200 + 恶意项：只接受纯主机，且覆盖生效 ────────────
  {
    const remote = {
      hosts: [
        'http://new.node-a.top',
        'http://new.node-a.top/',       // 重复（去尾斜杠后）
        'https://evil.example.com/path?x=1', // 带路径 → 拒绝
        'javascript:alert(1)',          // 非 http → 拒绝
        'http://127.0.0.1:8080',        // 纯 IP（防 SSRF）→ 拒绝
        '',
      ],
    };
    const s = loadApi((url) => url.includes('song-hosts.json')
      ? JSON.stringify({ status: 200, body: JSON.stringify(remote) })
      : JSON.stringify({ status: 404, body: '' }));
    const api = new s.KtvApi({ maxDeviceRetries: 0 });
    await api.init();
    await new Promise((r) => setTimeout(r, 30));
    const hosts = s.KtvApiConfig.HOSTS;
    check('远程配置覆盖生效', hosts[0] === 'http://new.node-a.top', hosts.join(','));
    check('带路径/非 http/纯 IP 项被过滤',
      !hosts.some((h) => h.includes('/path') || h.startsWith('javascript') || h.includes('127.0.0.1')));
    check('去重生效', new Set(hosts).size === hosts.length);
    // 纯 IP 主机符合格式但会被 KtvJsBridge 的 SSRF 白名单拦下；这里确认不会注入到签名主机之外
    check('配置未写入 CONFIG 以外的字段', s.KtvApiConfig.APP_ID === 'd4eeacc6cec3434fbc8c41608a3056a0');
  }

  // ── 3. 整轮失败 → 连续 3 次后熔断，第 4 次零请求 ──────────────
  {
    let calls = 0;
    const s = loadApi(() => { calls++; return JSON.stringify({ status: 0, body: '' }); });
    const api = new s.KtvApi({ maxDeviceRetries: 0 });
    for (let i = 0; i < 3; i++) await api.getSongUrl('7678785', '720', false);
    const before = calls;
    calls = 0;
    const url = await api.getSongUrl('7678785', '720', false);
    check('3 次整轮失败后熔断', url === null && calls === 0,
      '熔断前请求=' + before + ' 熔断后请求=' + calls);
  }

  // ── 4. 备用节点成功 → lastGoodHost 记录并优先 ────────────────
  {
    let calls = [];
    const s = loadApi((url) => {
      calls.push(url);
      if (url.includes('/i.php')) {
        // 第一个节点 502，第二个节点给 token
        return url.includes(BUILTIN[0])
          ? JSON.stringify({ status: 502, body: '' })
          : JSON.stringify({ status: 200, body: '{"code":200,"token":"tok"}' });
      }
      if (url.includes('/music/do.php')) {
        return JSON.stringify({
          status: 200,
          body: JSON.stringify({ code: 200, data: 'http://txog.ktvsky.com/E/ts/7678785.ts' }),
        });
      }
      return JSON.stringify({ status: 404, body: '' });
    });
    const api = new s.KtvApi({ maxDeviceRetries: 0 });
    const url = await api.getSongUrl('7678785', '720', false);
    check('备用节点可取到链', !!url && url.includes('7678785.ts'), String(url));
    check('记住成功节点', api.lastGoodHost === BUILTIN[1], String(api.lastGoodHost));
    calls = [];
    await api.getSongUrl('7678785', '720', false);
    // token 已按 host 缓存，第二次不会再发 i.php；看第一条 do.php 是否命中成功节点
    const firstDo = calls.find((u) => u.includes('/music/do.php'));
    check('下次优先命中成功节点',
      !!firstDo && firstDo.includes(BUILTIN[1]), String(firstDo));
  }

  // ── 5. 真网络：do.php 仍返回真实 .ts（非 poison） ─────────────
  if (process.env.REAL === '1') {
    const curlGet = (url) => {
      try {
        const out = execFileSync('curl', ['-s', '-m', '10', '-w', '\n%{http_code}', url],
          { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
        const cut = out.lastIndexOf('\n');
        return JSON.stringify({ status: parseInt(out.slice(cut + 1), 10) || 0, body: out.slice(0, cut) });
      } catch (e) {
        return JSON.stringify({ status: 0, body: '', error: String(e.message) });
      }
    };
    const s = loadApi((url) => url.includes('song-hosts.json')
      ? JSON.stringify({ status: 404, body: '' }) : curlGet(url));
    const api = new s.KtvApi({ debug: true, maxDeviceRetries: 1 });
    const url = await api.getSongUrl('7678785', '720', false);
    check('真实歌源可取到 ts 直链', !!url && /\.ts/.test(url) && !/poison/.test(url), String(url));
  }

  console.log('\n结果: ' + (failures === 0 ? 'ALL PASS' : failures + ' FAILED'));
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
