// Screenshots + the README demo video, from a running stack with demo data.
//
//   make quickstart                     # or: make lite && make lite-demo
//   node scripts/media/capture.cjs shots out/       # 2x PNG screenshots
//   node scripts/media/capture.cjs video out/       # raw tour video (.webm)
//   bash scripts/media/build.sh out/                # -> docs/screenshots/*.webp, docs/media/*
//
// Env: PADDOCK_UI (default http://127.0.0.1:3000), PADDOCK_API
// (default http://127.0.0.1:8080), PADDOCK_USER (admin), PADDOCK_PASSWORD
// (your ADMIN_BOOTSTRAP_PASSWORD). Needs `playwright` with Chromium.
const { chromium } = require('playwright');
const fs = require('fs');

const UI = process.env.PADDOCK_UI || 'http://127.0.0.1:3000';
const API = process.env.PADDOCK_API || 'http://127.0.0.1:8080';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function token() {
  const r = await fetch(`${API}/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: process.env.PADDOCK_USER || 'admin', password: process.env.PADDOCK_PASSWORD }),
  });
  if (!r.ok) throw new Error(`login failed: HTTP ${r.status} (set PADDOCK_PASSWORD)`);
  return (await r.json()).access_token;
}

async function signIn(page, tok) {
  await page.evaluate((t) => {
    localStorage.setItem('paddock.auth.v1', JSON.stringify({ token: t, user: { username: 'admin', role: 'admin', clearance: 'restricted' } }));
    sessionStorage.setItem('paddock.setup.redirected', '1');
  }, tok);
}

async function shots(out) {
  const tok = await token();
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: 'dark' });
  const p = await ctx.newPage();
  await p.goto(`${UI}/welcome`); await sleep(3500); await p.screenshot({ path: `${out}/landing.png` });
  await p.goto(`${UI}/check`); await sleep(2500); await p.screenshot({ path: `${out}/check.png` });
  await signIn(p, tok);
  for (const r of ['overview', 'chains', 'reports']) {
    await p.goto(`${UI}/${r}`); await sleep(3000); await p.screenshot({ path: `${out}/${r}.png` });
  }
  await p.goto(`${UI}/findings`); await sleep(2500);
  await p.locator('select[aria-label="exploitability filter"]').selectOption('confirmed'); await sleep(1500);
  await p.screenshot({ path: `${out}/findings-verified.png` });
  await p.goto(`${UI}/graph`); await sleep(3000);
  await p.mouse.move(760, 470);
  for (let i = 0; i < 2; i++) { await p.mouse.wheel(0, -200); await sleep(250); }
  await p.mouse.move(1430, 60); await sleep(1200); await p.screenshot({ path: `${out}/graph.png` });
  await b.close();
}

async function video(out) {
  const tok = await token();
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark', recordVideo: { dir: out, size: { width: 1440, height: 900 } } });
  const p = await ctx.newPage();
  await p.goto(`${UI}/welcome`, { waitUntil: 'networkidle' }); await sleep(4200);
  await p.mouse.wheel(0, 900); await sleep(1300); await p.mouse.wheel(0, 900); await sleep(1300);
  await signIn(p, tok);
  await p.goto(`${UI}/overview`); await sleep(2600);
  await p.mouse.move(700, 520); await sleep(500); await p.mouse.move(820, 520); await sleep(500);
  await p.goto(`${UI}/graph`); await sleep(1800);
  await p.mouse.move(690, 480);
  for (let i = 0; i < 3; i++) { await p.mouse.wheel(0, -220); await sleep(220); }
  await p.mouse.down(); await p.mouse.move(560, 470, { steps: 12 }); await p.mouse.up(); await sleep(900);
  await p.mouse.move(1380, 860); await sleep(600);
  await p.goto(`${UI}/findings`); await sleep(1500);
  await p.locator('select[aria-label="exploitability filter"]').selectOption('confirmed'); await sleep(3400);
  await p.goto(`${UI}/chains`); await sleep(2000);
  await p.goto(`${UI}/reports`); await sleep(2200);
  await p.mouse.move(800, 600); await p.mouse.wheel(0, 700); await sleep(1300);
  await p.evaluate(() => localStorage.removeItem('paddock.auth.v1'));
  await p.goto(`${UI}/check`); await sleep(1300);
  await p.locator('input').first().click();
  await p.keyboard.type('acme-demo.example', { delay: 55 }); await sleep(1400);
  await ctx.close(); await b.close();
}

(async () => {
  const [mode, out] = process.argv.slice(2);
  if (!['shots', 'video'].includes(mode) || !out) {
    console.error('usage: node scripts/media/capture.cjs shots|video <out-dir>'); process.exit(2);
  }
  fs.mkdirSync(out, { recursive: true });
  await (mode === 'shots' ? shots(out) : video(out));
})().catch((e) => { console.error(e); process.exit(1); });
