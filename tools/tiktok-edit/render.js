// usage: node render.js [fromFrame] [toFrame] [outDir] [port] [variant main|a|b]   (Playwright; page is served by build.sh)
const { chromium } = require('playwright'); const fs = require('fs');
const [,, from = '0', to = '507', out = 'out/frames', port = '8767', variant = 'main'] = process.argv;
fs.mkdirSync(out, { recursive: true });
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1080, height: 1920 } });
  p.on('pageerror', e => console.log('ERR', e.message));
  await p.goto(`http://localhost:${port}/edit.html?v=${variant}`); await p.waitForFunction('window.READY===true', null, { timeout: 30000 });
  for (let f = +from; f < +to; f++) {
    await p.evaluate(t => window.render(t), f / 30);
    await p.screenshot({ path: `${out}/f${String(f).padStart(4, '0')}.jpg`, type: 'jpeg', quality: 92 });
  }
  await b.close();
})();
