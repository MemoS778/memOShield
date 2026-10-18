import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn, execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {DatabaseSync} from 'node:sqlite';
import {chromium} from 'playwright';

// Isolated monitor-only server: never use the user's database or firewall.
const directory = await mkdtemp(join(tmpdir(), 'memoshield-ui-'));
let server, browser;
try {
  const binary = join(directory, 'server');
  execFileSync(process.env.GO_BIN || 'go', ['build', '-o', binary, '.'], {cwd: fileURLToPath(new URL('../../', import.meta.url)), stdio: 'inherit'});
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const base = `http://127.0.0.1:${port}`;
  server = spawn(binary, [], {env: {...process.env, MEMOSHIELD_LISTEN: `127.0.0.1:${port}`, MEMOSHIELD_DATA_DIR: directory, MEMOSHIELD_MODE: 'monitor', MEMOSHIELD_JOURNAL: '0', MEMOSHIELD_EVE_PATH: ''}, stdio: 'ignore'});
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(base)).ok) { ready = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready, 'server starts');
  if (process.env.GNOME_CLIENT_TEST === '1') {
    execFileSync('gjs', ['-m', fileURLToPath(new URL('../gnome-client.js', import.meta.url)), base, join(directory, 'access-token')], {stdio: 'inherit'});
  }
  browser = await chromium.launch({executablePath: process.env.BROWSER_PATH || undefined});
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error' && /Content Security Policy/i.test(message.text())) errors.push(message.text()); });
  await page.goto(base);
  await page.locator('#token').fill('incorrect-token');
  await page.locator('#login-button').click();
  await page.locator('#login-error').waitFor({state: 'visible'});
  await page.locator('#token').fill((await readFile(join(directory, 'access-token'), 'utf8')).trim());
  await page.locator('#login-button').click();
  await page.locator('#dashboard').waitFor({state: 'visible'});
  assert.equal(await page.locator('#metric-events').textContent(), '0');
  await page.locator('[data-view="protection"]').click();
  assert.ok(await page.locator('#ban-button').isDisabled());
  await page.locator('#allow-prefix').fill('192.0.2.42');
  await page.locator('#allow-form button').click();
  await page.locator('#allowlist li', {hasText: '192.0.2.42'}).waitFor();
  await page.locator('#allowlist li', {hasText: '192.0.2.42'}).getByRole('button').click();
  await page.locator('#allowlist li', {hasText: '192.0.2.42'}).waitFor({state: 'detached'});

  const db = new DatabaseSync(join(directory, 'personal.db'));
  try {
    db.exec('PRAGMA busy_timeout=5000');
    const insert = db.prepare('INSERT INTO personal_events(event_key,time,source,kind,source_ip,payload) VALUES(?,?,?,?,?,?)');
    for (let i = 1; i <= 20; i++) {
      const event = {time: new Date().toISOString(), source: 'journal', kind: 'ssh_failed', severity: i === 20 ? 'high' : 'medium', source_ip: `192.0.2.${i}`, evidence: '<img src=x onerror="window.injected=true">'};
      insert.run(`test-${i}`, Date.now(), event.source, event.kind, event.source_ip, JSON.stringify(event));
    }
  } finally { db.close(); }
  await page.locator('#refresh').click();
  await page.waitForFunction(() => document.getElementById('nav-events').textContent === '20');
  await page.locator('[data-view="events"]').click();
  assert.equal(await page.locator('#events tr').count(), 15);
  await page.locator('#next').click();
  assert.equal(await page.locator('#events tr').count(), 5);
  await page.locator('#severity-filter').selectOption('high');
  assert.equal(await page.locator('#events tr').count(), 1);
  await page.locator('#events .row-button').click();
  assert.match(await page.locator('#detail-evidence').textContent(), /<img/);
  assert.equal(await page.evaluate(() => window.injected), undefined);
  await page.keyboard.press('Escape');
  const downloaded = page.waitForEvent('download');
  await page.locator('#export').click();
  const download = await downloaded;
  const exported = JSON.parse(await readFile(await download.path(), 'utf8'));
  assert.equal(exported.events.length, 1);
  await page.locator('#pause').click();
  assert.equal(await page.locator('#pause').getAttribute('aria-pressed'), 'true');
  await page.locator('#pause').click();
  await page.locator('[data-view="sensors"]').click();
  await page.locator('#sensors .text-button').first().click();
  await page.locator('#help-dialog').waitFor({state: 'visible'});
  await page.keyboard.press('Escape');
  await page.setViewportSize({width: 390, height: 844});
  for (const view of ['overview', 'events', 'protection', 'sensors']) {
    await page.locator(`[data-view="${view}"]`).click();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${view}: no mobile page overflow`);
  }
  await page.locator('#logout').click();
  await page.locator('#login').waitFor({state: 'visible'});
  assert.deepEqual(errors, []);
  console.log('PASS: login, empty state, monitor guard, allowlist, pagination, filtering, safe evidence, export, pause, help, mobile layout, logout');
} finally {
  await browser?.close();
  if (server && server.exitCode === null) { const exited = once(server, 'exit'); server.kill(); await exited; }
  await rm(directory, {recursive: true, force: true});
}
