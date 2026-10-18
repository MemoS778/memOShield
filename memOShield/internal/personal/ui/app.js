'use strict';

const $ = id => document.getElementById(id);
const state = {
  events: [], bans: [], prefixes: [], status: null, page: 1, perPage: 15,
  stream: null, timer: null, paused: false, frozen: [], pending: 0,
  selected: null, epoch: 0, authenticated: false, refreshing: false,
};
const views = {
  overview: ['Genel bakış', 'Güvenliğin, bir bakışta.', 'Bilgisayarına ulaşan sinyalleri takip et, ne yapacağına sen karar ver.'],
  events: ['Olay akışı', 'Her olayın bir hikâyesi var.', 'Giriş denemelerini ve ağ uyarılarını incele. Kanıttan karara, tek bir akış.'],
  protection: ['Koruma', 'Kontrol sende.', 'Süreli engelleri yönet, güvendiğin adresleri koru.'],
  sensors: ['Sensörler', 'Görünürlüğünü yönet.', 'Bağlı kaynakları, veri akışını ve eksik kurulum adımlarını gör.'],
};
const kinds = {ssh_failed: 'Başarısız SSH parolası', ssh_success: 'Başarılı SSH girişi', ssh_bruteforce: 'Tekrarlanan SSH hataları', network_alert: 'Ağ sensörü uyarısı'};
const severity = {high: ['Yüksek', 'danger'], medium: ['Orta', 'caution'], low: ['Düşük', 'blue'], info: ['Bilgi', 'neutral']};
const sensorMeta = {
  journal: ['SSH günlüğü', '↳', 'Başarılı ve başarısız yerel SSH oturumları.'],
  suricata: ['Ağ sensörü', '⌁', 'Suricata EVE dosyasından alınan ağ uyarıları.'],
  firewall: ['Firewall', '◇', 'Süreli engellerin işletim sistemiyle uzlaştırılması.'],
  database: ['Olay deposu', '▤', 'Bu bilgisayarda tutulan kalıcı SQLite kayıtları.'],
};
const sensorStates = {disabled: ['Kapalı', 'neutral'], watching: ['İzleniyor', 'blue'], receiving: ['Veri alınıyor', 'good'], ready: ['Hazır', 'good'], warning: ['Kontrol et', 'caution'], error: ['Erişim sorunu', 'danger']};
const banStates = {pending: ['Bekliyor', 'caution'], unconfirmed: ['Doğrulanamadı', 'danger'], applied: ['Uygulandı', 'good'], expired: ['Süresi doldu', 'neutral'], removed: ['Kaldırıldı', 'neutral']};
const modeNames = {monitor: 'İzleme modu', manual: 'Manuel koruma', auto: 'Otomatik koruma'};
const modeDescriptions = {monitor: 'Olaylar kaydedilir, engel uygulanmaz.', manual: 'Engelleme kararlarını sen verirsin.', auto: 'Taze SSH parola hataları için süreli koruma.'};

function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = String(text);
  return el;
}
function badge(text, tone = 'neutral') { return node('span', 'pill ' + tone, text); }
function when(value) {
  if (!value || value.startsWith('0001-')) return 'Henüz doğrulanmadı';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Bilinmiyor' : date.toLocaleString('tr-TR', {dateStyle: 'short', timeStyle: 'medium'});
}
function timeOnly(value) { return new Date(value).toLocaleTimeString('tr-TR', {hour: '2-digit', minute: '2-digit'}); }
function relative(value) {
  const minutes = Math.floor((Date.now() - new Date(value).getTime()) / 60000);
  if (minutes < 0) return 'İleri tarihli kayıt';
  if (minutes < 1) return 'Az önce';
  if (minutes < 60) return `${minutes} dk önce`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)} sa önce`;
  return `${Math.floor(minutes / 1440)} gün önce`;
}
function toast(text, error = false) {
  const el = node('div', 'toast' + (error ? ' error' : ''));
  el.append(node('span', '', text));
  const close = node('button', '', '×'); close.setAttribute('aria-label', 'Bildirimi kapat');
  close.addEventListener('click', () => el.remove()); el.append(close);
  $('toasts').append(el);
  while ($('toasts').children.length > 3) $('toasts').firstChild.remove();
  setTimeout(() => el.remove(), error ? 10000 : 4500);
}
function errorText(message) {
  const translations = {
    'invalid access token': 'Erişim anahtarı eşleşmedi. Dosyadaki anahtarı eksiksiz yapıştır.',
    'authentication required': 'Oturumun sona erdi. Lütfen tekrar giriş yap.',
    'too many login attempts': 'Çok fazla giriş denemesi. Bir dakika sonra tekrar dene.',
    'IP is allowlisted': 'Bu IP güvenilir listede; engellenemez.',
    'invalid IP address': 'Geçerli bir IPv4 veya IPv6 adresi gir.',
    'invalid IP or CIDR': 'Geçerli bir IP adresi veya CIDR aralığı gir.',
    'monitor mode: blocking is disabled': 'İzleme modunda engelleme kapalı.',
    'Failed to fetch': 'Sunucuya ulaşılamadı. Yerel servisin çalıştığını kontrol et.',
  };
  return translations[message] || message;
}
async function api(path, body) {
  const options = body === undefined ? {} : {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)};
  const res = await fetch('/api/' + path, options);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = {error: `İstek tamamlanamadı (HTTP ${res.status}).`}; }
  if (res.status === 401 && path !== 'login') signedOut();
  if (!res.ok) throw new Error(errorText(data.error || `HTTP ${res.status}`));
  return data;
}
async function action(button, fn, success) {
  const disabled = button?.disabled;
  if (button) button.disabled = true;
  try { await fn(); if (success) toast(success); }
  catch (err) { toast(errorText(err.message), true); }
  finally { if (button?.isConnected) button.disabled = disabled; }
}
function signedOut() {
  state.epoch++; state.authenticated = false;
  state.stream?.close(); state.stream = null;
  clearInterval(state.timer); state.timer = null;
  state.events = []; state.bans = []; state.prefixes = []; state.status = null;
  state.paused = false; state.frozen = []; state.pending = 0; state.selected = null;
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  $('dashboard').hidden = true; $('login').hidden = false;
}
function setView(name) {
  if (!views[name]) name = 'overview';
  document.querySelectorAll('[data-panel]').forEach(el => { el.hidden = el.dataset.panel !== name; });
  document.querySelectorAll('[data-view]').forEach(el => {
    if (el.dataset.view === name) el.setAttribute('aria-current', 'page');
    else el.removeAttribute('aria-current');
  });
  $('breadcrumb').textContent = views[name][0]; $('page-title').textContent = views[name][1]; $('page-description').textContent = views[name][2];
  document.title = `${views[name][0]} · memOShield`;
}
function displayedEvents() { return state.paused ? state.frozen : state.events; }
function filteredEvents() {
  const query = $('filter').value.toLocaleLowerCase('tr-TR').trim();
  const level = $('severity-filter').value, source = $('source-filter').value, hours = $('time-filter').value;
  return displayedEvents().filter(e => {
    if (level !== 'all' && e.severity !== level) return false;
    if (source !== 'all' && e.source !== source) return false;
    if (hours !== 'all' && (Date.now() - new Date(e.time).getTime() > Number(hours) * 3600000 || new Date(e.time).getTime() > Date.now())) return false;
    const haystack = [e.source_ip, e.target_ip, e.user, e.evidence, kinds[e.kind] || e.kind].join(' ').toLocaleLowerCase('tr-TR');
    return !query || haystack.includes(query);
  });
}
function metricBanCount() {
  if (state.status?.mode === 'monitor') return 0;
  const status = state.status?.sensors?.firewall;
  if (status?.state !== 'ready' || Date.now() - new Date(status.updated).getTime() > 30000) return 0;
  return state.bans.filter(b => b.state === 'applied' && b.desired && new Date(b.expires).getTime() > Date.now()).length;
}
function renderMetrics() {
  const events = displayedEvents();
  $('metric-events').textContent = events.length;
  $('metric-high').textContent = events.filter(e => e.severity === 'high').length;
  $('metric-sources').textContent = new Set(events.map(e => e.source_ip).filter(Boolean)).size;
  $('metric-bans').textContent = metricBanCount();
  $('metric-bans-detail').textContent = state.status?.mode === 'monitor' ? 'İzleme modunda engelleme kapalı' : 'Son doğrulanan, süresi dolmamış';
  $('nav-events').textContent = state.events.length;
  $('onboarding').hidden = state.events.length > 0;
}
function svgNode(tag, attributes, text) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attributes)) el.setAttribute(key, String(value));
  if (text !== undefined) el.textContent = text;
  return el;
}
function renderChart() {
  const now = Date.now(), hour = 3600000, start = Math.floor(now / hour) * hour - 23 * hour;
  const bins = Array.from({length: 24}, () => ({all: 0, high: 0}));
  for (const e of displayedEvents()) {
    const stamp = new Date(e.time).getTime(), index = Math.floor((stamp - start) / hour);
    if (index >= 0 && index < 24 && stamp <= now) { bins[index].all++; if (e.severity === 'high') bins[index].high++; }
  }
  const total = bins.reduce((n, b) => n + b.all, 0), max = Math.max(1, ...bins.map(b => b.all));
  const svg = svgNode('svg', {viewBox: '0 0 640 195', preserveAspectRatio: 'none', 'aria-hidden': 'true'});
  for (let i = 0; i <= 3; i++) {
    const y = 15 + i * 48;
    svg.append(svgNode('line', {x1: 30, x2: 630, y1: y, y2: y, class: 'chart-grid'}));
    svg.append(svgNode('text', {x: 0, y: y + 3, class: 'chart-label'}, Math.round(max * (3 - i) / 3)));
  }
  bins.forEach((b, i) => {
    const x = 34 + i * 25, height = b.all / max * 140;
    if (b.all) {
      const bar = svgNode('rect', {x, y: 159 - height, width: 14, height, rx: 2, class: 'chart-bar'});
      bar.append(svgNode('title', {}, `${timeOnly(new Date(start + i * hour))}: ${b.all} olay, ${b.high} yüksek önem`)); svg.append(bar);
      if (b.high) svg.append(svgNode('rect', {x, y: 159 - b.high / max * 140, width: 14, height: b.high / max * 140, rx: 2, class: 'chart-high'}));
    }
    if (i % 4 === 0 || i === 23) svg.append(svgNode('text', {x, y: 185, class: 'chart-label', 'text-anchor': i === 23 ? 'end' : 'start'}, timeOnly(new Date(start + i * hour))));
  });
  if (!total) svg.append(svgNode('text', {x: 330, y: 83, 'text-anchor': 'middle', class: 'chart-empty-label'}, 'Olaylar geldikçe aktivite burada görünecek'));
  $('activity-chart').replaceChildren(svg);
  $('activity-chart').setAttribute('aria-label', `Görünen kayıtlarda son 24 saat: ${total} olay, ${bins.reduce((n, b) => n + b.high, 0)} yüksek önem.`);
  $('chart-summary').textContent = total ? `${total} olay / görünür kayıtlar` : 'Gerçek veri bekleniyor';
}
function miniEmpty(container, symbol, title, description) {
  const empty = node('div', 'mini-empty'); empty.append(node('span', '', symbol), node('strong', '', title), node('p', '', description)); container.replaceChildren(empty);
}
function renderRecent() {
  const recent = $('recent-events'), events = displayedEvents(); recent.replaceChildren();
  if (!events.length) miniEmpty(recent, '≋', 'Henüz hareket yok', 'İlk SSH kaydı veya ağ uyarısı burada görünecek.');
  for (const e of events.slice(0, 5)) {
    const button = node('button', 'recent-item');
    const content = node('div'); content.append(node('div', 'recent-title', kinds[e.kind] || e.kind), node('div', 'recent-ip mono', e.source_ip));
    button.append(node('span', 'recent-icon' + (e.severity === 'high' ? ' high' : ''), e.source === 'journal' ? '↳' : '⌁'), content, node('span', 'recent-time', relative(e.time)));
    button.addEventListener('click', () => showEvent(e)); recent.append(button);
  }
  const sources = $('top-sources'); sources.replaceChildren();
  const counts = new Map(); for (const e of events) counts.set(e.source_ip, (counts.get(e.source_ip) || 0) + 1);
  const top = [...counts].sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (!top.length) miniEmpty(sources, '⌁', 'Kaynak verisi bekleniyor', 'Görünen olayların IP dağılımı burada listelenir.');
  for (const [ip, count] of top) {
    const row = node('div', 'source-row'), head = node('div'), button = node('button', 'mono', ip);
    button.addEventListener('click', () => { $('filter').value = ip; state.page = 1; location.hash = 'events'; renderTable(); });
    head.append(button, node('span', '', `${count} olay`));
    const meter = node('meter'); meter.min = 0; meter.max = top[0][1]; meter.value = count; meter.setAttribute('aria-label', `${ip}: ${count} olay`);
    row.append(head, meter); sources.append(row);
  }
}
function cell(row, content, className = '') {
  const td = node('td', className); if (content instanceof Node) td.append(content); else td.textContent = content ?? '—'; row.append(td); return td;
}
function renderTable() {
  const filtered = filteredEvents(), pages = Math.max(1, Math.ceil(filtered.length / state.perPage));
  state.page = Math.max(1, Math.min(state.page, pages)); $('events').replaceChildren();
  for (const e of filtered.slice((state.page - 1) * state.perPage, state.page * state.perPage)) {
    const row = node('tr'); const date = node('div'); date.append(node('span', 'cell-title', timeOnly(e.time)), node('span', 'cell-sub', new Date(e.time).toLocaleDateString('tr-TR'))); cell(row, date, 'cell-time');
    cell(row, badge(...(severity[e.severity] || ['Bilinmiyor', 'neutral'])));
    const kind = node('div'); kind.append(node('span', 'cell-title', kinds[e.kind] || e.kind), node('span', 'cell-sub', e.source === 'journal' ? 'SSH günlüğü' : 'Suricata')); cell(row, kind);
    const ip = node('button', 'ip-button', e.source_ip); ip.title = 'IP adresini kopyala'; ip.addEventListener('click', () => copyIP(e.source_ip)); cell(row, ip);
    cell(row, (e.target_ip || 'Bu bilgisayar') + (e.port ? ':' + e.port : ''), 'mono');
    const detail = node('button', 'row-button', 'İncele ↗'); detail.setAttribute('aria-label', `${e.source_ip} olayını incele`); detail.addEventListener('click', () => showEvent(e)); cell(row, detail); $('events').append(row);
  }
  $('events-empty').hidden = filtered.length !== 0;
  const noEvents = displayedEvents().length === 0;
  $('events-empty-title').textContent = noEvents ? 'Henüz olay yok' : 'Bu filtrelerle eşleşen olay yok';
  $('events-empty-description').textContent = noEvents ? 'Gerçek bir kayıt alındığında akışta görünür. Örnek saldırı verisi gösterilmez.' : 'Aramanı değiştir veya filtreleri sıfırla. Arama en yeni 200 kaydı kapsar.';
  $('event-count').textContent = filtered.length;
  $('page-info').textContent = filtered.length ? `${(state.page - 1) * state.perPage + 1}–${Math.min(state.page * state.perPage, filtered.length)} / ${filtered.length} olay` : '0 olay';
  $('page-number').textContent = `${state.page} / ${pages}`; $('previous').disabled = state.page === 1; $('next').disabled = state.page === pages;
  $('export').disabled = filtered.length === 0;
  $('paused-notice').hidden = !state.paused; $('pending-events').textContent = `${state.pending} yeni olay`;
  $('pause').textContent = state.paused ? 'Canlıya dön' : 'Akışı duraklat'; $('pause').setAttribute('aria-pressed', String(state.paused));
}
function renderEvents() { renderMetrics(); renderChart(); renderRecent(); renderTable(); }

function renderStatus() {
  const data = state.status; if (!data) return;
  $('sidebar-mode').textContent = modeNames[data.mode] || data.mode; $('sidebar-mode-detail').textContent = modeDescriptions[data.mode] || '';
  $('monitor-banner').hidden = data.mode !== 'monitor'; $('ban-button').disabled = data.mode === 'monitor';
  $('sensor-summary').replaceChildren(); $('sensors').replaceChildren();
  for (const [name, meta] of Object.entries(sensorMeta)) {
    const s = data.sensors[name] || {state: 'disabled', detail: 'Durum bilgisi alınamadı', updated: ''};
    const [label, tone] = sensorStates[s.state] || [s.state, 'neutral'];
    const summary = node('div', 'sensor-summary-row'); summary.append(node('span', 'sensor-summary-icon', meta[1]), node('span', '', meta[0]), badge(label, tone)); $('sensor-summary').append(summary);
    const card = node('article', 'sensor-card'), header = node('div', 'sensor-card-header');
    header.append(node('span', 'sensor-glyph', meta[1]), node('h3', '', meta[0]), badge(label, tone));
    const footer = node('div', 'sensor-card-footer'); footer.append(node('small', '', 'Son durum: ' + when(s.updated)));
    const help = node('button', 'text-button', 'Kurulum rehberi ↗'); help.addEventListener('click', () => showHelp(name)); footer.append(help);
    card.append(header, node('p', '', meta[2]), node('p', 'field-help', s.detail), footer); $('sensors').append(card);
  }
  renderMetrics(); renderBans();
}
function renderBans() {
  $('bans').replaceChildren(); $('bans-empty').hidden = state.bans.length > 0;
  for (const b of state.bans) {
    const row = node('tr'); cell(row, b.ip, 'mono'); cell(row, b.reason); cell(row, when(b.expires), 'cell-time');
    const detail = node('div'); detail.append(badge(...(banStates[b.state] || [b.state, 'neutral'])), node('span', 'cell-sub', 'Son doğrulama: ' + when(b.confirmed)));
    if (b.error) detail.append(node('span', 'cell-sub', b.error)); cell(row, detail);
    const button = node('button', 'row-button', b.state === 'unconfirmed' ? 'Talebi iptal et' : 'Engeli kaldır');
    button.disabled = state.status?.mode === 'monitor' || !b.desired || b.state === 'expired';
    button.addEventListener('click', () => action(button, async () => { await mutate('unban', {ip: b.ip}); }, 'Engelleme kararı kaldırıldı.'));
    cell(row, button); $('bans').append(row);
  }
}
function renderAllowlist() {
  $('allowlist').replaceChildren(); $('allow-count').textContent = `${state.prefixes.length} adres`;
  if (!state.prefixes.length) $('allowlist').append(node('li', 'empty-list', 'Henüz güvenilir adres eklenmemiş.'));
  for (const prefix of state.prefixes) {
    const li = node('li'), button = node('button', 'text-button', 'Kaldır'); li.append(node('span', 'mono', prefix));
    button.setAttribute('aria-label', `${prefix} adresini güvenilir listeden kaldır`);
    button.addEventListener('click', () => action(button, () => mutate('allowlist', {prefix, add: false}), 'Adres güvenilir listeden kaldırıldı.'));
    li.append(button); $('allowlist').append(li);
  }
}
async function refresh(includeEvents = false) {
  const epoch = state.epoch;
  const requests = [api('status'), api('bans'), api('allowlist')]; if (includeEvents) requests.push(api('events'));
  const [status, bans, allow, snapshot] = await Promise.all(requests);
  if (epoch !== state.epoch) return;
  state.status = status; state.bans = bans.bans; state.prefixes = allow.prefixes;
  if (snapshot) {
    const combined = new Map([...state.events, ...snapshot.events].map(e => [e.id, e]));
    state.events = [...combined.values()].sort((a, b) => b.id - a.id).slice(0, 200);
  }
  renderStatus(); renderAllowlist(); if (snapshot) renderEvents();
  $('last-updated').textContent = 'Son güncelleme · ' + timeOnly(new Date()); $('connection-warning').hidden = true;
}
async function mutate(path, body) {
  try { await api(path, body); }
  finally { if (state.authenticated) await refresh().catch(() => {}); }
}
function streamState(label, tone) { $('stream-state').textContent = label; $('stream-pill').className = 'pill ' + tone; }
async function start() {
  const epoch = ++state.epoch;
  await refresh(true); if (epoch !== state.epoch) return;
  state.authenticated = true; $('login').hidden = true; $('dashboard').hidden = false;
  setView(location.hash.slice(1)); renderEvents();
  state.stream?.close(); streamState('Bağlanıyor', 'neutral');
  const latest = state.events.reduce((n, e) => Math.max(n, e.id), 0);
  const stream = new EventSource('/api/stream?after=' + latest); state.stream = stream;
  stream.onopen = () => { if (epoch === state.epoch) streamState('Canlı bağlantı', 'good'); };
  stream.onerror = () => { if (epoch === state.epoch) streamState('Yeniden bağlanıyor', 'caution'); };
  stream.onmessage = ({data}) => {
    if (epoch !== state.epoch) return;
    try {
      const e = JSON.parse(data); if (state.events.some(x => x.id === e.id)) return;
      state.events.unshift(e); state.events = state.events.slice(0, 200);
      if (state.paused) state.pending++;
      renderEvents();
      if (e.severity === 'high' && Date.now() - new Date(e.time).getTime() < 120000 && $('notifications').checked && window.Notification && Notification.permission === 'granted') {
        new Notification('memOShield · ' + (kinds[e.kind] || e.kind), {body: e.source_ip + ' — ' + e.evidence});
      }
    } catch { toast('Bir canlı olay okunamadı. Verileri yenileyebilirsin.', true); }
  };
  clearInterval(state.timer);
  state.timer = setInterval(async () => {
    if (state.refreshing) return; state.refreshing = true;
    try { await refresh(); } catch { if (state.authenticated) $('connection-warning').hidden = false; }
    finally { state.refreshing = false; }
  }, 10000);
}

function showEvent(e) {
  state.selected = e; $('detail-title').textContent = kinds[e.kind] || e.kind;
  $('detail-badges').replaceChildren(badge(...(severity[e.severity] || ['Bilinmiyor', 'neutral'])), badge(e.source === 'journal' ? 'SSH günlüğü' : 'Suricata', 'blue'));
  $('detail-fields').replaceChildren();
  for (const [key, value] of [['Kaynak IP', e.source_ip], ['Hedef', e.target_ip || 'Bu bilgisayar'], ['Zaman', when(e.time)], ['Hedef port', e.port || 'Kayıtta yok'], ['Kullanıcı', e.user || 'Kayıtta yok'], ['Olay kimliği', '#' + e.id]]) {
    const div = node('div'); div.append(node('dt', '', key), node('dd', '', value)); $('detail-fields').append(div);
  }
  $('detail-evidence').textContent = e.evidence; $('event-dialog').showModal();
}
async function copyIP(ip) {
  try { await navigator.clipboard.writeText(ip); toast('IP adresi kopyalandı.'); }
  catch { toast('Panoya erişilemiyor. IP adresini olay detayından seçip kopyalayabilirsin.', true); }
}
const helpContent = {
  modes: ['Çalışma modları', 'Mod değişikliği sunucu yapılandırmasıdır. Panelde görünen bir düğme, gerçekte etkin olmayan koruma izlenimi vermemeli.', ['monitor: Olayları kaydeder; IP engellemez.', 'manual: Firewall yardımcı süreciyle, yalnızca senin seçtiğin IP’leri süreli engeller.', 'auto: Manuel işlevlere ek olarak taze yerel SSH kayıtlarında 2 dakikada 10 parola hatasını 10 dakikalık engelle karşılar. Suricata uyarıları otomatik engel üretmez.'], 'MEMOSHIELD_MODE=manual'],
  journal: ['SSH günlüğünü bağla', 'Sensör root-owned sshd / sshd-session kayıtlarını okur. SSH servisinin kurulu veya açık olması ayrı bir durumdur.', ['Terminalinde journal erişimini kontrol et.', 'Erişim hatası varsa dağıtımının journal grup/ACL politikasını uygula; gerekirse oturumunu yeniden aç.', '“İzleniyor” günlük akışının açık olduğunu söyler. İlk gerçek SSH kaydı geldiğinde olay listesi dolar.'], 'journalctl --system SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session -n 10'],
  suricata: ['Ağ sensörünü bağla', 'Suricata ayrı kurulmalıdır. Bu okuyucu kendi başına ağ paketi yakalamaz; başka iki Wi-Fi cihazı arasındaki trafik normalde görünmez.', ['Suricata’yı kur ve doğru ağ arayüzü / HOME_NET ile yapılandır.', 'EVE JSON alert çıktısını aç. Dosyaya panel kullanıcısına yalnızca okuma erişimi ver.', 'Kullanıcı servisine aşağıdaki ortam değişkenini ekleyip servisi yeniden başlat. Ayrıntılar: memOShield/docs/deployment.md'], 'MEMOSHIELD_EVE_PATH=/var/log/suricata/eve.json'],
  firewall: ['Süreli engellemeyi etkinleştir', 'Web uygulaması normal kullanıcı olarak kalır. İşletim sistemi engellerini ayrı, dar yetkili yardımcı süreç uygular.', ['memoshield-fw binary’sini derle ve root-owned bir konuma kur.', 'deploy/memoshield-firewall.service dosyasında panel kullanıcısının UID değerini ayarla ve servisi kur.', 'Önce manual moduyla başla. Kurulumun tamamı docs/deployment.md dosyasında; sadece mod değişkenini ayarlamak yeterli değildir.'], 'go build -o memoshield-fw ./cmd/memoshield-fw'],
  database: ['Olay verileri', 'Veriler bu bilgisayardaki personal.db içinde saklanır. Giriş anahtarı ayrı bir dosyada tutulur.', ['Varsayılan dizin: ~/.local/state/memoshield. XDG_STATE_HOME veya MEMOSHIELD_DATA_DIR yolu değiştirebilir.', '30 gün / yaklaşık 100.000 olay sınırıyla düzenli temizlik yapılır. Panel en yeni 200 olayı gösterir.', 'Olay akışında filtrelediğin kayıtları JSON olarak indirebilirsin. İndirilen dosya yerel olay verilerini içerir.'], 'systemctl --user status memoshield-personal'],
};
function showHelp(name) {
  const [title, intro, steps, command] = helpContent[name] || helpContent.modes;
  $('help-title').textContent = title; const content = $('help-content'); content.replaceChildren(node('p', '', intro));
  const list = node('ol'); for (const step of steps) list.append(node('li', '', step)); content.append(list, node('code', '', command));
  $('help-dialog').showModal();
}

$('login-form').addEventListener('submit', async ev => {
  ev.preventDefault(); $('login-button').disabled = true; $('login-error').hidden = true;
  try { await api('login', {token: $('token').value.trim()}); $('token').value = ''; await start(); }
  catch (err) { $('login-error').textContent = errorText(err.message); $('login-error').hidden = false; }
  finally { $('login-button').disabled = false; }
});
$('show-token').addEventListener('click', () => { const show = $('token').type === 'password'; $('token').type = show ? 'text' : 'password'; $('show-token').textContent = show ? 'Gizle' : 'Göster'; $('show-token').setAttribute('aria-pressed', String(show)); $('show-token').setAttribute('aria-label', show ? 'Erişim anahtarını gizle' : 'Erişim anahtarını göster'); });
$('logout').addEventListener('click', () => action($('logout'), async () => { await api('logout', {}); signedOut(); }, 'Oturum kapatıldı.'));
$('refresh').addEventListener('click', () => action($('refresh'), () => refresh(true), 'Veriler güncellendi.'));
window.addEventListener('hashchange', () => setView(location.hash.slice(1)));
for (const id of ['filter', 'severity-filter', 'source-filter', 'time-filter']) $(id).addEventListener(id === 'filter' ? 'input' : 'change', () => { state.page = 1; renderTable(); });
$('clear-filters').addEventListener('click', () => { $('filter').value = ''; for (const id of ['severity-filter', 'source-filter', 'time-filter']) $(id).value = 'all'; state.page = 1; renderTable(); });
$('previous').addEventListener('click', () => { state.page--; renderTable(); });
$('next').addEventListener('click', () => { state.page++; renderTable(); });
$('pause').addEventListener('click', () => { state.paused = !state.paused; state.frozen = state.paused ? [...state.events] : []; state.pending = 0; renderEvents(); });
$('export').addEventListener('click', () => {
  const events = filteredEvents(); if (!events.length) return;
  const data = {exported_at: new Date().toISOString(), scope: 'Filtered snapshot of the latest 200 events; not full history', events};
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'}));
  const a = node('a'); a.href = url; a.download = 'memoshield-events-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json'; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(`${events.length} olay JSON olarak indirildi.`);
});
$('ban-form').addEventListener('submit', ev => { ev.preventDefault(); action($('ban-button'), async () => { await mutate('ban', {ip: $('ban-ip').value.trim(), minutes: Number($('ban-minutes').value), reason: $('ban-reason').value.trim()}); $('ban-ip').value = ''; $('ban-reason').value = ''; }, 'Süreli engel uygulandı ve doğrulandı.'); });
$('allow-form').addEventListener('submit', ev => { ev.preventDefault(); action(ev.submitter, async () => { await mutate('allowlist', {prefix: $('allow-prefix').value.trim(), add: true}); $('allow-prefix').value = ''; }, 'Güvenilir liste güncellendi.'); });
$('detail-copy').addEventListener('click', () => { if (state.selected) copyIP(state.selected.source_ip); });
$('detail-trust').addEventListener('click', () => { if (!state.selected) return; action($('detail-trust'), async () => { await mutate('allowlist', {prefix: state.selected.source_ip, add: true}); $('event-dialog').close(); }, 'IP güvenilir listeye eklendi.'); });
$('detail-ban').addEventListener('click', () => { if (!state.selected) return; $('ban-ip').value = state.selected.source_ip; $('ban-reason').value = kinds[state.selected.kind] || 'Olay incelemesi'; $('event-dialog').close(); location.hash = 'protection'; setView('protection'); $('ban-ip').focus(); });
document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => $(button.dataset.close).close()));
for (const id of ['event-dialog', 'help-dialog']) $(id).addEventListener('click', ev => { if (ev.target !== $(id)) return; const r = $(id).getBoundingClientRect(); if (ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom) $(id).close(); });
$('mode-help').addEventListener('click', () => showHelp('modes'));
$('protection-help').addEventListener('click', () => showHelp('firewall'));
$('notifications').addEventListener('change', async () => {
  if (!window.Notification) { $('notifications').checked = false; toast('Tarayıcı masaüstü bildirimlerini desteklemiyor.', true); return; }
  if ($('notifications').checked) {
    try { $('notifications').checked = await Notification.requestPermission() === 'granted'; }
    catch { $('notifications').checked = false; }
    if (!$('notifications').checked) toast('Bildirim izni verilmedi. Tarayıcı site ayarlarından değiştirebilirsin.');
  }
});
document.addEventListener('keydown', ev => {
  if (ev.key !== '/' || !state.authenticated || document.querySelector('dialog[open]') || /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) || document.activeElement.isContentEditable) return;
  ev.preventDefault(); location.hash = 'events'; setView('events'); $('filter').focus();
});
$('today').textContent = new Date().toLocaleDateString('tr-TR', {day: 'numeric', month: 'long', year: 'numeric'});
start().catch(err => { signedOut(); if (!err.message.includes('Oturumun sona erdi')) { $('login-error').textContent = errorText(err.message); $('login-error').hidden = false; } });
