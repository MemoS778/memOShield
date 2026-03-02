/* memOShield SIEM Dashboard — app.js */
/* Tab yonetimi, canli akis, severity siniflandirma, grafikler, harita, IP sorgulama, SSE */

// ——— Fallback demo verisi ———
const sampleEvents = [
  { timestamp: new Date().toISOString(), src_ip:'185.220.101.42', country:'Almanya', lat:52.52, lon:13.41, attack_type:'Port Scan', details:'TCP SYN taramasi tespit edildi — port 22,80,443' },
  { timestamp: new Date(Date.now()-30000).toISOString(), src_ip:'203.0.113.5', country:'Turkiye', lat:39.93, lon:32.87, attack_type:'Brute Force', details:'SSH brute force — 50 basarisiz deneme' },
  { timestamp: new Date(Date.now()-60000).toISOString(), src_ip:'198.51.100.77', country:'Rusya', lat:55.76, lon:37.62, attack_type:'DoS/DDoS', details:'SYN flood saldirisi — 12.000 paket/sn' },
  { timestamp: new Date(Date.now()-90000).toISOString(), src_ip:'45.33.32.156', country:'ABD', lat:37.77, lon:-122.42, attack_type:'Honeypot Trigger', details:'FTP honeypot (port 2121) baglanti denemesi' },
  { timestamp: new Date(Date.now()-120000).toISOString(), src_ip:'103.21.244.0', country:'Cin', lat:39.90, lon:116.41, attack_type:'SQL Injection', details:"Payload: ' OR 1=1 --" },
  { timestamp: new Date(Date.now()-150000).toISOString(), src_ip:'91.219.236.18', country:'Hollanda', lat:52.37, lon:4.90, attack_type:'XSS', details:'Reflected XSS denemesi' },
];

// ——— State ———
let _allEvents = [];
let _bans = [];
let currentPage = 1;
const perPage = 15;
let eventsChart = null;
let typeChart = null;
let countryChart = null;
let poller = null;
let _mapInited = false;

const demoEl = document.getElementById('memoDemo');
const IS_DEMO = demoEl ? (demoEl.dataset.demo === '1') : false;

// ——— Colors ———
const CHART_COLORS = ['#3b82f6','#f97316','#ef4444','#10b981','#a855f7','#06b6d4','#f59e0b','#ec4899','#64748b','#84cc16'];
const ATTACK_COLORS = {
  'Port Scan': '#3b82f6',
  'Brute Force': '#f97316',
  'DoS/DDoS': '#ef4444',
  'Honeypot Trigger': '#10b981',
  'SQL Injection': '#a855f7',
  'XSS': '#06b6d4',
  'Other': '#64748b'
};

// ——— Severity classification ———
const SEVERITY_MAP = {
  'DoS/DDoS':    'critical',
  'SQL Injection':'high',
  'XSS':         'high',
  'Brute Force':  'medium',
  'Port Scan':    'low',
  'Honeypot Trigger': 'info'
};

function getSeverity(attackType){
  return SEVERITY_MAP[attackType] || 'info';
}

function sevDotClass(sev){
  return { critical:'c', high:'h', medium:'m', low:'l', info:'i' }[sev] || 'i';
}

function sevLabel(sev){
  return { critical:'KRITIK', high:'YUKSEK', medium:'ORTA', low:'DUSUK', info:'BILGI' }[sev] || 'BILGI';
}

// ——— SIEM Clock ———
function updateClock(){
  const el = document.getElementById('siemClock');
  if(!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString('tr-TR', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
}

// ——— Tab system ———
function initTabs(){
  const tabs = document.querySelectorAll('.siem-tab');
  const panels = document.querySelectorAll('.siem-panel');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const panel = document.querySelector(`.siem-panel[data-panel="${target}"]`);
      if(panel) panel.classList.add('active');
      // Leaflet map needs invalidateSize when tab becomes visible
      if(target === 'threats' && map){
        setTimeout(() => map.invalidateSize(), 100);
      }
    });
  });
}

// ——— Toast notifications ———
function showToast(text, type='info', timeout=3500){
  const c = document.getElementById('toastContainer');
  if(!c) return;
  const el = document.createElement('div');
  el.className = 'toast ' + (type==='success'? 'success' : type==='error'? 'error' : '');
  el.textContent = text;
  c.appendChild(el);
  setTimeout(()=>{ el.style.opacity='0'; setTimeout(()=>el.remove(),300); }, timeout);
}

// ——— Confirm modal ———
function showConfirm(message){
  return new Promise(resolve => {
    const modal = document.getElementById('confirmModal');
    const msg = document.getElementById('confirmMessage');
    const yes = document.getElementById('confirmYes');
    const no = document.getElementById('confirmNo');
    msg.textContent = message;
    modal.style.display = 'flex';
    const cleanup = () => { modal.style.display='none'; yes.removeEventListener('click',onYes); no.removeEventListener('click',onNo); };
    const onYes = () => { cleanup(); resolve(true); };
    const onNo  = () => { cleanup(); resolve(false); };
    yes.addEventListener('click', onYes);
    no.addEventListener('click', onNo);
  });
}

// ——— API Fetch ———
async function fetchEvents(){
  try{
    const res = await fetch('/api/events');
    if(!res.ok) throw new Error('api');
    const data = await res.json();
    _allEvents = Array.isArray(data) ? data : (data.events || []);
    const notice = document.getElementById('offlineNotice');
    const badge = document.getElementById('statusBadge');
    if(notice) notice.style.display = 'none';
    if(badge){ badge.textContent = 'ONLINE'; badge.className = 'siem-status online'; }
    return _allEvents;
  } catch(err) {
    console.warn('API yok — mock veri kullaniliyor', err);
    _allEvents = sampleEvents;
    const notice = document.getElementById('offlineNotice');
    const badge = document.getElementById('statusBadge');
    if(notice) notice.style.display = 'block';
    if(badge){ badge.textContent = 'OFFLINE'; badge.className = 'siem-status offline'; }
    return sampleEvents;
  }
}

async function fetchBans(){
  try{
    const res = await fetch('/api/bans');
    if(!res.ok) throw new Error('no');
    const data = await res.json();
    _bans = Array.isArray(data) ? data : (data.bans || []);
    return _bans;
  } catch(err) {
    _bans = [];
    return [];
  }
}

// ——— IP Lookup ———
async function lookupIp(ip){
  const resultDiv = document.getElementById('lookupResult');
  const loadingDiv = document.getElementById('lookupLoading');
  const errorDiv = document.getElementById('lookupError');
  if(resultDiv) resultDiv.style.display = 'none';
  if(errorDiv) errorDiv.style.display = 'none';
  if(loadingDiv) loadingDiv.style.display = 'flex';

  try{
    const res = await fetch(`/api/lookup/${encodeURIComponent(ip)}`);
    const data = await res.json();
    if(loadingDiv) loadingDiv.style.display = 'none';

    if(data.error){
      if(errorDiv){ errorDiv.textContent = `Hata: ${data.error}`; errorDiv.style.display = 'block'; }
      return;
    }

    document.getElementById('lkIp').textContent = ip;
    document.getElementById('lkCountry').textContent = data.country || '-';
    document.getElementById('lkIsp').textContent = data.isp || '-';
    document.getElementById('lkOrg').textContent = data.org || '-';
    document.getElementById('lkHostname').textContent = data.hostname || '-';
    document.getElementById('lkCoord').textContent = (data.lat && data.lon) ? `${data.lat.toFixed(4)}, ${data.lon.toFixed(4)}` : '-';
    if(resultDiv) resultDiv.style.display = 'block';

    if(data.lat && data.lon && typeof L !== 'undefined'){
      initMap();
      const marker = L.marker([data.lat, data.lon]).addTo(map);
      marker.bindPopup(`<b>${ip}</b><br>${data.country}<br>ISP: ${data.isp}<br>Hostname: ${data.hostname}`).openPopup();
      map.setView([data.lat, data.lon], 6);
    }

    showToast(`IP ${ip} sorgulandi: ${data.country}`, 'success');
  } catch(err){
    if(loadingDiv) loadingDiv.style.display = 'none';
    if(errorDiv){ errorDiv.textContent = 'Sorgulama basarisiz — ag hatasi.'; errorDiv.style.display = 'block'; }
  }
}

// ——— Filters ———
function applyFilters(events){
  const q = (document.getElementById('search')?.value || '').toLowerCase().trim();
  const type = document.getElementById('typeFilter')?.value || 'all';
  return events.filter(e => {
    if(q){
      const found = (e.src_ip||'').includes(q) || (e.country||'').toLowerCase().includes(q) ||
                    (e.attack_type||'').toLowerCase().includes(q) || (e.details||'').toLowerCase().includes(q);
      if(!found) return false;
    }
    if(type !== 'all' && e.attack_type !== type) return false;
    return true;
  });
}

// ——— Severity bar update ———
function updateSeverityBar(events){
  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  events.forEach(e => {
    const sev = getSeverity(e.attack_type);
    counts[sev]++;
  });
  const el = id => document.getElementById(id);
  if(el('sevCritical')) el('sevCritical').textContent = counts.critical;
  if(el('sevHigh'))     el('sevHigh').textContent = counts.high;
  if(el('sevMedium'))   el('sevMedium').textContent = counts.medium;
  if(el('sevLow'))      el('sevLow').textContent = counts.low;
  if(el('sevInfo'))     el('sevInfo').textContent = counts.info;
}

// ——— Live feed ———
function renderLiveFeed(events){
  const feed = document.getElementById('liveFeed');
  const countEl = document.getElementById('liveCount');
  if(!feed) return;
  const latest = events.slice(0, 50); // show last 50
  if(countEl) countEl.textContent = events.length;

  feed.innerHTML = '';
  latest.forEach(e => {
    const sev = getSeverity(e.attack_type);
    const dt = new Date(e.timestamp);
    const time = dt.toLocaleTimeString('tr-TR', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
    const sevClass = { critical:'crit', high:'high', medium:'med', low:'low', info:'info-s' }[sev] || 'info-s';

    const line = document.createElement('div');
    line.className = `feed-line sev-${sev}`;
    line.innerHTML =
      `<span class="feed-time">${time}</span>` +
      `<span class="feed-sev ${sevClass}">${sevLabel(sev).substring(0,4)}</span>` +
      `<span class="feed-ip" data-ip="${e.src_ip}">${e.src_ip}</span>` +
      `<span class="feed-type">${e.attack_type || '-'}</span>` +
      `<span class="feed-detail">${e.details || ''}</span>`;
    feed.appendChild(line);
  });

  // IP click in live feed -> lookup
  feed.querySelectorAll('.feed-ip').forEach(el => {
    el.addEventListener('click', () => {
      const ip = el.dataset.ip;
      document.getElementById('lookupIp').value = ip;
      lookupIp(ip);
    });
  });
}

// ——— Charts ———
function aggregateByMinute(events){
  const m = {};
  events.forEach(e => {
    const dt = new Date(e.timestamp);
    const key = dt.getHours().toString().padStart(2,'0') + ':' + dt.getMinutes().toString().padStart(2,'0');
    m[key] = (m[key] || 0) + 1;
  });
  const labels = Object.keys(m).sort();
  const data = labels.map(l => m[l]);
  return { labels, data };
}

function renderCharts(events){
  // Bar chart: events by minute
  const agg = aggregateByMinute(events.slice(-200));
  const ctx = document.getElementById('eventsChart')?.getContext('2d');
  if(!ctx) return;
  if(eventsChart){
    eventsChart.data.labels = agg.labels;
    eventsChart.data.datasets[0].data = agg.data;
    eventsChart.update();
  } else {
    eventsChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: agg.labels,
        datasets: [{
          label: 'Olaylar / dakika',
          data: agg.data,
          backgroundColor: 'rgba(59,130,246,0.5)',
          borderColor: '#3b82f6',
          borderWidth: 1,
          borderRadius: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', font: { size: 10 } } },
          y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', stepSize: 1 }, beginAtZero: true }
        }
      }
    });
  }

  // Doughnut: attack types
  const types = {};
  events.forEach(e => { const k = e.attack_type || 'Other'; types[k] = (types[k]||0) + 1; });
  const tlabels = Object.keys(types);
  const tdata = tlabels.map(k => types[k]);
  const tcolors = tlabels.map(k => ATTACK_COLORS[k] || '#64748b');
  const ctx2 = document.getElementById('typeChart')?.getContext('2d');
  if(!ctx2) return;
  if(typeChart){
    typeChart.data.labels = tlabels;
    typeChart.data.datasets[0].data = tdata;
    typeChart.data.datasets[0].backgroundColor = tcolors;
    typeChart.update();
  } else {
    typeChart = new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: tlabels,
        datasets: [{ data: tdata, backgroundColor: tcolors, borderWidth: 0 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: { position:'bottom', labels: { color:'#94a3b8', padding:10, font:{ size:10 }, usePointStyle:true } }
        }
      }
    });
  }

  // Horizontal bar: top countries
  const countries = {};
  events.forEach(e => { const c = e.country || 'Bilinmiyor'; countries[c] = (countries[c]||0) + 1; });
  const sorted = Object.entries(countries).sort((a,b) => b[1]-a[1]).slice(0,10);
  const clabels = sorted.map(s => s[0]);
  const cdata = sorted.map(s => s[1]);
  const ctx3 = document.getElementById('countryChart')?.getContext('2d');
  if(!ctx3) return;
  if(countryChart){
    countryChart.data.labels = clabels;
    countryChart.data.datasets[0].data = cdata;
    countryChart.update();
  } else {
    countryChart = new Chart(ctx3, {
      type: 'bar',
      data: {
        labels: clabels,
        datasets: [{
          label: 'Olay sayisi',
          data: cdata,
          backgroundColor: CHART_COLORS.slice(0,10),
          borderRadius: 2,
          borderWidth: 0
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', stepSize: 1 }, beginAtZero: true },
          y: { grid: { display: false }, ticks: { color: '#e6eef8', font: { size: 11 } } }
        }
      }
    });
  }
}

// ——— Map (Leaflet) ———
let map = null;
let markersLayer = null;

function initMap(){
  if(typeof L === 'undefined') return;
  if(map) return;
  const container = document.getElementById('map');
  if(!container) return;
  map = L.map('map', { worldCopyJump: true }).setView([30, 20], 2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OSM &copy; CARTO'
  }).addTo(map);
  markersLayer = L.layerGroup().addTo(map);
  _mapInited = true;
}

function renderMap(events){
  if(typeof L === 'undefined') return;
  initMap();
  if(!markersLayer) return;
  markersLayer.clearLayers();
  const seen = {};
  events.forEach(e => {
    const lat = e.lat || e.latitude || null;
    const lon = e.lon || e.longitude || null;
    if(lat && lon){
      const key = `${lat.toFixed(1)}_${lon.toFixed(1)}`;
      seen[key] = (seen[key]||0) + 1;
      const color = ATTACK_COLORS[e.attack_type] || '#ef4444';
      const mk = L.circleMarker([lat, lon], {
        radius: Math.min(4 + seen[key], 14),
        color: color,
        fillColor: color,
        fillOpacity: 0.7,
        weight: 1
      });
      mk.bindPopup(`<b>${e.src_ip}</b><br><b>Tur:</b> ${e.attack_type||'-'}<br><b>Ulke:</b> ${e.country||'-'}<br><b>Detay:</b> ${e.details||'-'}`);
      markersLayer.addLayer(mk);
    }
  });
}

// ——— Stats ———
function renderStats(events){
  const el = id => document.getElementById(id);
  const statEvents = el('statEvents');
  const statBans = el('statBans');
  const statHoneypot = el('statHoneypot');
  const statRecent = el('statRecent');

  if(statEvents) statEvents.textContent = events.length;
  if(statBans) statBans.textContent = _bans.length;
  const honeypot = events.filter(e => (e.attack_type||'').toLowerCase().includes('honeypot')).length;
  if(statHoneypot) statHoneypot.textContent = honeypot;
  const recent = events.filter(e => new Date(e.timestamp) > Date.now() - 60000).length;
  if(statRecent) statRecent.textContent = recent;
}

// ——— Events table (with severity column) ———
function renderEventsTable(events){
  const tbody = document.querySelector('#eventsTable tbody');
  if(!tbody) return;
  tbody.innerHTML = '';
  const start = (currentPage-1)*perPage;
  const pageItems = events.slice(start, start+perPage);

  if(pageItems.length === 0){
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#64748b;padding:24px">Henuz olay yok</td></tr>';
  }

  for(const e of pageItems){
    const tr = document.createElement('tr');
    const color = ATTACK_COLORS[e.attack_type] || '#64748b';
    const sev = getSeverity(e.attack_type);
    const dotCls = sevDotClass(sev);
    tr.innerHTML = `
      <td><span class="sev-dot ${dotCls}"></span><span class="sev-text ${dotCls}">${sevLabel(sev)}</span></td>
      <td style="white-space:nowrap">${new Date(e.timestamp).toLocaleString('tr-TR')}</td>
      <td><span class="ip-link" data-ip="${e.src_ip}">${e.src_ip}</span></td>
      <td>${e.country || '-'}</td>
      <td><span class="attack-badge" style="background:${color}20;color:${color};border:1px solid ${color}40">${e.attack_type || '-'}</span></td>
      <td class="detail-cell">${e.details || '-'}</td>
      <td><button class="siem-btn danger ban-btn" data-ip="${e.src_ip}" style="padding:3px 8px;font-size:10px">BAN</button></td>
    `;
    tbody.appendChild(tr);
  }

  const pages = Math.max(1, Math.ceil(events.length / perPage));
  const pageInfo = document.getElementById('pageInfo');
  const prevBtn = document.getElementById('prevPage');
  const nextBtn = document.getElementById('nextPage');
  if(pageInfo) pageInfo.textContent = `${currentPage} / ${pages}`;
  if(prevBtn) prevBtn.disabled = currentPage <= 1;
  if(nextBtn) nextBtn.disabled = currentPage >= pages;

  // Ban buttons
  document.querySelectorAll('.ban-btn').forEach(b => b.addEventListener('click', async ev => {
    const ip = ev.currentTarget.dataset.ip;
    if(!ip) return;
    if(IS_DEMO){ showToast('Demo modu: Ban islemi devre disi','info'); return; }
    const ok = await showConfirm(`IP ${ip} banlansin mi?`);
    if(!ok) return;
    await banIp(ip, 'manual-ui');
  }));

  // IP click → lookup + switch to overview tab
  document.querySelectorAll('#eventsTable .ip-link').forEach(link => link.addEventListener('click', ()=>{
    const ip = link.dataset.ip;
    document.getElementById('lookupIp').value = ip;
    lookupIp(ip);
    // Switch to overview tab to show lookup
    const overviewTab = document.querySelector('.siem-tab[data-tab="overview"]');
    if(overviewTab) overviewTab.click();
  }));
}

// ——— Bans table ———
function renderBansTable(){
  const tbody = document.querySelector('#bansTable tbody');
  if(!tbody) return;
  tbody.innerHTML = '';
  if(_bans.length === 0){
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#64748b;padding:16px">Aktif ban yok</td></tr>';
  }
  _bans.forEach(b => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="white-space:nowrap">${b.timestamp ? new Date(b.timestamp).toLocaleString('tr-TR') : '-'}</td>
      <td><span class="ip-link" data-ip="${b.src_ip}">${b.src_ip}</span></td>
      <td>${b.reason||'-'}</td>
      <td><button class="siem-btn success unban-btn" data-ip="${b.src_ip}" style="padding:3px 8px;font-size:10px">UNBAN</button></td>
    `;
    tbody.appendChild(tr);
  });
  document.querySelectorAll('.unban-btn').forEach(btn => btn.addEventListener('click', async ev => {
    const ip = ev.currentTarget.dataset.ip;
    if(IS_DEMO){ showToast('Demo modu: Unban devre disi','info'); return; }
    const ok = await showConfirm(`IP ${ip} unban yapilsin mi?`);
    if(!ok) return;
    await unbanIp(ip);
  }));

  // Bans table IP click
  document.querySelectorAll('#bansTable .ip-link').forEach(link => link.addEventListener('click', () => {
    const ip = link.dataset.ip;
    document.getElementById('lookupIp').value = ip;
    lookupIp(ip);
    const overviewTab = document.querySelector('.siem-tab[data-tab="overview"]');
    if(overviewTab) overviewTab.click();
  }));
}

// ——— Ban / Unban API ———
async function banIp(ip, reason='manual-ui'){
  try{
    const res = await fetch('/api/ban', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip,reason}) });
    if(!res.ok) throw new Error('ban failed');
    showToast(`IP ${ip} banlandi`, 'success');
    await refreshAll();
  } catch(err){ showToast('Ban basarisiz','error'); }
}

async function unbanIp(ip){
  try{
    const res = await fetch('/api/unban', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip}) });
    if(!res.ok) throw new Error('unban failed');
    showToast(`IP ${ip} unban yapildi`, 'success');
    await refreshAll();
  } catch(err){ showToast('Unban basarisiz','error'); }
}

// ——— Main refresh ———
async function refreshAll(){
  await fetchEvents();
  await fetchBans();
  renderStats(_allEvents);
  updateSeverityBar(_allEvents);
  renderLiveFeed(_allEvents);
  renderCharts(_allEvents);
  renderMap(_allEvents);
  const filtered = applyFilters(_allEvents);
  const pages = Math.max(1, Math.ceil(filtered.length / perPage));
  if(currentPage > pages) currentPage = pages;
  renderEventsTable(filtered);
  renderBansTable();
}

// ——— Init ———
document.addEventListener('DOMContentLoaded', async () => {

  // Tab system
  initTabs();

  // Clock
  updateClock();
  setInterval(updateClock, 1000);

  // Pagination
  const prevBtn = document.getElementById('prevPage');
  const nextBtn = document.getElementById('nextPage');
  if(prevBtn) prevBtn.addEventListener('click', ()=>{ if(currentPage>1){ currentPage--; const f=applyFilters(_allEvents); renderEventsTable(f); } });
  if(nextBtn) nextBtn.addEventListener('click', ()=>{ const f=applyFilters(_allEvents); const p=Math.max(1,Math.ceil(f.length/perPage)); if(currentPage<p){ currentPage++; renderEventsTable(f); } });

  // Refresh button
  const refreshBtn = document.getElementById('refresh');
  if(refreshBtn) refreshBtn.addEventListener('click', ()=>{ refreshAll(); showToast('Yenilendi','success',1500); });

  // Search debounce
  let searchTimer;
  const searchEl = document.getElementById('search');
  if(searchEl) searchEl.addEventListener('input', ()=>{
    clearTimeout(searchTimer);
    searchTimer = setTimeout(()=>{ currentPage=1; const f=applyFilters(_allEvents); renderEventsTable(f); }, 250);
  });
  const typeFilterEl = document.getElementById('typeFilter');
  if(typeFilterEl) typeFilterEl.addEventListener('change', ()=>{ currentPage=1; const f=applyFilters(_allEvents); renderEventsTable(f); });

  // Ban form
  const banForm = document.getElementById('banForm');
  if(banForm){
    banForm.addEventListener('submit', async ev => {
      ev.preventDefault();
      const ip = document.getElementById('banIp').value.trim();
      const reason = document.getElementById('banReason').value.trim() || 'manual-ui';
      if(!ip) return showToast('IP giriniz','error');
      if(IS_DEMO){ showToast('Demo modu: Ban islemi devre disi','info'); banForm.reset(); return; }
      await banIp(ip, reason);
      banForm.reset();
    });
  }

  const clearBtn = document.getElementById('clearForm');
  if(clearBtn) clearBtn.addEventListener('click', ()=>{ if(banForm) banForm.reset(); });

  // Auto-refresh
  const autoEl = document.getElementById('autorefresh');
  if(autoEl){
    autoEl.addEventListener('change', ev => {
      if(ev.target.checked){
        poller = setInterval(refreshAll, 5000);
        showToast('Otomatik yenileme acildi','success',1500);
      } else {
        clearInterval(poller);
        poller = null;
        showToast('Otomatik yenileme kapatildi','info',1500);
      }
    });
  }

  // IP Lookup button + enter key
  const lookupBtn = document.getElementById('lookupBtn');
  const lookupInput = document.getElementById('lookupIp');
  if(lookupBtn) lookupBtn.addEventListener('click', ()=>{
    const ip = lookupInput?.value.trim();
    if(ip) lookupIp(ip);
    else showToast('IP adresi giriniz','error');
  });
  if(lookupInput) lookupInput.addEventListener('keydown', ev => {
    if(ev.key === 'Enter'){ ev.preventDefault(); lookupBtn?.click(); }
  });

  // ——— Initial load ———
  await refreshAll();

  if(IS_DEMO){
    const banCard = document.getElementById('banCard');
    if(banCard){ banCard.style.opacity='0.5'; banCard.style.pointerEvents='none'; }
    showToast('Demo modu etkin — yonetimsel islemler pasif','info',3000);
  }

  // SSE realtime stream
  if(window.EventSource){
    try{
      const es = new EventSource('/stream');
      es.onmessage = ev => {
        try{
          const obj = JSON.parse(ev.data);
          _allEvents.unshift(obj);
          const sev = getSeverity(obj.attack_type);
          showToast(`[${sevLabel(sev)}] ${obj.attack_type} — ${obj.src_ip}`, 'info', 3000);
          renderStats(_allEvents);
          updateSeverityBar(_allEvents);
          renderLiveFeed(_allEvents);
          renderCharts(_allEvents);
          renderMap(_allEvents);
          const filtered = applyFilters(_allEvents);
          renderEventsTable(filtered);
        } catch(err){ console.warn('stream parse', err); }
      };
      es.onerror = () => {
        console.warn('SSE baglanti kesildi');
        const badge = document.getElementById('statusBadge');
        if(badge){ badge.textContent = 'OFFLINE'; badge.className = 'siem-status offline'; }
      };
    } catch(err){ console.warn('SSE init failed', err); }
  }

  // Start auto-refresh (checked by default)
  poller = setInterval(refreshAll, 5000);
});
