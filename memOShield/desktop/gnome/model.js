// Shared presentation logic; all counts describe the API's newest-200 snapshot.
export const modes = {monitor: 'İzleme modu', manual: 'Manuel koruma', auto: 'Otomatik koruma'};
export const kinds = {ssh_failed: 'Başarısız SSH girişi', ssh_success: 'Başarılı SSH oturumu', ssh_bruteforce: 'Tekrarlanan parola hataları', network_alert: 'Ağ sensörü uyarısı'};
export const levels = {high: ['Yüksek', 'danger'], medium: ['Orta', 'warning'], low: ['Düşük', 'blue'], info: ['Bilgi', 'muted']};
export const banStates = {applied: 'Son uygulama doğrulandı', pending: 'Uygulama bekleniyor', unconfirmed: 'Doğrulanamadı', removed: 'Kaldırıldı', expired: 'Süresi doldu'};
export const sensors = {
    journal: ['SSH oturumları', 'utilities-terminal-symbolic', 'Bilgisayarına yapılan SSH girişlerini takip eder.'],
    suricata: ['Ağ uyarıları', 'network-wired-symbolic', 'Suricata tarafından üretilen ağ uyarılarını okur.'],
    firewall: ['IP engelleme', 'security-high-symbolic', 'Süreli engellerin işletim sistemine uygulanmasını izler.'],
    database: ['Yerel kayıtlar', 'drive-harddisk-symbolic', 'Olay geçmişini bu bilgisayarda saklar.'],
};
export const sensorStates = {disabled: ['Kapalı', 'muted'], watching: ['Veri bekliyor', 'blue'], receiving: ['Veri alıyor', 'good'], ready: ['Hazır', 'good'], warning: ['Kontrol gerekli', 'warning'], error: ['Erişim sorunu', 'danger']};

export function summarize(data, now = Date.now()) {
    const hour = 3600000;
    const start = Math.floor(now / hour) * hour - 23 * hour;
    const bins = Array.from({length: 24}, () => ({all: 0, high: 0}));
    for (const event of data.events) {
        const stamp = new Date(event.time).getTime();
        const i = Math.floor((stamp - start) / hour);
        if (i >= 0 && i < 24 && stamp <= now) {
            bins[i].all++;
            if (event.severity === 'high') bins[i].high++;
        }
    }
    const active = data.bans.filter(ban => ban.desired && new Date(ban.expires).getTime() > now);
    const firewall = data.status.sensors.firewall;
    const age = now - new Date(firewall?.updated).getTime();
    const confirmed = data.status.mode !== 'monitor' && firewall?.state === 'ready' && age >= 0 && age <= 30000;
    return {
        bins, start, active,
        high: data.events.filter(event => event.severity === 'high').length,
        sources: new Set(data.events.map(event => event.source_ip).filter(Boolean)).size,
        confirmed: confirmed ? active.filter(ban => ban.state === 'applied').length : 0,
        chartTotal: bins.reduce((sum, bin) => sum + bin.all, 0),
        sensorCount: ['journal', 'suricata'].filter(key => ['watching', 'receiving'].includes(data.status.sensors[key]?.state)).length,
    };
}

export function filteredEvents(events, filter) {
    if (filter === 'high') return events.filter(event => event.severity === 'high');
    if (filter === 'journal' || filter === 'suricata') return events.filter(event => event.source === filter);
    return events;
}

export function stamp(value) {
    if (!value || value.startsWith('0001-')) return 'Henüz yok';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Bilinmiyor' : date.toLocaleString('tr-TR');
}
