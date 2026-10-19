import Clutter from 'gi://Clutter';
import GLib from 'gi://GLib';
import Pango from 'gi://Pango';
import St from 'gi://St';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import {Client} from './client.js';
import {modes, kinds, levels, sensors, sensorStates, banStates, summarize, filteredEvents, stamp} from './model.js';

function box(vertical = false, style = '') {
    return new St.BoxLayout({orientation: vertical ? Clutter.Orientation.VERTICAL : Clutter.Orientation.HORIZONTAL, style_class: style, x_expand: true});
}
function text(value, style = '', wrap = false) {
    const label = new St.Label({text: String(value), style_class: style, y_align: Clutter.ActorAlign.CENTER});
    if (wrap) {
        label.x_expand = true;
        label.clutter_text.line_wrap = true;
        label.clutter_text.line_wrap_mode = Pango.WrapMode.WORD_CHAR;
        label.clutter_text.ellipsize = Pango.EllipsizeMode.NONE;
    }
    return label;
}
function icon(name, size = 18, style = '') {
    return new St.Icon({icon_name: name, icon_size: size, style_class: style, y_align: Clutter.ActorAlign.CENTER});
}
function badge(value, tone = 'muted') { return text(value, `mo-badge mo-${tone}`); }
function button(label, callback, style = 'mo-button', iconName = null) {
    const actor = new St.Button({style_class: style, can_focus: true, accessible_name: label});
    const contents = box(false, 'mo-button-content');
    if (iconName) contents.add_child(icon(iconName, 16));
    contents.add_child(text(label));
    actor.set_child(contents);
    actor.connect('clicked', callback);
    return actor;
}

export default class MemOShield extends Extension {
    enable() {
        this._view = 'overview';
        this._filter = 'all';
        this._page = 0;
        this._data = null;
        this._selected = null;
        this._error = null;
        this._notice = '';
        this._settings = this.getSettings();
        this._button = new PanelMenu.Button(0.0, 'memOShield güvenlik kontrol merkezi');
        const panel = box(false, 'mo-panel');
        panel.add_child(icon('security-high-symbolic', 16));
        this._panelLabel = text('memOShield', 'mo-panel-name');
        this._panelCount = text('…', 'mo-panel-count');
        panel.add_child(this._panelLabel);
        panel.add_child(this._panelCount);
        this._button.add_child(panel);
        this._button.menu.box.add_style_class_name('mo-menu');
        this._root = box(true, 'mo-dashboard');
        this._button.menu.box.add_child(this._root);
        this._buildShell();
        Main.panel.addToStatusArea(this.uuid, this._button);
        this._button.menu.connect('open-state-changed', (_menu, open) => {
            if (open) { this._resize(); this._refresh(); }
        });
        this._settingsId = this._settings.connect('changed', () => { this.disable(); this.enable(); });
        try {
            this._client = new Client(this._settings.get_string('service-url'), this._settings.get_string('token-path'));
        } catch (error) { this._error = error.message; this._render(); return; }
        this._render();
        this._refresh();
        this._timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 15, () => {
            this._refresh();
            return GLib.SOURCE_CONTINUE;
        });
    }

    disable() {
        if (this._timer) GLib.Source.remove(this._timer);
        this._timer = null;
        if (this._settingsId) this._settings.disconnect(this._settingsId);
        this._settingsId = null;
        this._client?.close();
        this._client = null;
        this._button?.destroy();
        this._button = null;
        this._settings = null;
        this._data = null;
        this._busy = false;
        this._mutating = false;
    }

    _buildShell() {
        const header = box(false, 'mo-header');
        header.add_child(icon('security-high-symbolic', 32, 'mo-brand-icon'));
        const brand = box(true, 'mo-brand');
        brand.add_child(text('memOShield', 'mo-title'));
        brand.add_child(text('CİHAZ GÜVENLİĞİ / KONTROL MERKEZİ', 'mo-eyebrow'));
        header.add_child(brand);
        header.add_child(button('Yenile', () => this._refresh(), 'mo-icon-button', 'view-refresh-symbolic'));
        header.add_child(button('Ayarlar', () => this.openPreferences(), 'mo-icon-button', 'emblem-system-symbolic'));
        this._root.add_child(header);
        const nav = box(false, 'mo-nav');
        this._tabs = {};
        for (const [key, title, glyph] of [
            ['overview', 'Genel bakış', 'view-grid-symbolic'], ['events', 'Olaylar', 'view-list-symbolic'],
            ['sensors', 'Sensörler', 'network-wired-symbolic'], ['protection', 'Koruma', 'security-high-symbolic'],
        ]) {
            const tab = button(title, () => this._navigate(key), 'mo-tab', glyph);
            tab.x_expand = true;
            this._tabs[key] = tab;
            nav.add_child(tab);
        }
        this._root.add_child(nav);
        this._scroll = new St.ScrollView({x_expand: true, overlay_scrollbars: true, style_class: 'mo-scroll'});
        this._scroll.set_policy(St.PolicyType.NEVER, St.PolicyType.AUTOMATIC);
        this._body = box(true, 'mo-body');
        this._scroll.set_child(this._body);
        this._root.add_child(this._scroll);
        const footer = box(false, 'mo-footer');
        footer.add_child(icon('computer-symbolic', 14));
        const host = text(GLib.get_host_name(), 'mo-muted');
        host.x_expand = true;
        footer.add_child(host);
        this._updated = text('Bağlanıyor…', 'mo-muted');
        footer.add_child(this._updated);
        this._root.add_child(footer);
        this._resize();
    }

    _resize() {
        const monitor = Main.layoutManager.primaryMonitor;
        if (!monitor) return;
        const scale = St.ThemeContext.get_for_stage(global.stage).scale_factor;
        this._root.width = Math.min(760 * scale, monitor.width - 40 * scale);
        this._scroll.height = Math.max(160 * scale, Math.min(570 * scale, monitor.height - 240 * scale));
    }

    _navigate(view) {
        this._view = view;
        this._selected = null;
        this._notice = '';
        this._render();
        this._scroll.vadjustment.value = 0;
    }

    async _refresh() {
        if (!this._client || this._busy) return;
        const client = this._client;
        this._busy = true;
        try {
            const data = await client.snapshot();
            if (client !== this._client) return;
            this._data = data;
            this._error = null;
            this._lastUpdate = Date.now();
        } catch (error) {
            if (client !== this._client) return;
            this._error = error.message;
        } finally {
            if (client === this._client) { this._busy = false; this._render(); }
        }
    }

    _render() {
        if (!this._button) return;
        for (const [key, tab] of Object.entries(this._tabs)) {
            if (key === this._view) tab.add_style_pseudo_class('active');
            else tab.remove_style_pseudo_class('active');
        }
        this._body.destroy_all_children();
        this._panelCount.text = this._error ? '!' : this._data ? String(summarize(this._data).high) : '…';
        this._panelCount.style_class = `mo-panel-count${this._error || (this._data && summarize(this._data).high) ? ' mo-panel-alert' : ''}`;
        this._updated.text = this._lastUpdate ? `${this._error ? 'Son veri' : 'Güncellendi'} ${new Date(this._lastUpdate).toLocaleTimeString('tr-TR')} · 15 sn` : 'Yerel servis bekleniyor';
        if (this._error) this._banner('Servis bağlantısı kesildi', 'Aşağıdaki bilgiler güncel olmayabilir. Servisi ve bağlantı ayarlarını kontrol et.', 'danger', 'network-offline-symbolic');
        if (this._notice) this._banner('İşlem sonucu', this._notice, this._noticeError ? 'warning' : 'blue', 'dialog-information-symbolic');
        if (!this._data) {
            this._empty(this._error ? 'Yerel servise bağlanılamadı' : 'Kontrol merkezi hazırlanıyor', this._error || 'Sensör durumları ve gerçek olay kayıtları alınıyor.', 'network-offline-symbolic');
            if (this._error) this._body.add_child(button('Bağlantı ayarlarını aç', () => this.openPreferences(), 'mo-button mo-primary'));
            return;
        }
        if (this._selected) { this._eventDetail(); return; }
        if (this._view === 'overview') this._overview();
        else if (this._view === 'events') this._events();
        else if (this._view === 'sensors') this._sensors();
        else this._protection();
    }

    _heading(title, subtitle, action = null) {
        const row = box(false, 'mo-section-heading');
        const labels = box(true);
        labels.add_child(text(title, 'mo-section-title'));
        if (subtitle) labels.add_child(text(subtitle, 'mo-muted', true));
        row.add_child(labels);
        if (action) row.add_child(action);
        this._body.add_child(row);
    }

    _banner(title, description, tone, glyph) {
        const row = box(false, `mo-banner mo-banner-${tone}`);
        row.add_child(icon(glyph, 24));
        const labels = box(true, 'mo-banner-copy');
        labels.add_child(text(title, 'mo-banner-title'));
        labels.add_child(text(description, 'mo-description', true));
        row.add_child(labels);
        this._body.add_child(row);
    }

    _empty(title, description, glyph = 'view-list-symbolic') {
        const panel = box(true, 'mo-empty');
        panel.add_child(icon(glyph, 32, 'mo-empty-icon'));
        panel.add_child(text(title, 'mo-section-title'));
        panel.add_child(text(description, 'mo-description', true));
        this._body.add_child(panel);
    }

    _overview() {
        const {status, events} = this._data;
        const summary = summarize(this._data);
        const monitor = status.mode === 'monitor';
        const warnings = Object.values(status.sensors).filter(sensor => ['warning', 'error'].includes(sensor.state)).length;
        const title = summary.high ? `${summary.high} yüksek önem olayı inceleme bekliyor` : warnings ? 'Sensörlerden biri kontrol gerektiriyor' : monitor ? 'Olayları izliyorsun' : 'Koruma kararlarını takip ediyorsun';
        this._banner(title, monitor ? 'İzleme modu açık. Olaylar kaydedilir; IP adresleri otomatik engellenmez.' : `${modes[status.mode]}. ${summary.confirmed} süreli engel son 30 saniyedeki firewall durumuyla doğrulandı.`, summary.high || warnings ? 'warning' : 'blue', 'security-high-symbolic');
        const metrics = box(false, 'mo-metrics');
        for (const [value, label, hint, tone, glyph, target] of [
            [events.length, 'OLAY', 'En yeni 200 kayıt', 'blue', 'view-list-symbolic', 'events'],
            [summary.high, 'YÜKSEK ÖNEM', 'İncelenecek kayıt', 'warning', 'dialog-warning-symbolic', 'events'],
            [summary.sensorCount, 'VERİ KAYNAĞI', 'SSH / ağ · en fazla 2', 'teal', 'network-wired-symbolic', 'sensors'],
            [this._error ? '—' : summary.confirmed, 'DOĞRULANMIŞ ENGEL', monitor ? 'İzleme modunda kapalı' : 'Son 30 sn doğrulaması', 'purple', 'security-high-symbolic', 'protection'],
        ]) {
            const tile = new St.Button({style_class: `mo-metric mo-metric-${tone}`, x_expand: true, can_focus: true, accessible_name: `${label}: ${value}`});
            const contents = box(true, 'mo-metric-content');
            const top = box(false);
            const name = text(label, 'mo-metric-label'); name.x_expand = true;
            top.add_child(name); top.add_child(icon(glyph, 16));
            contents.add_child(top);
            contents.add_child(text(value, `mo-metric-value mo-text-${tone}`));
            contents.add_child(text(hint, 'mo-metric-hint', true));
            tile.set_child(contents);
            tile.connect('clicked', () => { this._filter = label === 'YÜKSEK ÖNEM' ? 'high' : 'all'; this._page = 0; this._navigate(target); });
            metrics.add_child(tile);
        }
        this._body.add_child(metrics);
        this._chart(summary);
        this._heading('Son hareketler', 'Ne oldu, nereden geldi?', button('Tüm olaylar', () => this._navigate('events'), 'mo-link'));
        if (!events.length) {
            this._empty('Henüz kayıt gelmedi', 'Bu, cihazın güvenli olduğunun kanıtı değildir. SSH günlük erişimini ve ağ sensörünü kontrol edebilirsin.', 'document-find-symbolic');
            this._body.add_child(button('Sensörleri kontrol et', () => this._navigate('sensors'), 'mo-button', 'network-wired-symbolic'));
        } else for (const event of events.slice(0, 3)) this._eventRow(event);
    }

    _chart(summary) {
        const card = box(true, 'mo-chart-card');
        const heading = box(false);
        const title = text('Olay aktivitesi', 'mo-section-title'); title.x_expand = true;
        heading.add_child(title);
        heading.add_child(badge(`${summary.chartTotal} olay · 24 saat`, 'blue'));
        card.add_child(heading);
        card.add_child(text('En yeni 200 kayıt içindeki saatlik dağılım', 'mo-muted'));
        const plot = new St.DrawingArea({style_class: 'mo-chart', x_expand: true, accessible_name: `Son 24 saatlik saat dilimlerinde ${summary.chartTotal} olay`});
        plot.connect('repaint', area => {
            const cr = area.get_context();
            const [width, height] = area.get_surface_size();
            try {
                const max = Math.max(1, ...summary.bins.map(bin => bin.all));
                cr.setSourceRGBA(0.35, 0.43, 0.55, 0.22);
                cr.setLineWidth(1);
                for (let i = 0; i < 4; i++) { const y = 6 + (height - 12) * i / 3; cr.moveTo(0, y); cr.lineTo(width, y); }
                cr.stroke();
                const step = width / 24;
                summary.bins.forEach((bin, i) => {
                    if (!bin.all) return;
                    const h = bin.all / max * (height - 16);
                    cr.setSourceRGBA(0.34, 0.62, 1, 0.85);
                    cr.rectangle(i * step + 3, height - 6 - h, Math.max(1, step - 6), h); cr.fill();
                    if (bin.high) {
                        const high = bin.high / max * (height - 16);
                        cr.setSourceRGBA(1, 0.66, 0.31, 1);
                        cr.rectangle(i * step + 3, height - 6 - high, Math.max(1, step - 6), high); cr.fill();
                    }
                });
            } finally { cr.$dispose(); }
        });
        card.add_child(plot);
        const legend = box(false, 'mo-chart-legend');
        const start = new Date(summary.start).toLocaleTimeString('tr-TR', {hour: '2-digit', minute: '2-digit'});
        legend.add_child(text(start, 'mo-muted'));
        const center = text(summary.chartTotal ? '● Tüm olaylar     ● Yüksek önem: turuncu' : 'Gerçek olay geldiğinde grafik oluşacak', 'mo-muted');
        center.x_expand = true; center.x_align = Clutter.ActorAlign.CENTER;
        legend.add_child(center); legend.add_child(text('Şimdi', 'mo-muted'));
        card.add_child(legend);
        this._body.add_child(card);
    }

    _eventRow(event) {
        const [level, tone] = levels[event.severity] || ['Bilgi', 'muted'];
        const row = new St.Button({style_class: 'mo-event', can_focus: true, x_expand: true, accessible_name: `${level}: ${kinds[event.kind] || event.kind}, ${event.source_ip}`});
        const contents = box(false, 'mo-event-content');
        contents.add_child(icon(event.source === 'journal' ? 'utilities-terminal-symbolic' : 'network-wired-symbolic', 22, `mo-text-${tone}`));
        const copy = box(true, 'mo-event-copy');
        copy.add_child(text(kinds[event.kind] || event.kind, 'mo-event-title'));
        copy.add_child(text(`${event.source_ip}  →  ${event.target_ip || 'Bu bilgisayar'}${event.port ? `:${event.port}` : ''}`, 'mo-monospace'));
        contents.add_child(copy);
        contents.add_child(badge(level, tone));
        contents.add_child(text(new Date(event.time).toLocaleTimeString('tr-TR', {hour: '2-digit', minute: '2-digit'}), 'mo-muted'));
        contents.add_child(icon('go-next-symbolic', 14));
        row.set_child(contents);
        row.connect('clicked', () => { this._selected = event; this._render(); this._scroll.vadjustment.value = 0; });
        this._body.add_child(row);
    }

    _events() {
        this._heading('Olay inceleme', 'Bir kayda tıklayarak kanıtı ve kullanılabilir işlemleri aç.');
        const filters = box(false, 'mo-filters');
        for (const [value, label] of [['all', 'Tümü'], ['high', 'Yüksek önem'], ['journal', 'SSH'], ['suricata', 'Ağ']]) {
            const control = button(label, () => { this._filter = value; this._page = 0; this._render(); }, 'mo-filter');
            if (this._filter === value) control.add_style_pseudo_class('active');
            filters.add_child(control);
        }
        this._body.add_child(filters);
        const rows = filteredEvents(this._data.events, this._filter);
        const pages = Math.max(1, Math.ceil(rows.length / 8));
        this._page = Math.min(this._page, pages - 1);
        if (!rows.length) this._empty('Bu görünümde olay yok', 'Filtreyi değiştirebilir veya Sensörler bölümünden veri kaynaklarını kontrol edebilirsin.');
        for (const event of rows.slice(this._page * 8, (this._page + 1) * 8)) this._eventRow(event);
        const pagination = box(false, 'mo-pagination');
        const previous = button('Önceki', () => { this._page--; this._render(); }, 'mo-button', 'go-previous-symbolic');
        previous.reactive = this._page > 0;
        pagination.add_child(previous);
        const count = text(`${rows.length} kayıt · ${this._page + 1} / ${pages}`, 'mo-muted'); count.x_expand = true; count.x_align = Clutter.ActorAlign.CENTER;
        pagination.add_child(count);
        const next = button('Sonraki', () => { this._page++; this._render(); }, 'mo-button', 'go-next-symbolic'); next.reactive = this._page < pages - 1;
        pagination.add_child(next);
        this._body.add_child(pagination);
        this._body.add_child(text('En yeni 200 kayıt gösterilir. IP adresi bir kişinin kimliği değildir.', 'mo-footnote', true));
    }

    _eventDetail() {
        const event = this._selected;
        this._body.add_child(button('Listeye dön', () => { this._selected = null; this._render(); }, 'mo-link', 'go-previous-symbolic'));
        this._heading(kinds[event.kind] || event.kind, stamp(event.time));
        const panel = box(true, 'mo-card');
        for (const [key, value] of [['Kaynak IP', event.source_ip], ['Hedef', event.target_ip || 'Bu bilgisayar'], ['Port', event.port || 'Kayıtta yok'], ['Kullanıcı', event.user || 'Kayıtta yok'], ['Kaynak', event.source === 'journal' ? 'SSH günlüğü' : 'Suricata'], ['Önem', (levels[event.severity] || ['Bilgi'])[0]]]) {
            const row = box(false, 'mo-detail-row');
            const label = text(key, 'mo-muted'); label.x_expand = true;
            row.add_child(label); row.add_child(text(value, 'mo-event-title'));
            panel.add_child(row);
        }
        this._body.add_child(panel);
        this._heading('Kaynak kaydı / kanıt', 'Kayıt içeriği olduğu gibi metin olarak gösterilir.');
        this._body.add_child(text(event.evidence, 'mo-evidence', true));
        const actions = box(false, 'mo-actions');
        actions.add_child(button('IP’yi kopyala', () => { St.Clipboard.get_default().set_text(St.ClipboardType.CLIPBOARD, event.source_ip); this._notice = 'IP adresi kopyalandı.'; this._noticeError = false; this._render(); }, 'mo-button', 'edit-copy-symbolic'));
        const trust = button('Güvenilir yap', () => this._mutate('allowlist', {prefix: event.source_ip, add: true}, 'IP güvenilir listeye eklendi.'), 'mo-button');
        trust.reactive = !this._error && !this._mutating; actions.add_child(trust);
        if (this._data.status.mode !== 'monitor') {
            const ban = button('10 dk engelle', () => this._mutate('ban', {ip: event.source_ip, minutes: 10, reason: 'GNOME kontrol merkezinden kullanıcı kararı'}, 'Süreli engel uygulandı ve doğrulandı.'), 'mo-button mo-destructive');
            ban.reactive = !this._error && !this._mutating; actions.add_child(ban);
        }
        this._body.add_child(actions);
        if (this._data.status.mode === 'monitor') this._body.add_child(text('İzleme modunda engelleme kapalıdır. Koruma bölümünde kurulum durumunu görebilirsin.', 'mo-footnote', true));
    }

    _sensors() {
        this._heading('Neyi görebiliyorsun?', 'Her kart bir veri kaynağını ve ne yapman gerektiğini açıklar.');
        for (const [key, [title, glyph, description]] of Object.entries(sensors)) {
            const state = this._data.status.sensors[key] || {state: 'disabled', detail: 'Durum henüz alınmadı.'};
            const [label, tone] = sensorStates[state.state] || [state.state, 'muted'];
            const card = box(true, 'mo-card');
            const header = box(false, 'mo-card-heading');
            header.add_child(icon(glyph, 24, `mo-text-${tone}`));
            const heading = text(title, 'mo-section-title'); heading.x_expand = true;
            header.add_child(heading); header.add_child(badge(label, tone));
            card.add_child(header);
            card.add_child(text(description, 'mo-description', true));
            card.add_child(text(state.detail || '', 'mo-sensor-detail', true));
            if (state.state === 'disabled' || state.state === 'error' || state.state === 'warning') {
                const advice = {journal: 'Yapılacak: SSH günlük okuma izinlerini kontrol et.', suricata: 'Yapılacak: Suricata’yı kur ve serviste MEMOSHIELD_EVE_PATH yolunu ayarla.', firewall: this._data.status.mode === 'monitor' ? 'İzleme modunda bu normaldir. Engelleme için firewall yardımcısı ve manual/auto modu gerekir.' : 'Yapılacak: memoshield-firewall servisini ve son hata mesajını kontrol et.', database: 'Yapılacak: Veri dizininin erişim izinlerini ve disk alanını kontrol et.'};
                card.add_child(text(advice[key], 'mo-footnote', true));
            }
            card.add_child(text(`Son durum: ${stamp(state.updated)}`, 'mo-muted'));
            this._body.add_child(card);
        }
        this._body.add_child(text('“Veri bekliyor” saldırı olmadığı anlamına gelmez. Normal Wi-Fi bağlantısı diğer iki cihazın trafiğini genellikle göstermez.', 'mo-footnote', true));
    }

    _protection() {
        const {status} = this._data;
        const summary = summarize(this._data);
        const monitor = status.mode === 'monitor';
        this._banner(modes[status.mode] || status.mode, monitor ? 'Şu an yalnızca izleme yapılıyor. Bu eklenti çalışma modunu kendiliğinden değiştirmez.' : 'Burada süreli engelleme talepleri ve son uygulama sonuçları gösterilir.', 'blue', 'security-high-symbolic');
        if (monitor) {
            const setup = box(true, 'mo-card');
            setup.add_child(text('Engellemeyi açmak için', 'mo-section-title'));
            setup.add_child(text('1. memoshield-fw yardımcı sürecini kur.\n2. Kullanıcı servisini MEMOSHIELD_MODE=manual ile yeniden başlat.\n3. Olay detayından IP seçerek süreli engel uygula.', 'mo-description', true));
            setup.add_child(text('Ayrıntılı kurulum: memOShield/docs/deployment.md', 'mo-footnote', true));
            this._body.add_child(setup);
        }
        this._heading('Süresi dolmamış talepler', `${summary.active.length} talep · ${this._error ? 'Doğrulama bilgisi güncel değil' : `${summary.confirmed} yakın zamanda doğrulanmış engel`}`);
        if (!summary.active.length) this._empty('Engelleme talebi yok', 'Bir olayın detayından süreli engelleme kararı verebilirsin.', 'security-high-symbolic');
        for (const ban of summary.active) {
            const card = box(true, 'mo-card');
            const header = box(false, 'mo-card-heading');
            const ip = text(ban.ip, 'mo-section-title'); ip.x_expand = true;
            header.add_child(ip); header.add_child(badge(banStates[ban.state] || ban.state, ban.state === 'applied' ? 'blue' : 'warning'));
            card.add_child(header);
            card.add_child(text(ban.reason, 'mo-description', true));
            card.add_child(text(`Bitiş: ${stamp(ban.expires)}\nSon doğrulama: ${stamp(ban.confirmed)}`, 'mo-muted', true));
            if (ban.error) card.add_child(text(ban.error, 'mo-footnote', true));
            if (!monitor) {
                const cancel = button('Talebi kaldır / iptal et', () => this._mutate('unban', {ip: ban.ip}, 'Engelleme talebi kaldırıldı.'), 'mo-button');
                cancel.reactive = !this._error && !this._mutating; card.add_child(cancel);
            }
            this._body.add_child(card);
        }
        this._body.add_child(text('İzleme moduna geçmek daha önce uygulanmış kernel engellerini hemen kaldırmaz; süreleri dolabilir. Durum son başarılı uzlaştırmayı gösterir.', 'mo-footnote', true));
    }

    async _mutate(path, body, success) {
        if (!this._client || this._mutating || this._error) return;
        const client = this._client;
        this._mutating = true;
        this._notice = 'İşlem uygulanıyor…'; this._noticeError = false; this._render();
        try {
            await client.api(path, body);
            if (client !== this._client) return;
            await this._refresh();
            this._notice = success;
        } catch (error) {
            if (client !== this._client) return;
            this._notice = error.message; this._noticeError = true;
        } finally {
            if (client === this._client) { this._mutating = false; this._render(); }
        }
    }
}
