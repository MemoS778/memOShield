import GLib from 'gi://GLib';
import St from 'gi://St';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Client} from './client.js';

const modes = {monitor: 'İzleme', manual: 'Manuel koruma', auto: 'Otomatik koruma'};
const sensorNames = {journal: 'SSH günlüğü', suricata: 'Suricata', firewall: 'Firewall', database: 'Olay deposu'};
const sensorStates = {disabled: 'Kapalı', watching: 'İzleniyor', receiving: 'Veri alınıyor', ready: 'Hazır', warning: 'Kontrol et', error: 'Hata'};
const kinds = {ssh_failed: 'Başarısız SSH', ssh_success: 'Başarılı SSH', ssh_bruteforce: 'Tekrarlanan SSH hataları', network_alert: 'Ağ uyarısı'};

export default class MemOShield extends Extension {
    enable() {
        this._settings = this.getSettings();
        this._button = new PanelMenu.Button(0.0, 'memOShield Personal');
        this._label = new St.Label({text: 'memOShield · …', style_class: 'memoshield-panel-label'});
        this._button.add_child(this._label);
        this._status = new PopupMenu.PopupMenuItem('Yerel servise bağlanıyor…', {reactive: false});
        this._button.menu.addMenuItem(this._status);
        this._notice = new PopupMenu.PopupMenuItem('Veriler bu bilgisayarda tutulur.', {reactive: false});
        this._button.menu.addMenuItem(this._notice);
        this._content = new PopupMenu.PopupMenuSection();
        this._button.menu.addMenuItem(this._content);
        this._button.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this._button.menu.addAction('Şimdi yenile', () => this._refresh());
        this._button.menu.addAction('Eklenti ayarları', () => this.openPreferences());
        Main.panel.addToStatusArea(this.uuid, this._button);
        this._settingsId = this._settings.connect('changed', () => { this.disable(); this.enable(); });
        try {
            this._client = new Client(this._settings.get_string('service-url'), this._settings.get_string('token-path'));
        } catch (error) {
            this._status.label.text = error.message;
            this._label.text = 'memOShield · Ayar gerekli';
            return;
        }
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
        this._busy = false;
        this._mutating = false;
    }

    async _refresh() {
        if (!this._client || this._busy) return;
        const client = this._client;
        this._busy = true;
        try {
            const data = await client.snapshot();
            if (client !== this._client) return;
            this._render(data);
        } catch (error) {
            if (client !== this._client) return;
            this._label.text = 'memOShield · Bağlantı yok';
            this._status.label.text = 'Servise ulaşılamıyor; koruma durumu bilinmiyor.';
            this._notice.label.text = error.message.slice(0, 180);
            this._content.removeAll();
            this._text(this._content, 'memoshield-personal kullanıcı servisini kontrol et.');
        } finally {
            if (client === this._client) this._busy = false;
        }
    }

    _text(menu, text) {
        const item = new PopupMenu.PopupMenuItem(text, {reactive: false});
        item.label.add_style_class_name('memoshield-detail');
        menu.addMenuItem(item);
    }

    _render({status, events, bans}) {
        const mode = modes[status.mode] || status.mode;
        const high = events.filter(event => event.severity === 'high').length;
        this._label.text = `memOShield · ${mode}${high ? ` · ${high}!` : ''}`;
        this._status.label.text = `${mode} · ${events.length} görünür olay / en yeni 200`;
        this._notice.label.text = `Son güncelleme: ${GLib.DateTime.new_now_local().format('%H:%M:%S')}`;
        this._content.removeAll();
        const sensors = new PopupMenu.PopupSubMenuMenuItem('Sensör durumları');
        for (const [name, sensor] of Object.entries(status.sensors)) {
            this._text(sensors.menu, `${sensorNames[name] || name}: ${sensorStates[sensor.state] || sensor.state}`);
            if (sensor.detail) this._text(sensors.menu, sensor.detail.slice(0, 180));
        }
        this._content.addMenuItem(sensors);
        this._content.addMenuItem(new PopupMenu.PopupSeparatorMenuItem('Son 5 olay'));
        if (!events.length) this._text(this._content, 'Henüz olay yok. Gerçek sensör verisi bekleniyor.');
        for (const event of events.slice(0, 5)) {
            const item = new PopupMenu.PopupSubMenuMenuItem(`${event.severity === 'high' ? '! ' : ''}${event.source_ip} · ${kinds[event.kind] || event.kind}`);
            this._text(item.menu, new Date(event.time).toLocaleString());
            this._text(item.menu, event.evidence.slice(0, 400));
            item.menu.addAction('IP adresini kopyala', () => St.Clipboard.get_default().set_text(St.ClipboardType.CLIPBOARD, event.source_ip));
            item.menu.addAction('Güvenilir listeye ekle', () => this._mutate('allowlist', {prefix: event.source_ip, add: true}, 'IP güvenilir listeye eklendi.'));
            if (status.mode !== 'monitor') {
                item.menu.addAction('Bu IP’yi 10 dakika engelle', () => this._mutate('ban', {ip: event.source_ip, minutes: 10, reason: 'GNOME eklentisinden kullanıcı kararı'}, 'Süreli engel doğrulandı.'));
            }
            this._content.addMenuItem(item);
        }
        const active = bans.filter(ban => ban.desired && new Date(ban.expires).getTime() > Date.now());
        const decisions = new PopupMenu.PopupSubMenuMenuItem(`Engelleme kararları (${active.length})`);
        if (!active.length) this._text(decisions.menu, 'Süresi dolmamış engelleme talebi yok.');
        for (const ban of active) {
            const item = new PopupMenu.PopupSubMenuMenuItem(`${ban.ip} · ${ban.state}`);
            this._text(item.menu, `Bitiş: ${new Date(ban.expires).toLocaleString()}`);
            if (ban.error) this._text(item.menu, ban.error.slice(0, 180));
            if (status.mode !== 'monitor') item.menu.addAction('Talebi kaldır / iptal et', () => this._mutate('unban', {ip: ban.ip}, 'Engelleme talebi kaldırıldı.'));
            decisions.menu.addMenuItem(item);
        }
        this._content.addMenuItem(decisions);
        if (status.mode === 'monitor') this._text(this._content, 'İzleme modu: yeni engel uygulanmaz.');
        this._text(this._content, 'Durum 15 saniyede bir yenilenir; sürekli doğrulama değildir.');
    }

    async _mutate(path, body, success) {
        if (!this._client || this._mutating) return;
        const client = this._client;
        this._mutating = true;
        try {
            await client.api(path, body);
            if (client !== this._client) return;
            await this._refresh();
            if (client === this._client) this._notice.label.text = success;
        } catch (error) {
            if (client === this._client) this._notice.label.text = error.message.slice(0, 180);
        } finally {
            if (client === this._client) this._mutating = false;
        }
    }
}
