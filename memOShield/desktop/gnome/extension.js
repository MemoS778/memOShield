import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import St from 'gi://St';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Client} from './client.js';

export default class MemOShield extends Extension {
    enable() {
        this._settings = this.getSettings();
        this._button = new PanelMenu.Button(0, 'memOShield');
        this._button.add_child(new St.Icon({icon_name: 'security-high-symbolic', style_class: 'system-status-icon'}));
        this._status = new PopupMenu.PopupMenuItem('Servise bağlanılıyor…', {reactive: false});
        this._button.menu.addMenuItem(this._status);
        this._button.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this._recent = [];
        for (let i = 0; i < 3; i++) {
            const row = new PopupMenu.PopupMenuItem('');
            row.connect('activate', () => this._open());
            row.visible = false; this._recent.push(row); this._button.menu.addMenuItem(row);
        }
        const open = new PopupMenu.PopupMenuItem('memOShield’ı aç');
        open.connect('activate', () => this._open());
        this._button.menu.addMenuItem(open);
        Main.panel.addToStatusArea(this.uuid, this._button);
        this._client = new Client(this._settings.get_string('socket-path'), this._settings.get_string('token-path'));
        this._refresh();
        this._timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 15, () => { this._refresh(); return GLib.SOURCE_CONTINUE; });
    }
    _open() {
        const app = Gio.DesktopAppInfo.new('io.github.MemoS778.memOShield.desktop');
        if (!app) { Main.notify('memOShield', 'Masaüstü uygulaması kurulu değil. desktop/install.sh ile kurun.'); return; }
        try { app.launch([], global.create_app_launch_context(0, -1)); }
        catch (error) { Main.notify('memOShield', error.message); }
    }
    async _refresh() {
        if (this._busy) return;
        this._busy = true;
        try {
            const data = await this._client.snapshot();
            if (!this._button) return;
            this._status.label.text = `memOShield · ${data.status.mode}`;
            this._recent.forEach((row, i) => {
                const event = data.events[i]; row.visible = !!event;
                if (event) row.label.text = `${event.kind} · ${event.source_ip || 'yerel olay'}`;
            });
        } catch (error) {
            if (this._button) {
                this._status.label.text = 'Servise ulaşılamıyor';
                this._recent.forEach(row => { row.visible = false; });
            }
        } finally { this._busy = false; }
    }
    disable() {
        if (this._timer) GLib.Source.remove(this._timer);
        this._timer = null; this._client?.close(); this._client = null;
        this._button?.destroy(); this._button = null; this._settings = null;
    }
}
