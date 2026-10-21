#!/usr/bin/gjs -m
import Adw from 'gi://Adw?version=1';
import Gtk from 'gi://Gtk?version=4.0';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gdk from 'gi://Gdk?version=4.0';
import System from 'system';
import {Client} from '../gnome/client.js';

const app = new Adw.Application({application_id: 'io.github.MemoS778.memOShield'});
let win, client, timer, content, status, page = 'overview', busy = false;
let smokeFailed = false;
const names = {overview: 'Genel bakış', changes: 'Değişiklikler', events: 'Olay geçmişi', protection: 'Koruma', settings: 'Ayarlar'};
const label = (text, style = '', wrap = false) => {
    const w = new Gtk.Label({label: String(text), xalign: 0, wrap, selectable: true});
    if (style) w.add_css_class(style);
    return w;
};
const box = (spacing = 12) => new Gtk.Box({orientation: Gtk.Orientation.VERTICAL, spacing});
function button(text, action) {
    const w = new Gtk.Button({label: text});
    w.connect('clicked', action);
    return w;
}
function clear(w) { while (w.get_first_child()) w.remove(w.get_first_child()); }
function card(title, detail) {
    const w = box(); w.add_css_class('shield-card');
    w.append(label(title, 'heading', true));
    if (detail) w.append(label(detail, 'dim-label', true));
    content.append(w); return w;
}
async function mutate(route, body) {
    try { await client.api(route, body); await refresh(); }
    catch (error) { status.label = error.message; }
}
function eventCard(event, mode) {
    const c = card(event.kind === 'ssh_failed' ? 'Başarısız SSH girişi' : event.kind === 'ssh_success' ? 'Başarılı SSH girişi' : event.kind === 'ssh_bruteforce' ? 'Tekrarlanan SSH parola hataları' : 'Ağ uyarısı', event.evidence);
    if (event.severity === 'high') c.add_css_class('critical');
    c.append(label(`${new Date(event.time).toLocaleString('tr-TR')} · ${event.source} · ${event.source_ip || '—'}`, 'monospace', true));
    if (event.source_ip) {
        const actions = new Gtk.Box({spacing: 8});
        actions.append(button('Güvenilir listeye ekle', () => mutate('allowlist', {prefix: event.source_ip, add: true})));
        const block = button('10 dakika engelle', () => mutate('ban', {ip: event.source_ip, reason: 'Masaüstü uygulamasından kullanıcı kararı', minutes: 10}));
        block.sensitive = mode !== 'monitor'; actions.append(block); c.append(actions);
    }
    return c;
}
function exportEvents(events) {
    const dialog = new Gtk.FileDialog({title: 'Olayları JSON olarak kaydet', initial_name: 'memoshield-events.json'});
    dialog.save(win, null, (source, result) => {
        try {
            const file = source.save_finish(result);
            file.replace_contents(new TextEncoder().encode(JSON.stringify(events, null, 2)), null, false, Gio.FileCreateFlags.PRIVATE, null);
            if (win) status.label = `${events.length} olay kaydedildi. Dosya IP ve günlük kanıtları içerir.`;
        } catch (error) {
            if (win && !error.matches(Gtk.DialogError, Gtk.DialogError.DISMISSED)) status.label = error.message;
        }
    });
}
async function refresh() {
    if (busy || !win) return;
    busy = true;
    try {
        const data = await client.snapshot();
        if (!win) return;
        status.label = `YEREL İZLEME · ${data.status.mode.toUpperCase()} · ${new Date().toLocaleTimeString('tr-TR')}`;
        clear(content);
        content.append(label(names[page], 'page-title'));
        if (page === 'changes') {
            card('Değişiklik izleme hazırlanıyor', 'Envanter ve yeni dinleme noktalarının tespiti henüz uygulanmadı. Bu ekran sistemin değişmediğini veya güvenli olduğunu göstermez.');
        } else if (page === 'events') {
            const search = new Gtk.SearchEntry({placeholder_text: 'IP, kullanıcı, kaynak veya kanıt ara…', hexpand: true});
            const toolbar = new Gtk.Box({spacing: 8});
            toolbar.append(search);
            let matches = data.events;
            toolbar.append(button('JSON kaydet', () => exportEvents(matches)));
            content.append(toolbar);
            if (!data.events.length) card('Henüz olay yok', 'Yapılandırılmış sensörlerden gerçek olaylar burada görünecek.');
            const rows = data.events.map(event => ({event, widget: eventCard(event, data.status.mode)}));
            search.connect('search-changed', () => {
                const query = search.text.toLocaleLowerCase('tr-TR');
                matches = [];
                for (const row of rows) {
                    row.widget.visible = JSON.stringify(row.event).toLocaleLowerCase('tr-TR').includes(query);
                    if (row.widget.visible) matches.push(row.event);
                }
            });
        } else if (page === 'protection') {
            card('Kontrollü koruma', `${data.status.mode} modu. Engeller yalnızca bu bilgisayara gelen kaynak IP trafiğine uygulanır. “applied” son başarılı işlemi ifade eder.`);
            for (const ban of data.bans) {
                const c = card(ban.ip, `${ban.state} · ${ban.reason}\nBitiş: ${new Date(ban.expires).toLocaleString('tr-TR')}${ban.error ? '\n' + ban.error : ''}`);
                const remove = button('Kaldır / iptal et', () => mutate('unban', {ip: ban.ip}));
                remove.sensitive = data.status.mode !== 'monitor'; c.append(remove);
            }
            const result = await client.api('allowlist');
            if (!win || page !== 'protection') return;
            const add = card('Güvenilir IP / CIDR', 'Bu adreslerle eşleşen engellerin kaldırılması talep edilir.');
            const entry = new Gtk.Entry({placeholder_text: '192.0.2.44 veya 192.0.2.0/24'});
            add.append(entry); add.append(button('Ekle', () => mutate('allowlist', {prefix: entry.text.trim(), add: true})));
            for (const prefix of result.prefixes) {
                const row = card(prefix, 'Güvenilir adres');
                row.append(button('Listeden çıkar', () => mutate('allowlist', {prefix, add: false})));
            }
        } else if (page === 'settings') {
            card('Yerel servis bağlantısı', `Unix socket: ${client.socketPath}\nTarayıcı veya TCP portu kullanılmaz. Erişim anahtarı yerel dosyadan otomatik okunur.`);
            for (const [name, sensor] of Object.entries(data.status.sensors)) card(`${name} · ${sensor.state}`, sensor.detail);
            card('Çalışma biçimi', 'Pencereyi kapatmak izlemeyi durdurmaz. Sensör ve çalışma modu servis yapılandırmasından yönetilir.');
        } else {
            card('Güvenlik kontrol merkezi', 'Bu bilgisayardan toplanan olaylar ve sensör durumu. Bağlantı kurulması, bilgisayarın güvenli olduğunun kanıtı değildir.');
            card('Son olaylar', `${data.events.length} görünür kayıt · ${data.events.filter(e => e.severity === 'high').length} yüksek önem · ${data.bans.filter(b => b.state === 'applied' && b.desired && new Date(b.expires) > new Date()).length} son işlemde uygulanmış engel`);
            for (const [name, sensor] of Object.entries(data.status.sensors)) card(`${name} · ${sensor.state}`, sensor.detail);
            for (const event of data.events.slice(0, 5)) eventCard(event, data.status.mode);
        }
    } catch (error) {
        smokeFailed = true;
        if (win) {
            status.label = 'SERVİSE ULAŞILAMIYOR'; clear(content);
            card('Bağlantı kurulamadı', `${error.message}\nServis durumunu kontrol edin: systemctl --user status memoshield-personal.service`);
        }
    } finally { busy = false; }
}
app.connect('activate', () => {
    if (win) { win.present(); return; }
    Adw.StyleManager.get_default().color_scheme = Adw.ColorScheme.FORCE_DARK;
    const css = new Gtk.CssProvider();
    css.load_from_path(GLib.build_filenamev([GLib.path_get_dirname(Gio.File.new_for_uri(import.meta.url).get_path()), 'style.css']));
    Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION);
    client = new Client(GLib.getenv('MEMOSHIELD_SOCKET') || '');
    win = new Adw.ApplicationWindow({application: app, title: 'memOShield', default_width: 1080, default_height: 760});
    const root = box(0), header = new Adw.HeaderBar();
    header.set_title_widget(label('memOShield', 'brand'));
    header.pack_end(button('Yenile', refresh)); root.append(header);
    const body = new Gtk.Box({spacing: 0, vexpand: true});
    const nav = box(8); nav.add_css_class('sidebar');
    for (const [key, name] of Object.entries(names)) nav.append(button(name, () => { page = key; refresh(); }));
    body.append(nav);
    content = box(16); content.add_css_class('content');
    const scroll = new Gtk.ScrolledWindow({hexpand: true, vexpand: true, hscrollbar_policy: Gtk.PolicyType.NEVER});
    scroll.set_child(content); body.append(scroll); root.append(body);
    status = label('SERVİSE BAĞLANILIYOR', 'status-line'); root.append(status);
    win.set_content(root);
    win.connect('close-request', () => {
        if (timer) GLib.Source.remove(timer); timer = null;
        client.close(); win = null; return false;
    });
    timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 15, () => {
        const focus = win?.get_focus();
        if (!(focus instanceof Gtk.Entry) && !(focus instanceof Gtk.SearchEntry)) refresh();
        return GLib.SOURCE_CONTINUE;
    });
    win.present();
    if (GLib.getenv('MEMOSHIELD_UI_SMOKE') === '1') {
        (async () => {
            try {
                for (const key of Object.keys(names)) { page = key; await refresh(); }
                if (smokeFailed) throw new Error('Native window failed to load service data');
                print('Native GTK pages: PASS');
            } catch (error) { smokeFailed = true; printerr(error.message); }
            if (timer) GLib.Source.remove(timer);
            timer = null; client.close(); app.quit();
        })();
    } else refresh();
});
app.run([System.programInvocationName, ...ARGV]);
if (GLib.getenv('MEMOSHIELD_UI_SMOKE') === '1' && smokeFailed) System.exit(1);
