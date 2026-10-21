import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Soup from 'gi://Soup?version=3.0';

export class Client {
    constructor(socketPath = '', tokenPath = '') {
        this.origin = 'http://localhost';
        this.socketPath = socketPath || GLib.getenv('MEMOSHIELD_SOCKET') || GLib.build_filenamev([
            GLib.getenv('XDG_RUNTIME_DIR') || GLib.build_filenamev([GLib.getenv('XDG_STATE_HOME') || GLib.build_filenamev([GLib.get_home_dir(), '.local', 'state']), 'memoshield']),
            'memoshield', 'control.sock',
        ]);
        if (!GLib.path_is_absolute(this.socketPath))
            throw new Error('Unix socket yolu mutlak bir dosya yolu olmalı.');
        this.tokenPath = tokenPath || (GLib.getenv('MEMOSHIELD_DATA_DIR') ? GLib.build_filenamev([GLib.getenv('MEMOSHIELD_DATA_DIR'), 'access-token']) : GLib.build_filenamev([
            GLib.getenv('XDG_STATE_HOME') || GLib.build_filenamev([GLib.get_home_dir(), '.local', 'state']),
            'memoshield', 'access-token',
        ]));
        this.cancel = new Gio.Cancellable();
        this.session = new Soup.Session({timeout: 8, remote_connectable: new Gio.UnixSocketAddress({path: this.socketPath}), proxy_resolver: new Gio.SimpleProxyResolver()});
        this.session.add_feature(new Soup.CookieJar());
        this.closed = false;
        this.login = null;
    }

    close() {
        this.closed = true;
        this.cancel.cancel();
        this.session.abort();
    }

    async request(path, body) {
        if (this.closed) throw new Error('Bağlantı kapatıldı.');
        const message = Soup.Message.new(body === undefined ? 'GET' : 'POST', `${this.origin}/api/${path}`);
        // Never forward the token or cookie to a redirect destination.
        message.set_flags(Soup.MessageFlags.NO_REDIRECT);
        if (body !== undefined) {
            message.request_headers.append('Origin', this.origin);
            message.set_request_body_from_bytes('application/json', new GLib.Bytes(new TextEncoder().encode(JSON.stringify(body))));
        }
        const bytes = await new Promise((resolve, reject) => {
            this.session.send_and_read_async(message, GLib.PRIORITY_DEFAULT, this.cancel, (session, result) => {
                try { resolve(session.send_and_read_finish(result)); } catch (error) { reject(error); }
            });
        });
        const status = message.get_status();
        let data;
        try { data = JSON.parse(new TextDecoder().decode(bytes.get_data())); }
        catch { throw new Error(`Servis yanıtı okunamadı (HTTP ${status}).`); }
        if (status !== 200) {
            const error = new Error(data.error || `HTTP ${status}`);
            error.status = status;
            throw error;
        }
        return data;
    }

    async authenticate() {
        const file = Gio.File.new_for_path(this.tokenPath);
        const contents = await new Promise((resolve, reject) => {
            file.load_contents_async(this.cancel, (source, result) => {
                try { const [, bytes] = source.load_contents_finish(result); resolve(bytes); }
                catch { reject(new Error('Erişim anahtarı okunamıyor. Servisi ve ayarlardaki dosya yolunu kontrol et.')); }
            });
        });
        const token = new TextDecoder().decode(contents).trim();
        if (!/^[0-9a-f]{64}$/i.test(token)) throw new Error('Erişim anahtarı dosyası geçersiz.');
        await this.request('login', {token});
    }

    async api(path, body) {
        try { return await this.request(path, body); }
        catch (error) {
            if (error.status !== 401 || this.closed) throw error;
            if (!this.login) this.login = this.authenticate().finally(() => { this.login = null; });
            await this.login;
            return this.request(path, body);
        }
    }

    async snapshot() {
        // Authenticate once before issuing parallel requests.
        const status = await this.api('status');
        const [events, bans] = await Promise.all([this.api('events'), this.api('bans')]);
        return {status, events: events.events, bans: bans.bans};
    }
}
