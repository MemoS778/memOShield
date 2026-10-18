import Adw from 'gi://Adw';
import {ExtensionPreferences} from 'resource:///org/gnome/Shell/Extensions/js/extensions/prefs.js';

export default class Preferences extends ExtensionPreferences {
    fillPreferencesWindow(window) {
        const settings = this.getSettings();
        const page = new Adw.PreferencesPage({title: 'memOShield', icon_name: 'security-high-symbolic'});
        const group = new Adw.PreferencesGroup({title: 'Yerel servis bağlantısı', description: 'Eklenti ayrı çalışan memoshield-personal servisine bağlanır. Anahtar yalnızca yerel dosyadan okunur; ayarlara kaydedilmez.'});
        for (const [key, title] of [['service-url', 'Servis adresi (http://127.0.0.1:5000)'], ['token-path', 'Anahtar dosyasının tam yolu (varsayılan için boş)']]) {
            const row = new Adw.EntryRow({title, text: settings.get_string(key), show_apply_button: true});
            row.connect('apply', () => settings.set_string(key, row.text.trim()));
            group.add(row);
        }
        page.add(group);
        page.add(new Adw.PreferencesGroup({title: 'Çalışma biçimi', description: 'Durum 15 saniyede bir yenilenir. Servis kapalıysa eklenti bunu bildirir. İzleme modunda engelleme kapalıdır. Eklentiyi kapatmak arka plan servisini veya mevcut süreli engelleri durdurmaz.'}));
        window.add(page);
    }
}
