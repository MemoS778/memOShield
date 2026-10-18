// Run against the isolated server created by tests/ui/smoke.mjs.
import GLib from 'gi://GLib';
import System from 'system';
import {Client, localOrigin} from '../desktop/gnome/client.js';

const loop = new GLib.MainLoop(null, false);
let failure = false;
function check(condition, message) { if (!condition) throw new Error(message); }
async function test() {
    for (const url of ['https://127.0.0.1:5000', 'http://example.com:5000', 'http://127.0.0.1:5000/other', 'http://user@127.0.0.1:5000', 'http://127.0.0.1:5000?token=x']) {
        let rejected = false;
        try { localOrigin(url); } catch { rejected = true; }
        check(rejected, `unsafe origin accepted: ${url}`);
    }
    check(localOrigin('http://[::1]:5000/') === 'http://[::1]:5000', 'IPv6 loopback');
    const client = new Client(ARGV[0], ARGV[1]);
    try {
        const snapshot = await client.snapshot();
        check(snapshot.status.mode === 'monitor', 'monitor mode');
        check(snapshot.events.length === 0, 'empty database');
        await client.api('allowlist', {prefix: '192.0.2.99', add: true});
        check((await client.api('allowlist')).prefixes.includes('192.0.2.99/32'), 'authenticated mutation');
        await client.api('allowlist', {prefix: '192.0.2.99', add: false});
        let rejected = false;
        try { await client.api('ban', {ip: '192.0.2.99', minutes: 10, reason: 'test'}); }
        catch (error) { rejected = error.status === 409; }
        check(rejected, 'monitor mode blocks mutation');
        await client.api('logout', {});
        check((await client.snapshot()).status.mode === 'monitor', 'reauthenticate expired session');
        await client.api('logout', {});
    } finally { client.close(); }
    let rejected = false;
    try { await client.api('status'); } catch { rejected = true; }
    check(rejected, 'closed client rejects work');
    print('PASS: GNOME client authentication, cookie reuse, origin validation, mutations, monitor guard, reauthentication, cancellation');
}
test().catch(error => { printerr(error.stack); failure = true; }).finally(() => loop.quit());
loop.run();
if (failure) System.exit(1);
