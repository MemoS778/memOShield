import {Client} from '../gnome/client.js';

const client = new Client('');
try {
    const data = await client.snapshot();
    if (data.status.mode !== 'monitor') throw new Error('Unexpected mode');
    await client.api('allowlist', {prefix: '192.0.2.44', add: true});
    const list = await client.api('allowlist');
    if (!list.prefixes.includes('192.0.2.44/32')) throw new Error('Allowlist did not persist');
    let rejected = false;
    try { await client.api('ban', {ip: '192.0.2.44', reason: 'test', minutes: 10}); }
    catch (error) { rejected = error.status === 409; }
    if (!rejected) throw new Error('Monitor mode allowed mutation');
    await client.api('logout', {});
    await client.api('status'); // reauthenticate after logout
    print('Native Unix-socket client: PASS');
} finally { client.close(); }
