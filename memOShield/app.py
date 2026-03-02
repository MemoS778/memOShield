import os
from flask import Flask, jsonify, request, render_template, Response, stream_with_context, session, redirect, url_for, flash
import logging

from memoshield.db import init_db, get_events, get_rules, add_ban, get_bans
from memoshield.firewall import Firewall
from memoshield.geoip import GeoIPClient
from memoshield.ids import IDS
from memoshield.honeypot import Honeypot
from memoshield.notifier import Notifier
from memoshield.pcap_recorder import PCAPRecorder
from memoshield.broadcaster import broadcaster
from memoshield import mock_stream

logging.basicConfig(level=logging.INFO)
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('FLASK_SECRET', 'change-this-secret')

# init
init_db()
firewall = Firewall()
geo = GeoIPClient()
ids = IDS(firewall, geo)
honeypot = Honeypot(ids, firewall, geo)
notifier = Notifier()
pcap = PCAPRecorder()

# try to start background services at init time (best-effort)
try:
    ids.start()
    honeypot.start()
    pcap.start()
    logging.info("Background services started")
except Exception as e:
    logging.warning("Failed to start background services: %s", e)

# optional demo mock stream (enable by env var ENABLE_MOCK_STREAM=1)
try:
    if os.environ.get('ENABLE_MOCK_STREAM', '0') in ('1', 'true', 'True'):
        mock_stream.start(interval=int(os.environ.get('MOCK_STREAM_INTERVAL', '3')))
        logging.info('Mock stream started (ENABLE_MOCK_STREAM=1)')
except Exception:
    pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    # allow ?demo=1 to view without login (read-only demo)
    demo = request.args.get('demo') == '1' or session.get('logged_in')
    if not demo and not session.get('logged_in'):
        return redirect(url_for('login', next=request.path))
    return render_template('dashboard.html', demo=(request.args.get('demo') == '1'))

@app.route('/demo')
def demo():
    return render_template('dashboard.html', demo=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        pw = request.form.get('password')
        admin_pw = os.environ.get('ADMIN_PASSWORD', 'admin')
        if pw == admin_pw:
            session['logged_in'] = True
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Yanlış parola', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/api/events')
def api_events():
    events = get_events(200)
    return jsonify(events if isinstance(events, list) else [])

@app.route('/api/rules')
def api_rules():
    rules = get_rules()
    if isinstance(rules, list):
        return jsonify({'rules': rules})
    return jsonify(rules)

@app.route('/api/bans')
def api_bans():
    bans = get_bans(200)
    return jsonify(bans if isinstance(bans, list) else [])

@app.route('/api/lookup/<ip>')
def api_lookup(ip):
    """IP bilgilerini sorgula - ülke, ISP, hostname, koordinat"""
    try:
        info = geo.lookup(ip)
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e), 'ip': ip}), 500

@app.route('/api/unban', methods=['POST'])
def api_unban():
    if not session.get('logged_in'):
        return jsonify({'error': 'authentication required'}), 403
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    firewall.remove_rule(ip)
    return jsonify({'ok': True})

@app.route('/api/ban', methods=['POST'])
def api_ban():
    if not session.get('logged_in'):
        return jsonify({'error': 'authentication required'}), 403
    data = request.get_json() or {}
    ip = data.get('ip')
    reason = data.get('reason', 'manual')
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    firewall.add_rule(ip, reason)
    add_ban(ip, reason)
    notifier.send_telegram(f"IP banned: {ip} — {reason}")
    return jsonify({'ok': True})

@app.route('/api/record', methods=['POST'])
def api_record():
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    ids.record_packet(ip)
    return jsonify({'ok': True})

@app.route('/api/whitelist')
def api_whitelist():
    try:
        from memoshield.whitelist import get_whitelist
        ips = get_whitelist()
        if isinstance(ips, list):
            return jsonify({'whitelist': ips})
        return jsonify(ips)
    except Exception as e:
        return jsonify({'whitelist': [], 'error': str(e)}), 500

@app.route('/api/whitelist/add', methods=['POST'])
def api_whitelist_add():
    if not session.get('logged_in'):
        return jsonify({'error': 'authentication required'}), 403
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    try:
        from memoshield.whitelist import add_to_whitelist
        add_to_whitelist(ip)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/honeypot-status')
def api_honeypot_status():
    return jsonify({
        'status': 'running',
        'ports': [2121, 2222, 2323, 3307]
    })

@app.route('/stream')
def stream():
    def event_stream():
        q = broadcaster.register()
        try:
            while True:
                data = q.get()
                yield f"data: {data}\n\n"
        except GeneratorExit:
            broadcaster.unregister(q)
    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
