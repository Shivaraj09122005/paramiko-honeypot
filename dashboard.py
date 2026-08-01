"""
Web Dashboard - Milestone 6
-------------------------------
A small Flask app that reads from the same SQLite database the honeypot
writes to (logs/honeypot.db) and renders charts summarizing attacker
activity: top source IPs, top commands run, top credentials tried, and
recent download attempts.

Run this SEPARATELY from server.py, on a different port, while the
honeypot is running:
    python dashboard.py
Then visit http://<vm-ip>:5000 in a browser.
"""

from flask import Flask, render_template_string

import db
import threat_intel
import analyzer
import attck_mapping
import malware_capture

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; background: #0f1115; color: #e6e6e6; margin: 0; padding: 24px; }
        h1 { color: #ff6b6b; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 24px; }
        .card { background: #1a1d24; border-radius: 10px; padding: 20px; }
        canvas { max-height: 300px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #333; font-size: 14px; }
        .stat { font-size: 32px; font-weight: bold; color: #4dd0e1; }
    </style>
</head>
<body>
    <h1>Honeypot Dashboard</h1>
    <div class="card">
        <div>Total events logged</div>
        <div class="stat">{{ total_events }}</div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Top Source IPs</h3>
            <canvas id="ipChart"></canvas>
        </div>
       <div class="card">
            <h3>IP Intelligence</h3>
            <table>
                <tr><th>IP</th><th>Events</th><th>Country</th><th>City</th><th>ISP</th></tr>
                {% for ip, count, intel in ip_intel %}
                <tr><td>{{ ip }}</td><td>{{ count }}</td><td>{{ intel.country }}</td><td>{{ intel.city }}</td><td>{{ intel.isp }}</td></tr>
                {% endfor %}
            </table>
        </div>
        <div class="card">
            <h3>Top Commands</h3>
            <canvas id="cmdChart"></canvas>
        </div>
        <div class="card">
            <h3>Top Credentials Tried</h3>
            <table>
                <tr><th>Username</th><th>Password</th><th>Attempts</th></tr>
                {% for user, pw, count in credentials %}
                <tr><td>{{ user }}</td><td>{{ pw }}</td><td>{{ count }}</td></tr>
                {% endfor %}
            </table>
        </div>
        <div class="card">
            <h3>Recent Download Attempts</h3>
            <table>
                <tr><th>Tool</th><th>URL</th><th>Time</th></tr>
                {% for tool, url, ts in downloads %}
                <tr><td>{{ tool }}</td><td>{{ url }}</td><td>{{ ts }}</td></tr>
                {% endfor %}
            </table>
        </div>
    <div class="card">
            <h3>Command Intent Breakdown</h3>
            <canvas id="intentChart"></canvas>
        </div>
       <div class="card">
            <h3>MITRE ATT&amp;CK Mapping</h3>
            <table>
                <tr><th>Category</th><th>Count</th><th>Tactic</th><th>Technique</th></tr>
                {% for category, count, tactic_id, tactic_name, tech_id, tech_name in attck_rows %}
                <tr><td>{{ category }}</td><td>{{ count }}</td>
                    <td>{{ tactic_id }} {{ tactic_name }}</td>
                    <td>{{ tech_id }} {{ tech_name }}</td></tr>
                {% endfor %}
            </table>
        </div>
       <div class="card">
            <h3>Captured Samples (quarantined, never executed)</h3>
            <table>
                <tr><th>SHA256</th><th>URL</th><th>Tool</th><th>Size</th><th>VirusTotal Verdict</th></tr>
                {% for sha256, url, tool, src_ip, size, status, ts, vt_verdict, vt_malicious, vt_total in samples %}
                <tr><td>{{ sha256[:16] if sha256 else '-' }}...</td><td>{{ url }}</td><td>{{ tool }}</td>
                    <td>{{ size or '-' }}</td>
                    <td>
                        {% if vt_verdict == 'malicious' %}
                            🔴 Malicious ({{ vt_malicious }}/{{ vt_total }})
                        {% elif vt_verdict == 'suspicious' %}
                            🟡 Suspicious ({{ vt_malicious }}/{{ vt_total }})
                        {% elif vt_verdict == 'clean' %}
                            🟢 Clean (0/{{ vt_total }})
                        {% elif vt_verdict == 'not_found' %}
                            ⚪ Not in VT database
                        {% elif vt_verdict == 'no_api_key' %}
                            ⚪ VT lookup not configured
                        {% else %}
                            ⚪ {{ vt_verdict or status }}
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        <div class="card">
            <h3>Recent Sessions</h3>
        <div class="card">
            <h3>Recent Sessions</h3>
            <table>
                <tr><th>Session</th><th>IP</th><th>Started</th><th>Commands</th><th></th></tr>
                {% for sid, ip, started, cmds in sessions %}
                <tr><td>{{ sid }}</td><td>{{ ip }}</td><td>{{ started }}</td><td>{{ cmds }}</td>
                    <td><a href="/session/{{ sid }}">Replay &rarr;</a></td></tr>
                {% endfor %}
            </table>
        </div>
    </div>

    <script>
        new Chart(document.getElementById('ipChart'), {
            type: 'bar',
            data: {
                labels: {{ ip_labels | tojson }},
                datasets: [{ label: 'Events', data: {{ ip_values | tojson }}, backgroundColor: '#4dd0e1' }]
            },
            options: { plugins: { legend: { display: false } } }
        });

        new Chart(document.getElementById('cmdChart'), {
            type: 'bar',
            data: {
                labels: {{ cmd_labels | tojson }},
                datasets: [{ label: 'Times run', data: {{ cmd_values | tojson }}, backgroundColor: '#ff6b6b' }]
            },
            options: { indexAxis: 'y', plugins: { legend: { display: false } } }
        });

        new Chart(document.getElementById('intentChart'), {
            type: 'doughnut',
            data: {
                labels: {{ category_labels | tojson }},
                datasets: [{ data: {{ category_values | tojson }}, backgroundColor: ['#4dd0e1', '#ff6b6b', '#ffd166', '#06d6a0', '#a78bfa', '#f77f00'] }]
            }
        });
    </script>
</body>
</html>
"""

app = Flask(__name__)
REPLAY_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Session Replay - {{ session_id }}</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0f1115; color: #e6e6e6; margin: 0; padding: 24px; }
        a { color: #4dd0e1; }
        .terminal { background: #000; border-radius: 8px; padding: 20px; margin-top: 16px; min-height: 200px; white-space: pre-wrap; }
        .prompt { color: #4dd0e1; }
        button { background: #ff6b6b; color: #000; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; }
    </style>
</head>
<body>
    <a href="/">&larr; Back to dashboard</a>
    <h2>Session Replay: {{ session_id }}</h2>
    <button onclick="replay()">&#9654; Play</button>
    <div class="terminal" id="term"></div>

    <script>
        const events = {{ events | tojson }};
        // event tuple order: event_type, username, password, command, tool, url, timestamp
        async function replay() {
            const term = document.getElementById('term');
            term.textContent = '';
            for (const ev of events) {
                const [type, username, password, command, tool, url, ts] = ev;
                let line = '';
                if (type === 'login_attempt') {
                    line = `[LOGIN] user=${username} pass=${password}`;
                } else if (type === 'command') {
                    line = `root@prod-web01:~# ${command}`;
                } else if (type === 'download_attempt') {
                    line = `[DOWNLOAD via ${tool}] ${url}`;
                } else {
                    line = `[${type}]`;
                }
                term.textContent += line + '\\n';
                await new Promise(r => setTimeout(r, 500));
            }
        }
    </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    ips = db.top_ips(10)
    ip_intel = [(ip, count, threat_intel.lookup_ip(ip)) for ip, count in ips]
    commands = db.top_commands(10)
    credentials = db.top_credentials(10)
    downloads = db.recent_downloads(10)
    total_events = db.total_event_count()
    sessions = db.recent_sessions(15)

    category_totals = {}
    for command, count in db.all_command_counts():
        category, _risk = analyzer.classify_and_score(command)
        category_totals[category] = category_totals.get(category, 0) + count

    samples = malware_capture.recent_samples(15)

    attck_rows = []
    for category, count in category_totals.items():
        info = attck_mapping.get_attck_info(category)
        attck_rows.append((category, count, info["tactic_id"], info["tactic_name"], info["technique_id"], info["technique_name"]))

    return render_template_string(
        PAGE_TEMPLATE,
        total_events=total_events,
        ip_labels=[row[0] for row in ips],
        ip_values=[row[1] for row in ips],
        ip_intel=ip_intel,
        cmd_labels=[row[0] for row in commands],
        cmd_values=[row[1] for row in commands],
        credentials=credentials,
        downloads=downloads,
        sessions=sessions,
        category_labels=list(category_totals.keys()),
        category_values=list(category_totals.values()),
        attck_rows=attck_rows,
        samples=samples,
    )
@app.route("/session/<session_id>")
def replay(session_id):
    events = db.session_events(session_id)
    return render_template_string(REPLAY_TEMPLATE, session_id=session_id, events=events)


if __name__ == "__main__":
    threat_intel.init_intel_table()
    app.run(host="0.0.0.0", port=5000, debug=False)
