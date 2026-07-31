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
    </script>
</body>
</html>
"""

app = Flask(__name__)


@app.route("/")
def dashboard():
    ips = db.top_ips(10)
    ip_intel = [(ip, count, threat_intel.lookup_ip(ip)) for ip, count in ips]
    commands = db.top_commands(10)
    credentials = db.top_credentials(10)
    downloads = db.recent_downloads(10)
    total_events = db.total_event_count()

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
    )


if __name__ == "__main__":
    threat_intel.init_intel_table()
    app.run(host="0.0.0.0", port=5000, debug=False)
