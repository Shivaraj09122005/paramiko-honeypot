"""
Web Dashboard - Milestone 6 (redesigned)
-------------------------------
A small Flask app that reads from the same SQLite database the honeypot
writes to (logs/honeypot.db) and renders charts summarizing attacker
activity: top source IPs, top commands run, top credentials tried,
recent download attempts, IP intelligence, MITRE ATT&CK mapping,
captured malware samples, and session replay.

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

app = Flask(__name__)

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>honeypot // monitor</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0e0f;
    --panel:#12181c;
    --panel-2:#161d21;
    --border:#222b2f;
    --text:#e7ebec;
    --muted:#7a8a8f;
    --amber:#ffb703;
    --green:#00ff9c;
    --red:#ff5c5c;
    --blue:#5eb1ff;
    --violet:#a78bfa;
    --mono:'JetBrains Mono', monospace;
    --sans:'Inter', sans-serif;
    --display:'Space Grotesk', sans-serif;
  }
  *{ box-sizing:border-box; }
  body{
    margin:0; background:var(--bg); color:var(--text);
    font-family:var(--sans);
    position:relative;
    min-height:100vh;
  }
  body::before{
    content:''; position:fixed; inset:0; pointer-events:none; z-index:999;
    background:repeating-linear-gradient(
      to bottom, rgba(255,255,255,0.014) 0px, rgba(255,255,255,0.014) 1px,
      transparent 1px, transparent 3px
    );
  }
  @media (prefers-reduced-motion: no-preference){
    .live-dot{ animation:pulse 1.6s ease-in-out infinite; }
    .cursor{ animation:blink 1s steps(1) infinite; }
  }
  @keyframes pulse{ 0%,100%{opacity:1;} 50%{opacity:.25;} }
  @keyframes blink{ 0%,50%{opacity:1;} 51%,100%{opacity:0;} }

  header{
    border-bottom:1px solid var(--border);
    padding:26px 32px;
    display:flex; align-items:center; justify-content:space-between;
    background:linear-gradient(180deg, var(--panel-2), var(--bg));
  }
  .prompt{
    font-family:var(--display); font-size:26px; font-weight:700;
    color:var(--text); letter-spacing:-.01em;
  }
  .prompt .path{ color:var(--green); }
  .prompt .sep{ color:var(--muted); font-weight:500; }
  .prompt .cursor{ color:var(--amber); }
  .status{
    display:flex; align-items:center; gap:8px;
    font-family:var(--mono); font-size:12px; letter-spacing:.12em;
    color:var(--muted); text-transform:uppercase;
  }
  .live-dot{
    width:8px; height:8px; border-radius:50%; background:var(--green);
    box-shadow:0 0 8px var(--green);
  }

  main{ padding:32px 40px 60px; max-width:1800px; margin:0 auto; }

  .eyebrow{
    font-family:var(--mono); font-size:11px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--muted); margin:0 0 6px;
  }
  .stat-row{ display:flex; gap:20px; margin-bottom:28px; flex-wrap:wrap; }
  .stat-box{
    border:1px solid var(--border); background:var(--panel);
    padding:18px 24px; min-width:160px;
    box-shadow:0 4px 20px rgba(0,0,0,.35);
  }
  .stat-box .value{
    font-family:var(--display); font-size:38px; font-weight:700; color:var(--green);
    line-height:1;
  }

  .grid{ display:grid; grid-template-columns:repeat(auto-fit, minmax(480px, 1fr)); gap:24px; }
  @media (max-width: 1000px){ .grid{ grid-template-columns:1fr; } }

  .panel{
    border:1px solid var(--border); background:var(--panel);
    padding:28px 28px 26px; position:relative;
    min-height:340px;
    box-shadow:0 4px 20px rgba(0,0,0,.35);
    transition:transform .15s ease, box-shadow .15s ease;
  }
  .panel:hover{
    transform:translateY(-2px);
    box-shadow:0 8px 28px rgba(0,0,0,.5);
  }
  .panel::before{
    content:''; position:absolute; top:0; left:0; bottom:0;
    width:3px; background:var(--accent, var(--amber));
  }
  .panel h3{
    margin:0 0 20px; font-family:var(--display); font-size:20px;
    letter-spacing:-.01em; color:var(--text); font-weight:700;
    display:flex; align-items:center; gap:8px;
  }
  .panel h3 .muted{ color:var(--muted); font-weight:500; font-family:var(--mono); font-size:12px; text-transform:none; letter-spacing:0; }

  .panel.c-green{ --accent: var(--green); }
  .panel.c-amber{ --accent: var(--amber); }
  .panel.c-red{ --accent: var(--red); }
  .panel.c-blue{ --accent: var(--blue); }
  .panel.c-violet{ --accent: var(--violet); }

  table{ width:100%; border-collapse:collapse; }
  th, td{
    text-align:left; padding:10px 10px; font-size:14px;
    border-bottom:1px solid var(--border);
  }
  th{
    font-family:var(--mono); font-size:11px; letter-spacing:.08em;
    text-transform:uppercase; color:var(--muted); font-weight:500;
  }
  td{ font-family:var(--mono); font-size:13.5px; color:var(--text); }
  td.sans{ font-family:var(--sans); font-size:14px; }
  tr:hover td{ background:var(--panel-2); }

  a{ color:var(--amber); text-decoration:none; }
  a:hover{ text-decoration:underline; }

  .verdict-malicious{ color:var(--red); font-weight:600; }
  .verdict-clean{ color:var(--green); font-weight:600; }
  .verdict-neutral{ color:var(--muted); }

  canvas{ max-height:280px; }

  .footer-note{
    margin-top:32px; font-family:var(--mono); font-size:11px;
    color:var(--muted); letter-spacing:.04em;
  }
</style>
</head>
<body>

<header>
  <div class="prompt"><span class="path">honeypot</span><span class="sep">@</span>monitor<span class="sep">:~$</span> <span class="cursor">_</span></div>
  <div class="status"><span class="live-dot"></span> live</div>
</header>

<main>
  <p class="eyebrow">Session Overview</p>
  <div class="stat-row">
    <div class="stat-box">
      <div class="eyebrow">Total Events</div>
      <div class="value">{{ total_events }}</div>
    </div>
  </div>

  <div class="grid">
    <div class="panel c-green">
      <h3>Top Source IPs</h3>
      <canvas id="ipChart"></canvas>
    </div>
    <div class="panel c-amber">
      <h3>Top Commands</h3>
      <canvas id="cmdChart"></canvas>
    </div>

    <div class="panel c-blue">
      <h3>IP Intelligence</h3>
      <table>
        <tr><th>IP</th><th>Events</th><th>Country</th><th>City</th><th>ISP</th></tr>
        {% for ip, count, intel in ip_intel %}
        <tr><td>{{ ip }}</td><td>{{ count }}</td><td class="sans">{{ intel.country }}</td><td class="sans">{{ intel.city }}</td><td class="sans">{{ intel.isp }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="panel c-red">
      <h3>Top Credentials Tried</h3>
      <table>
        <tr><th>Username</th><th>Password</th><th>Attempts</th></tr>
        {% for user, pw, count in credentials %}
        <tr><td>{{ user }}</td><td>{{ pw }}</td><td>{{ count }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="panel c-violet">
      <h3>Command Intent Breakdown <span class="muted">// analyzer.py</span></h3>
      <canvas id="intentChart"></canvas>
    </div>

    <div class="panel c-amber">
      <h3>MITRE ATT&amp;CK Mapping</h3>
      <table>
        <tr><th>Category</th><th>Count</th><th>Tactic</th><th>Technique</th></tr>
        {% for category, count, tactic_id, tactic_name, tech_id, tech_name in attck_rows %}
        <tr><td class="sans">{{ category }}</td><td>{{ count }}</td>
            <td>{{ tactic_id }} <span class="sans muted">{{ tactic_name }}</span></td>
            <td>{{ tech_id }} <span class="sans muted">{{ tech_name }}</span></td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="panel c-blue">
      <h3>Recent Download Attempts</h3>
      <table>
        <tr><th>Tool</th><th>URL</th><th>Time</th></tr>
        {% for tool, url, ts in downloads %}
        <tr><td>{{ tool }}</td><td class="sans">{{ url }}</td><td>{{ ts }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="panel c-red">
      <h3>Captured Samples <span class="muted">// quarantined, never executed</span></h3>
      <table>
        <tr><th>SHA256</th><th>URL</th><th>Tool</th><th>Size</th><th>VirusTotal Verdict</th></tr>
        {% for sha256, url, tool, src_ip, size, status, ts, vt_verdict, vt_malicious, vt_total in samples %}
        <tr><td>{{ sha256[:16] if sha256 else '-' }}...</td><td class="sans">{{ url }}</td><td>{{ tool }}</td>
            <td>{{ size or '-' }}</td>
            <td>
                {% if vt_verdict == 'malicious' %}
                    <span class="verdict-malicious">MALICIOUS ({{ vt_malicious }}/{{ vt_total }})</span>
                {% elif vt_verdict == 'suspicious' %}
                    <span class="verdict-malicious">SUSPICIOUS ({{ vt_malicious }}/{{ vt_total }})</span>
                {% elif vt_verdict == 'clean' %}
                    <span class="verdict-clean">CLEAN (0/{{ vt_total }})</span>
                {% elif vt_verdict == 'not_found' %}
                    <span class="verdict-neutral">NOT IN VT DB</span>
                {% elif vt_verdict == 'no_api_key' %}
                    <span class="verdict-neutral">VT NOT CONFIGURED</span>
                {% else %}
                    <span class="verdict-neutral">{{ vt_verdict or status }}</span>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
      </table>
    </div>

    <div class="panel c-green">
      <h3>Recent Sessions</h3>
      <table>
        <tr><th>Session</th><th>IP</th><th>Started</th><th>Commands</th><th></th></tr>
        {% for sid, ip, started, cmds in sessions %}
        <tr><td>{{ sid }}</td><td>{{ ip }}</td><td class="sans">{{ started }}</td><td>{{ cmds }}</td>
            <td><a href="/session/{{ sid }}">replay &rarr;</a></td></tr>
        {% endfor %}
      </table>
    </div>
  </div>

  <p class="footer-note">honeypot dashboard // read-only view of captured attacker activity // no real systems at risk</p>
</main>

<script>
  Chart.defaults.color = '#7a8a8f';
  Chart.defaults.borderColor = '#222b2f';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";

  new Chart(document.getElementById('ipChart'), {
      type: 'bar',
      data: {
          labels: {{ ip_labels | tojson }},
          datasets: [{ label: 'Events', data: {{ ip_values | tojson }}, backgroundColor: '#00ff9c' }]
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
  });

  new Chart(document.getElementById('cmdChart'), {
      type: 'bar',
      data: {
          labels: {{ cmd_labels | tojson }},
          datasets: [{ label: 'Times run', data: {{ cmd_values | tojson }}, backgroundColor: '#ffb703' }]
      },
      options: { indexAxis: 'y', plugins: { legend: { display: false } } }
  });

  new Chart(document.getElementById('intentChart'), {
      type: 'doughnut',
      data: {
          labels: {{ category_labels | tojson }},
          datasets: [{ data: {{ category_values | tojson }}, backgroundColor: ['#00ff9c', '#ffb703', '#ff5c5c', '#5eead4', '#a78bfa', '#7a8a8f'] }]
      },
      options: { plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } } }
  });
</script>
</body>
</html>
"""
REPLAY_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>session replay // {{ session_id }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0e0f; --panel:#12181c; --border:#222b2f;
    --text:#e7ebec; --muted:#7a8a8f; --amber:#ffb703; --green:#00ff9c;
    --mono:'JetBrains Mono', monospace; --sans:'Inter', sans-serif;
  }
  body{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); padding:32px; }
  a{ color:var(--amber); text-decoration:none; font-family:var(--mono); font-size:13px; }
  a:hover{ text-decoration:underline; }
  h2{ font-family:var(--mono); font-weight:500; font-size:18px; color:var(--green); }
  button{
    background:var(--amber); color:#0a0e0f; border:none; padding:10px 20px;
    font-family:var(--mono); font-weight:700; letter-spacing:.04em;
    cursor:pointer; margin:16px 0;
  }
  button:hover{ opacity:.85; }
  .terminal{
    background:#000; border:1px solid var(--border);
    padding:20px; min-height:240px; white-space:pre-wrap;
    font-family:var(--mono); font-size:13.5px; color:var(--green);
    line-height:1.6;
  }
</style>
</head>
<body>
  <a href="/">&larr; back to dashboard</a>
  <h2>session replay: {{ session_id }}</h2>
  <button onclick="replay()">&#9654; PLAY</button>
  <div class="terminal" id="term"></div>

  <script>
      const events = {{ events | tojson }};
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
    samples = malware_capture.recent_samples(15)

    category_totals = {}
    for command, count in db.all_command_counts():
        category, _risk = analyzer.classify_and_score(command)
        category_totals[category] = category_totals.get(category, 0) + count

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
