"""
Web Dashboard - Milestone 6 (+ Milestone 15 blocked IPs, Milestone 17 AI chat)
--------------------------------------------------------------------------------
A small Flask app that reads from the same SQLite database the honeypot
writes to (logs/honeypot.db) and renders charts summarizing attacker
activity: top source IPs, top commands run, top credentials tried,
recent download attempts, blocked/banned IPs, and an AI mitigation
advisor with a live chat for each session.

Run this SEPARATELY from server.py, on a different port, while the
honeypot is running:

    python dashboard.py

Then visit http://<vm-ip>:5000 in a browser.
"""

from flask import Flask, render_template_string, request, redirect, url_for, jsonify
import db
import threat_intel
import analyzer
import attck_mapping
import malware_capture
import mitigation_advisor

# Change this to your own repo URL if you fork the project.
GITHUB_REPO_URL = "https://github.com/Shivaraj09122005/paramiko-honeypot"

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelHive &mdash; Threat Operations Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0a0b14;
    --bg-elevated: #12141f;
    --card: #151726;
    --card-border: #262a42;
    --accent: #5eead4;
    --accent-2: #f97066;
    --accent-3: #ffb454;
    --violet: #8b5cf6;
    --text: #edeef7;
    --text-dim: #949bb8;
    --radius: 16px;
  }

  * { box-sizing: border-box; }

  html { scroll-behavior: smooth; }

  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background:
      radial-gradient(circle at 12% -10%, rgba(139,92,246,0.20) 0%, transparent 45%),
      radial-gradient(circle at 88% 0%, rgba(94,234,212,0.14) 0%, transparent 40%),
      radial-gradient(circle at 50% 100%, rgba(249,112,102,0.08) 0%, transparent 55%),
      linear-gradient(180deg, #0d0f1a 0%, var(--bg) 100%);
    background-attachment: fixed;
    color: var(--text);
    margin: 0;
    padding: 0 0 48px 0;
    min-height: 100vh;
  }

  header {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 24px 40px;
    background: linear-gradient(135deg, rgba(139,92,246,0.10), rgba(94,234,212,0.06) 60%, rgba(249,112,102,0.05));
    border-bottom: 1px solid var(--card-border);
    box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    backdrop-filter: blur(6px);
    flex-wrap: wrap;
    gap: 16px;
  }

  header::after {
    content: "";
    position: absolute;
    left: 0; right: 0; bottom: -1px;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), var(--violet), var(--accent-2), transparent);
    opacity: 0.6;
  }

  .brand { display: flex; align-items: center; gap: 16px; }

  .brand-icon {
    width: 48px; height: 48px;
    border-radius: 13px;
    background: linear-gradient(135deg, var(--accent), var(--violet) 65%, var(--accent-2));
    display: flex; align-items: center; justify-content: center;
    font-size: 24px;
    box-shadow: 0 0 0 1px rgba(255,255,255,0.06), 0 8px 24px rgba(139,92,246,0.35);
  }

  h1 {
    margin: 0;
    font-size: 23px;
    font-weight: 900;
    letter-spacing: -0.03em;
    background: linear-gradient(90deg, #ffffff, #c9cede 80%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .subtitle {
    margin: 3px 0 0 0;
    color: var(--text-dim);
    font-size: 12.5px;
    display: flex;
    align-items: center;
    gap: 7px;
    letter-spacing: 0.01em;
  }

  .live-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 0 0 rgba(94,234,212,0.6);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(94,234,212,0.55); }
    70%  { box-shadow: 0 0 0 7px rgba(94,234,212,0); }
    100% { box-shadow: 0 0 0 0 rgba(94,234,212,0); }
  }

  .header-buttons { display: flex; align-items: center; gap: 12px; }

  .gh-button {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01));
    border: 1px solid var(--card-border);
    color: var(--text);
    text-decoration: none;
    font-weight: 600;
    font-size: 14px;
    padding: 10px 20px;
    border-radius: 11px;
    transition: border-color .15s ease, transform .15s ease, box-shadow .15s ease;
  }
  .gh-button:hover {
    border-color: var(--accent);
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(94,234,212,0.15);
  }
  .gh-button svg { width: 16px; height: 16px; fill: currentColor; }

  main { padding: 36px 40px; max-width: 1400px; margin: 0 auto; }

  .overview {
    display: flex;
    align-items: center;
    gap: 20px;
    background: linear-gradient(135deg, rgba(139,92,246,0.10), var(--card) 55%);
    border: 1px solid var(--card-border);
    border-radius: var(--radius);
    padding: 24px 30px;
    margin-bottom: 28px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
  }

  .overview .label {
    color: var(--text-dim);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }

  .overview .stat {
    font-size: 40px;
    font-weight: 800;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 22px;
  }

  @media (max-width: 900px) {
    .grid { grid-template-columns: 1fr; }
    main, header { padding-left: 20px; padding-right: 20px; }
  }

  .card {
    background: linear-gradient(180deg, rgba(255,255,255,0.02), transparent), var(--card);
    border: 1px solid var(--card-border);
    border-radius: var(--radius);
    padding: 22px;
    transition: border-color .15s ease, transform .15s ease, box-shadow .15s ease;
  }
  .card:hover {
    border-color: rgba(94,234,212,0.35);
    transform: translateY(-2px);
    box-shadow: 0 12px 30px rgba(0,0,0,0.3);
  }

  .card-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
  }

  .card-icon {
    width: 30px; height: 30px;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 15px;
    flex-shrink: 0;
  }

  .card h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 700;
    letter-spacing: -0.01em;
  }

  .card .card-desc {
    margin: -8px 0 14px 0;
    font-size: 12.5px;
    color: var(--text-dim);
  }

  canvas { max-height: 280px; }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    text-align: left;
    padding: 8px 10px;
    color: var(--text-dim);
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--card-border);
  }
  td {
    text-align: left;
    padding: 9px 10px;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
  }
  tr:hover td { background: rgba(94,234,212,0.04); }

  .table-wrap { max-height: 300px; overflow-y: auto; }

  a.replay-link { color: var(--accent); text-decoration: none; font-weight: 600; }
  a.replay-link:hover { text-decoration: underline; }

  .badge-banned {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    background: rgba(249,112,102,0.15);
    color: var(--accent-2);
    font-weight: 700;
    font-size: 11px;
  }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-icon">🛡️</div>
    <div>
      <h1>SentinelHive</h1>
      <p class="subtitle"><span class="live-dot"></span>Threat Operations Console &middot; live SSH intrusion analytics</p>
    </div>
  </div>
  <div class="header-buttons">
    <a class="gh-button" href="/settings">⚙️ Settings</a>
    <a class="gh-button" href="{{ github_url }}" target="_blank" rel="noopener noreferrer">
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>
      View on GitHub
    </a>
  </div>
</header>

<main>

  <div class="overview">
    <div>
      <div class="label">Total Events Logged</div>
      <div class="stat">{{ total_events }}</div>
    </div>
  </div>

  <div class="grid">

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(94,234,212,0.15); color:var(--accent);">📡</div>
        <h3>Top Attacking Source IPs</h3>
      </div>
      <canvas id="ipChart"></canvas>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(255,180,84,0.15); color:var(--accent-3);">🌐</div>
        <h3>IP Threat Intelligence</h3>
      </div>
      <div class="table-wrap">
        <table>
          <tr><th>IP</th><th>Events</th><th>Country</th><th>City</th><th>ISP</th></tr>
          {% for ip, count, intel in ip_intel %}
          <tr><td>{{ ip }}</td><td>{{ count }}</td><td>{{ intel.country }}</td><td>{{ intel.city }}</td><td>{{ intel.isp }}</td></tr>
          {% endfor %}
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(249,112,102,0.15); color:var(--accent-2);">⌨️</div>
        <h3>Most Executed Commands</h3>
      </div>
      <canvas id="cmdChart"></canvas>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(94,234,212,0.15); color:var(--accent);">🔑</div>
        <h3>Credential Attack Patterns</h3>
      </div>
      <div class="table-wrap">
        <table>
          <tr><th>Username</th><th>Password</th><th>Attempts</th></tr>
          {% for user, pw, count in credentials %}
          <tr><td>{{ user }}</td><td>{{ pw }}</td><td>{{ count }}</td></tr>
          {% endfor %}
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(255,180,84,0.15); color:var(--accent-3);">📥</div>
        <h3>Malicious Payload Downloads</h3>
      </div>
      <div class="table-wrap">
        <table>
          <tr><th>Tool</th><th>URL</th><th>Time</th></tr>
          {% for tool, url, ts in downloads %}
          <tr><td>{{ tool }}</td><td>{{ url }}</td><td>{{ ts }}</td></tr>
          {% endfor %}
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(249,112,102,0.15); color:var(--accent-2);">🚫</div>
        <h3>Blocked / Banned IPs (DoS &amp; Brute-Force)</h3>
      </div>
      <div class="card-desc">IPs temporarily banned by the connection/auth rate limiter.</div>
      <div class="table-wrap">
        <table>
          <tr><th>IP</th><th>Reason</th><th>Banned At</th><th>Expires</th></tr>
          {% for ip, reason, banned_at, expires_at in banned_ips %}
          <tr><td>{{ ip }}</td><td><span class="badge-banned">{{ reason }}</span></td><td>{{ banned_at }}</td><td>{{ expires_at }}</td></tr>
          {% endfor %}
          {% if not banned_ips %}
          <tr><td colspan="4" style="color:var(--text-dim);">No IPs currently banned.</td></tr>
          {% endif %}
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(249,112,102,0.15); color:var(--accent-2);">🎯</div>
        <h3>Attacker Intent Breakdown</h3>
      </div>
      <canvas id="intentChart"></canvas>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(249,112,102,0.15); color:var(--accent-2);">🧪</div>
        <h3>Captured Malware Samples (VirusTotal)</h3>
      </div>
      <div class="card-desc">Quarantined, hashed, never executed &mdash; verdicts via VirusTotal hash lookup.</div>
      <div class="table-wrap">
        <table>
          <tr><th>Captured</th><th>IP</th><th>Tool</th><th>SHA-256</th><th>Size</th><th>Status</th><th>VT Verdict</th></tr>
          {% for sha256, url, tool, src_ip, size_bytes, status, captured_at, vt_verdict, vt_malicious, vt_total in malware_samples %}
          <tr>
            <td>{{ captured_at }}</td>
            <td>{{ src_ip }}</td>
            <td>{{ tool }}</td>
            <td title="{{ url }}">{{ sha256[:12] + '…' if sha256 else '-' }}</td>
            <td>{{ size_bytes if size_bytes is not none else '-' }}</td>
            <td>{{ status }}</td>
            <td>{{ vt_verdict if vt_verdict else '-' }}{% if vt_malicious is not none and vt_total is not none %} ({{ vt_malicious }}/{{ vt_total }}){% endif %}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(255,180,84,0.15); color:var(--accent-3);">🕓</div>
        <h3>Recent Attacker Sessions</h3>
      </div>
      <div class="table-wrap">
        <table>
          <tr><th>Session</th><th>IP</th><th>Started</th><th>Commands</th><th></th></tr>
          {% for sid, ip, started, cmds in sessions %}
          <tr><td>{{ sid }}</td><td>{{ ip }}</td><td>{{ started }}</td><td>{{ cmds }}</td>
          <td><a href="/session/{{ sid }}">Replay &rarr;</a> | <a href="/session/{{ sid }}/mitigations">AI Mitigations &rarr;</a></td></tr>
          {% endfor %}
        </table>
      </div>
    </div>

  </div>
</main>

<script>
new Chart(document.getElementById('ipChart'), {
  type: 'bar',
  data: {
    labels: {{ ip_labels | tojson }},
    datasets: [{ label: 'Events', data: {{ ip_values | tojson }}, backgroundColor: '#5eead4', borderRadius: 6 }]
  },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8b93a7' }, grid: { color: 'rgba(255,255,255,0.05)' } },
      y: { ticks: { color: '#8b93a7' }, grid: { color: 'rgba(255,255,255,0.05)' } }
    }
  }
});

new Chart(document.getElementById('cmdChart'), {
  type: 'bar',
  data: {
    labels: {{ cmd_labels | tojson }},
    datasets: [{ label: 'Times run', data: {{ cmd_values | tojson }}, backgroundColor: '#f97066', borderRadius: 6 }]
  },
  options: {
    indexAxis: 'y',
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8b93a7' }, grid: { color: 'rgba(255,255,255,0.05)' } },
      y: { ticks: { color: '#8b93a7' }, grid: { color: 'rgba(255,255,255,0.05)' } }
    }
  }
});

new Chart(document.getElementById('intentChart'), {
  type: 'doughnut',
  data: {
    labels: {{ category_labels | tojson }},
    datasets: [{ data: {{ category_values | tojson }}, backgroundColor: ['#5eead4', '#f97066', '#ffb454', '#22d3ee', '#a78bfa', '#34d399'] }]
  },
  options: { plugins: { legend: { labels: { color: '#e8eaf0' } } } }
});
</script>
</body>
</html>
"""

app = Flask(__name__)

SETTINGS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>Settings - SentinelHive</title>
<style>
body { font-family: Arial, sans-serif; background: #0a0b14; color: #edeef7; margin: 0; padding: 40px; }
a { color: #5eead4; }
.card { background: #151726; border: 1px solid #262a42; border-radius: 12px; padding: 24px; max-width: 500px; }
input[type=text], input[type=password] {
  width: 100%; padding: 10px; margin-top: 8px; margin-bottom: 16px;
  background: #0a0b14; border: 1px solid #262a42; border-radius: 6px; color: #edeef7;
}
button {
  background: #5eead4; color: #06110f; border: none; padding: 10px 20px;
  border-radius: 8px; cursor: pointer; font-weight: 700;
}
.status { margin-bottom: 16px; padding: 10px; border-radius: 6px; }
.status.set { background: rgba(94,234,212,0.15); color: #5eead4; }
.status.unset { background: rgba(249,112,102,0.15); color: #f97066; }
</style>
</head>
<body>
<a href="/">&larr; Back to dashboard</a>
<h2>Settings</h2>
<div class="card">
  <div class="status {{ 'set' if has_key else 'unset' }}">
    {{ 'API key is set. AI-powered mitigations and chat are active.' if has_key else 'No API key set. Mitigations page will use the rule-based fallback only.' }}
  </div>
  <form method="POST">
    <label for="api_key">Anthropic API Key</label>
    <input type="password" id="api_key" name="api_key" placeholder="sk-ant-...">
    <button type="submit">Save Key</button>
  </form>
  {% if has_key %}
  <form method="POST" action="/settings/clear" style="margin-top: 10px;">
    <button type="submit" style="background:#f97066;">Remove Key</button>
  </form>
  {% endif %}
</div>
</body>
</html>
"""

MITIGATIONS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>Mitigations - {{ report.session_id }}</title>
<style>
body { font-family: Arial, sans-serif; background: #0a0b14; color: #edeef7; margin: 0; padding: 24px; }
a { color: #5eead4; }
.card { background: #151726; border: 1px solid #262a42; border-radius: 10px; padding: 20px; margin-top: 16px; }
.risk { font-size: 32px; font-weight: bold; color: #f97066; }
ul { padding-left: 20px; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #262a42; font-size: 14px; }
.mode-badge { display:inline-block; padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; }
.mode-llm { background: rgba(94,234,212,0.15); color: #5eead4; }
.mode-rule { background: rgba(255,180,84,0.15); color: #ffb454; }
.no-key-notice { background: rgba(249,112,102,0.12); color: #f97066; padding: 12px; border-radius: 8px; margin-top: 16px; }
#chat-log { max-height: 320px; overflow-y: auto; margin-bottom: 12px; }
.chat-msg { padding: 8px 12px; border-radius: 8px; margin-bottom: 8px; font-size: 14px; line-height: 1.5; }
.chat-msg.user { background: #1e2233; margin-left: 40px; }
.chat-msg.assistant { background: #10261f; margin-right: 40px; }
.chat-msg p { margin: 0 0 10px 0; }
.chat-msg p:last-child { margin-bottom: 0; }
.chat-msg ul, .chat-msg ol { margin: 0 0 10px 0; padding-left: 22px; }
.chat-msg li { margin-bottom: 4px; }
.chat-msg h1, .chat-msg h2, .chat-msg h3, .chat-msg h4 { margin: 14px 0 6px 0; font-size: 15px; color: #5eead4; }
.chat-msg h1:first-child, .chat-msg h2:first-child, .chat-msg h3:first-child { margin-top: 0; }
.chat-msg code { background: #0a0b14; padding: 2px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 13px; }
.chat-msg pre { background: #0a0b14; border: 1px solid #262a42; padding: 10px 12px; border-radius: 6px; overflow-x: auto; margin: 8px 0; }
.chat-msg pre code { background: none; padding: 0; }
.chat-msg strong { color: #edeef7; }
.chat-msg hr { border: none; border-top: 1px solid #262a42; margin: 12px 0; }
#chat-input-row { display: flex; gap: 8px; }
#chat-input { flex: 1; padding: 10px; background: #0a0b14; border: 1px solid #262a42; border-radius: 6px; color: #edeef7; }
#chat-send { background: #5eead4; color: #06110f; border: none; padding: 10px 18px; border-radius: 8px; cursor: pointer; font-weight: 700; }
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/9.1.6/marked.min.js"></script>
</head>
<body>
<a href="/">&larr; Back to dashboard</a>
<h2>Mitigation Report: {{ report.session_id }}</h2>
<div class="card">
<div>Risk Score</div>
<div class="risk">{{ report.risk_score }} / 100</div>
<div>Source IP: {{ report.src_ip }}</div>
<div>Mode: <span class="mode-badge {{ 'mode-llm' if report.mode == 'llm-enhanced' else 'mode-rule' }}">{{ report.mode }}</span></div>
</div>

{% if not has_key %}
<div class="no-key-notice">
  No API key set &mdash; showing rule-based mitigations only. <a href="/settings">Add your Anthropic API key</a> for real-time AI analysis and chat.
</div>
{% endif %}

{% if report.narrative %}
<div class="card">
<h3>AI Summary</h3>
<p>{{ report.narrative }}</p>
</div>
{% endif %}

<div class="card">
<h3>ATT&amp;CK Techniques Observed</h3>
<table>
<tr><th>Category</th><th>Count</th><th>Tactic</th><th>Technique</th></tr>
{% for t in report.attck_techniques %}
<tr><td>{{ t.category }}</td><td>{{ t.count }}</td><td>{{ t.tactic_id }} {{ t.tactic_name }}</td><td>{{ t.technique_id }} {{ t.technique_name }}</td></tr>
{% endfor %}
</table>
</div>

<div class="card">
<h3>Recommended Mitigations</h3>
<ul>
{% for m in report.mitigations %}
<li>{{ m }}</li>
{% endfor %}
</ul>
</div>

<div class="card">
<h3>Ask the AI about this session</h3>
{% if not has_key %}
<p style="color:#949bb8;">Set an API key in <a href="/settings">Settings</a> to use the chat.</p>
{% else %}
<div id="chat-log"></div>
<div id="chat-input-row">
  <input type="text" id="chat-input" placeholder="e.g. What's the attacker likely trying to do?">
  <button id="chat-send">Send</button>
</div>
<script>
const sessionId = {{ report.session_id | tojson }};
let history = [];
const log = document.getElementById('chat-log');
const input = document.getElementById('chat-input');
const sendBtn = document.getElementById('chat-send');

function addMessage(role, text) {
  const div = document.createElement('div');
  div.className = 'chat-msg ' + role;
  if (role === 'assistant') {
    div.innerHTML = marked.parse(text);
  } else {
    div.textContent = text;
  }
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

async function sendMessage() {
  const message = input.value.trim();
  if (!message) return;
  addMessage('user', message);
  input.value = '';
  sendBtn.disabled = true;
  sendBtn.textContent = '...';
  try {
    const res = await fetch(`/session/${sessionId}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, history })
    });
    const data = await res.json();
    addMessage('assistant', data.reply);
    history.push({ role: 'user', content: message });
    history.push({ role: 'assistant', content: data.reply });
  } catch (e) {
    addMessage('assistant', 'Error contacting the AI. Check the dashboard terminal for details.');
  }
  sendBtn.disabled = false;
  sendBtn.textContent = 'Send';
}

sendBtn.addEventListener('click', sendMessage);
input.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });
</script>
{% endif %}
</div>

</body>
</html>
"""

REPLAY_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Session Replay - {{ session_id }} &mdash; SentinelHive</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0b14;
    --card: #151726;
    --card-border: #262a42;
    --accent: #5eead4;
    --accent-2: #f97066;
    --violet: #8b5cf6;
    --text: #edeef7;
    --text-dim: #949bb8;
  }
  body {
    font-family: 'Inter', sans-serif;
    background:
      radial-gradient(circle at 12% -10%, rgba(139,92,246,0.18) 0%, transparent 45%),
      radial-gradient(circle at 88% 0%, rgba(94,234,212,0.12) 0%, transparent 40%),
      linear-gradient(180deg, #0d0f1a 0%, var(--bg) 100%);
    background-attachment: fixed;
    color: var(--text);
    margin: 0;
    padding: 32px 40px;
    min-height: 100vh;
  }
  a.back-link {
    color: var(--accent);
    text-decoration: none;
    font-weight: 600;
    font-size: 14px;
  }
  a.back-link:hover { text-decoration: underline; }
  h2 { margin: 18px 0 4px 0; font-weight: 800; letter-spacing: -0.01em; }
  .meta { color: var(--text-dim); font-size: 13px; margin-bottom: 18px; }
  button {
    background: var(--accent);
    color: #06110f;
    border: none;
    padding: 10px 20px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 700;
    font-size: 14px;
  }
  button:hover { filter: brightness(1.08); }
  .terminal {
    background: #000;
    border: 1px solid var(--card-border);
    border-radius: 10px;
    padding: 22px;
    margin-top: 18px;
    min-height: 220px;
    white-space: pre-wrap;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    line-height: 1.6;
  }
</style>
</head>
<body>
<a class="back-link" href="/">&larr; Back to dashboard</a>
<h2>Session Replay</h2>
<div class="meta">Session ID: {{ session_id }}</div>
<button onclick="replay()">&#9654; Play Session</button>
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
    malware_samples = malware_capture.recent_samples(10)
    banned_ips = db.active_bans()

    category_totals = {}
    for command, count in db.all_command_counts():
        category, _risk = analyzer.classify_and_score(command)
        category_totals[category] = category_totals.get(category, 0) + count

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
        banned_ips=banned_ips,
        category_labels=list(category_totals.keys()),
        category_values=list(category_totals.values()),
        malware_samples=malware_samples,
        github_url=GITHUB_REPO_URL,
    )


@app.route("/session/<session_id>")
def replay(session_id):
    events = db.session_events(session_id)
    return render_template_string(REPLAY_TEMPLATE, session_id=session_id, events=events)


@app.route("/session/<session_id>/mitigations")
def mitigations(session_id):
    report = mitigation_advisor.generate_report(session_id)
    return render_template_string(
        MITIGATIONS_TEMPLATE,
        report=report,
        has_key=mitigation_advisor.has_api_key(),
    )


@app.route("/session/<session_id>/chat", methods=["POST"])
def session_chat(session_id):
    data = request.get_json(force=True)
    message = data.get("message", "")
    history = data.get("history", [])
    reply = mitigation_advisor.chat_about_session(session_id, message, history)
    return jsonify({"reply": reply})


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        key = request.form.get("api_key", "").strip()
        if key:
            mitigation_advisor.save_api_key(key)
        return redirect(url_for("settings"))
    return render_template_string(
        SETTINGS_TEMPLATE,
        has_key=mitigation_advisor.has_api_key(),
    )


@app.route("/settings/clear", methods=["POST"])
def settings_clear():
    mitigation_advisor.clear_api_key()
    return redirect(url_for("settings"))


if __name__ == "__main__":
    threat_intel.init_intel_table()
    malware_capture.init_samples_table()
    app.run(host="0.0.0.0", port=5000, debug=False)
