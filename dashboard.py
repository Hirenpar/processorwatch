#!/usr/bin/env python3
"""
ProcessorWatch Dashboard — Flask web UI
Run: python dashboard.py
Then open: http://localhost:5000
"""

from flask import Flask, render_template_string, jsonify, request
import sqlite3, json, os
from datetime import datetime
from monitor import init_db, run_scan, CONFIG, load_merchants

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>ProcessorWatch — TakeCard</title>
<meta http-equiv="refresh" content="300">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #0d1b2a; color: #e8e8e8; }
  .header { background: #0d1b2a; border-bottom: 2px solid #1a6b3c;
            padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
  .header h1 { color: #fff; font-size: 22px; }
  .header .sub { color: #7fb3d3; font-size: 13px; }
  .stats { display: flex; gap: 16px; padding: 20px 24px; }
  .stat { background: #1a2a3a; border-radius: 8px; padding: 16px 20px; flex: 1; }
  .stat .num { font-size: 32px; font-weight: 700; color: #3498db; }
  .stat .lbl { font-size: 12px; color: #7fb3d3; margin-top: 4px; }
  .stat.red .num { color: #e74c3c; }
  .stat.green .num { color: #27ae60; }
  .alerts-section { padding: 0 24px 20px; }
  .alerts-section h2 { color: #e74c3c; margin-bottom: 12px; font-size: 16px; }
  .alert-card { background: #2c1515; border: 1px solid #e74c3c; border-radius: 8px;
                padding: 14px 18px; margin-bottom: 10px; }
  .alert-card .time { font-size: 11px; color: #999; }
  .alert-card .msg { color: #f39c12; margin-top: 4px; font-weight: 600; }
  .alert-card .pitch { font-size: 12px; color: #aaa; margin-top: 6px; }
  .alert-card .ack-btn { background: #27ae60; color: #fff; border: none;
                          padding: 4px 12px; border-radius: 4px; cursor: pointer;
                          font-size: 12px; margin-top: 8px; }
  .merchants-section { padding: 0 24px 40px; }
  .merchants-section h2 { color: #fff; margin-bottom: 12px; font-size: 16px; }
  .search { background: #1a2a3a; border: 1px solid #2c3e50; color: #fff;
             padding: 8px 14px; border-radius: 6px; width: 100%; max-width: 400px;
             margin-bottom: 16px; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #1a2a3a; color: #7fb3d3; padding: 10px 12px; text-align: left;
       font-weight: 600; position: sticky; top: 0; }
  td { padding: 8px 12px; border-bottom: 1px solid #1a2a3a; vertical-align: top; }
  tr:hover td { background: #1a2a3a; }
  .proc-tag { display: inline-block; background: #1a4a2a; color: #27ae60;
               padding: 2px 8px; border-radius: 4px; margin: 2px; font-size: 11px; }
  .fallback-tag { display: inline-block; background: #4a2a1a; color: #f39c12;
                   padding: 2px 8px; border-radius: 4px; margin: 2px; font-size: 11px; }
  .none-tag { color: #666; font-style: italic; font-size: 11px; }
  .status-ok { color: #27ae60; }
  .status-warn { color: #f39c12; }
  .status-alert { color: #e74c3c; font-weight: 700; }
  .status-unknown { color: #666; }
  .scan-btn { background: #3498db; color: #fff; border: none;
               padding: 8px 20px; border-radius: 6px; cursor: pointer;
               font-size: 14px; margin-right: 10px; }
  .scan-btn:hover { background: #2980b9; }
  .cat-badge { font-size: 10px; color: #7fb3d3; background: #1a2a3a;
                padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>⚡ ProcessorWatch</h1>
    <div class="sub">TakeCard | High-Risk Merchant Payment Drop Monitor</div>
  </div>
  <div style="margin-left:auto; display:flex; gap:10px; align-items:center;">
    <button class="scan-btn" onclick="triggerScan()">▶ Run Scan Now</button>
    <span style="font-size:12px; color:#666;">Auto-refreshes every 5 min</span>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="num">{{ stats.total }}</div><div class="lbl">Merchants Monitored</div></div>
  <div class="stat red"><div class="num">{{ stats.alerts_today }}</div><div class="lbl">Alerts Today</div></div>
  <div class="stat green"><div class="num">{{ stats.with_processor }}</div><div class="lbl">Active Processors Detected</div></div>
  <div class="stat"><div class="num">{{ stats.no_processor }}</div><div class="lbl">No Processor Found (cold leads)</div></div>
  <div class="stat"><div class="num">{{ stats.last_scan }}</div><div class="lbl">Last Full Scan</div></div>
</div>

{% if alerts %}
<div class="alerts-section">
  <h2>🚨 Recent Alerts ({{ alerts|length }})</h2>
  {% for a in alerts %}
  <div class="alert-card" id="alert-{{ a.id }}">
    <div class="time">{{ a.fired_at }}</div>
    <div class="msg">{{ a.message }}</div>
    {% if a.pitch %}<div class="pitch">Pitch: {{ a.pitch }}</div>{% endif %}
    {% if not a.acknowledged %}
    <button class="ack-btn" onclick="ackAlert({{ a.id }})">✓ Mark Called</button>
    {% else %}
    <span style="color:#27ae60; font-size:12px;">✓ Marked Called</span>
    {% endif %}
  </div>
  {% endfor %}
</div>
{% endif %}

<div class="merchants-section">
  <h2>All Merchants</h2>
  <input class="search" type="text" id="search" placeholder="Search by name, category, or domain..." oninput="filterTable()">
  <table id="merchantTable">
    <thead>
      <tr>
        <th>#</th>
        <th>Merchant</th>
        <th>Category</th>
        <th>Vol</th>
        <th>Processors Detected</th>
        <th>Fallback Signals</th>
        <th>Status</th>
        <th>Last Checked</th>
      </tr>
    </thead>
    <tbody>
    {% for m in merchants %}
    <tr>
      <td style="color:#666">{{ m.id }}</td>
      <td>
        <strong>{{ m.name }}</strong><br>
        <a href="https://{{ m.website }}" target="_blank" style="color:#3498db; font-size:11px;">{{ m.website }}</a>
      </td>
      <td><span class="cat-badge">{{ m.category }}</span></td>
      <td style="font-size:11px; color:#7fb3d3;">{{ m.vol_tier }}</td>
      <td>
        {% if m.processors %}
          {% for p in m.processors %}
          <span class="proc-tag">{{ p }}</span>
          {% endfor %}
        {% else %}
          <span class="none-tag">none detected</span>
        {% endif %}
      </td>
      <td>
        {% if m.fallbacks %}
          {% for f in m.fallbacks %}
          <span class="fallback-tag">{{ f }}</span>
          {% endfor %}
        {% else %}
          <span class="none-tag">—</span>
        {% endif %}
      </td>
      <td>
        {% if m.status == "alert" %}<span class="status-alert">🚨 DROPPED</span>
        {% elif m.status == "warn" %}<span class="status-warn">⚠️ Fallback</span>
        {% elif m.status == "ok" %}<span class="status-ok">✓ Active</span>
        {% else %}<span class="status-unknown">— Not scanned</span>{% endif %}
      </td>
      <td style="font-size:11px; color:#666;">{{ m.last_checked or "Never" }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<script>
function filterTable() {
  const q = document.getElementById("search").value.toLowerCase();
  document.querySelectorAll("#merchantTable tbody tr").forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
  });
}

function triggerScan() {
  fetch("/run-scan", {method: "POST"})
    .then(r => r.json())
    .then(d => { alert("Scan started! " + d.message); });
}

function ackAlert(id) {
  fetch("/ack-alert/" + id, {method: "POST"})
    .then(r => r.json())
    .then(d => { document.getElementById("alert-" + id).style.opacity = "0.5"; });
}
</script>
</body>
</html>
"""

def get_stats(conn):
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM merchants WHERE active=1")
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM alerts WHERE date(fired_at)=date('now')")
    alerts_today = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(DISTINCT merchant_id) FROM scans
        WHERE processors_detected != '{}' AND processors_detected != 'null'
        AND id IN (SELECT MAX(id) FROM scans GROUP BY merchant_id)
    """)
    with_proc = c.fetchone()[0]

    c.execute("SELECT MAX(scanned_at) FROM scans")
    last = c.fetchone()[0]
    last_scan = last[:16].replace("T", " ") if last else "Never"

    return {
        "total": total,
        "alerts_today": alerts_today,
        "with_processor": with_proc,
        "no_processor": total - with_proc,
        "last_scan": last_scan
    }

def get_merchant_data(conn):
    c = conn.cursor()
    c.execute("""
        SELECT m.id, m.name, m.website, m.category, m.vol_tier,
               s.processors_detected, s.fallback_signals, s.scanned_at
        FROM merchants m
        LEFT JOIN scans s ON s.id = (
            SELECT MAX(id) FROM scans WHERE merchant_id = m.id
        )
        WHERE m.active=1
        ORDER BY m.id
    """)
    rows = c.fetchall()
    result = []
    for r in rows:
        procs    = list(json.loads(r[5] or "{}").keys())
        fallbacks= list(json.loads(r[6] or "{}").keys())
        if r[7]:
            if procs and not fallbacks: status = "ok"
            elif fallbacks: status = "warn"
            else: status = "unknown"
        else:
            status = "unscanned"
        result.append({
            "id": r[0], "name": r[1], "website": r[2],
            "category": r[3], "vol_tier": r[4],
            "processors": procs, "fallbacks": fallbacks,
            "status": status,
            "last_checked": r[7][:16].replace("T"," ") if r[7] else None
        })
    return result

def get_alerts(conn, limit=20):
    c = conn.cursor()
    c.execute("""
        SELECT a.id, a.message, a.fired_at, a.acknowledged, m.name, m.pitch
        FROM alerts a JOIN merchants m ON a.merchant_id=m.id
        ORDER BY a.fired_at DESC LIMIT ?
    """, (limit,))
    return [{"id":r[0],"message":r[1],"fired_at":r[2][:16].replace("T"," "),
             "acknowledged":r[3],"name":r[4],"pitch":r[5]} for r in c.fetchall()]

@app.route("/")
def index():
    conn = init_db()
    return render_template_string(HTML,
        stats=get_stats(conn),
        merchants=get_merchant_data(conn),
        alerts=get_alerts(conn)
    )

@app.route("/run-scan", methods=["POST"])
def trigger_scan():
    import threading
    conn = init_db()
    t = threading.Thread(target=run_scan, args=(conn,), daemon=True)
    t.start()
    return jsonify({"message": "Scan started in background. Refresh in ~10 min."})

@app.route("/ack-alert/<int:alert_id>", methods=["POST"])
def ack_alert(alert_id):
    conn = init_db()
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    conn.commit()
    return jsonify({"ok": True})

@app.route("/api/status")
def api_status():
    conn = init_db()
    return jsonify({"stats": get_stats(conn), "merchants": get_merchant_data(conn)})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"ProcessorWatch Dashboard starting on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
