#!/usr/bin/env python3
"""
ProcessorWatch - High-Risk Merchant Payment Drop Monitor
For TakeCard | Built to alert when merchants lose processing
"""

import sqlite3, requests, json, time, hashlib, smtplib, os
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — edit these before deploying
# ─────────────────────────────────────────────────────────────────────────────
CONFIG = {
    "check_interval_hours": 12,      # How often to scan (12 = twice/day)
    "alert_email_from": os.getenv("PW_ALERT_EMAIL_FROM", "alerts@yourdomain.com"),
    "alert_email_to":   os.getenv("PW_ALERT_EMAIL_TO", "you@example.com"),
    "smtp_host":        os.getenv("PW_SMTP_HOST", "smtp.gmail.com"),
    "smtp_port":        int(os.getenv("PW_SMTP_PORT", "587")),
    "smtp_user":        os.getenv("PW_SMTP_USER", ""),
    "smtp_pass":        os.getenv("PW_SMTP_PASS", ""),
    # Twilio SMS (optional)
    "twilio_sid":       os.getenv("PW_TWILIO_SID", ""),
    "twilio_token":     os.getenv("PW_TWILIO_TOKEN", ""),
    "twilio_from":      os.getenv("PW_TWILIO_FROM", ""),
    "twilio_to":        os.getenv("PW_TWILIO_TO", ""),          # Your cell number e.g. +19135551234
    "db_path":          os.getenv("PW_DB_PATH", "processorwatch.db"),
    "request_timeout":  int(os.getenv("PW_REQUEST_TIMEOUT", "12")),
    "user_agent": os.getenv("PW_USER_AGENT", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
}

# ─────────────────────────────────────────────────────────────────────────────
# PAYMENT PROCESSOR FINGERPRINTS
# These are JS files, script tags, form attributes, and DOM patterns that
# indicate which processor a merchant is using.
# ─────────────────────────────────────────────────────────────────────────────
PROCESSOR_SIGNALS = {
    "Stripe":           ["js.stripe.com", "stripe-js", "StripeElement", "data-stripe", "__stripe"],
    "Shopify Payments": ["shop.app/pay", "shopify-payment", "cdn.shopify.com/shopifycloud/checkout"],
    "PayPal":           ["paypal.com/sdk", "paypalobjects.com", "paypal-button", "paypal_checkout"],
    "Square":           ["squareup.com/payments", "square-payment", "sq-payment-form", "Web Payments SDK"],
    "Authorize.net":    ["authorize.net", "AcceptUI", "anet_fields"],
    "Braintree":        ["braintreegateway.com", "braintree-hosted-fields", "braintree.js"],
    "Adyen":            ["adyen.com/checkoutshopper", "adyen-checkout"],
    "NMI":              ["secure.networkmerchants.com", "CollectJS"],
    "Checkout.com":     ["cdn.checkout.com", "frames.checkout.com"],
    "Klarna":           ["klarna.com/us/payments", "klarna-checkout"],
    "Affirm":           ["cdn1.affirm.com", "affirm.com/js"],
    "Sezzle":           ["sezzle.com/v2/javascript"],
    "WooCommerce":      ["woocommerce", "wc-payment"],
    "2Checkout":        ["2co.com", "avangate.com"],
    "PaymentCloud":     ["paymentcloudinc", "paymentcloud"],
}

# Signs a merchant may have LOST their processor:
FALLBACK_SIGNALS = {
    "crypto_accepted":    ["bitcoin", "ethereum", "crypto", "coinbase commerce", "bitpay", "coinpayments"],
    "check_money_order":  ["money order", "check or money order", "pay by check", "cashiers check", "personal check"],
    "wire_transfer":      ["wire transfer", "bank wire", "ach only", "bank transfer only"],
    "no_card_available":  ["credit card temporarily", "card payment unavailable", "cards not accepted",
                           "payment method unavailable", "processing issues"],
    "paypal_only":        ["we only accept paypal", "paypal only", "paypal payments only"],
    "venmo_zelle":        ["venmo", "zelle", "cash app"],
    "contact_to_pay":     ["contact us to complete", "call to purchase", "email to place order"],
}

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(CONFIG["db_path"])
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS merchants (
            id INTEGER PRIMARY KEY,
            name TEXT, website TEXT UNIQUE, category TEXT,
            pitch TEXT, vol_tier TEXT,
            active INTEGER DEFAULT 1,
            added_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            merchant_id INTEGER,
            scanned_at TEXT,
            processors_detected TEXT,
            fallback_signals TEXT,
            page_hash TEXT,
            http_status INTEGER,
            error TEXT,
            FOREIGN KEY(merchant_id) REFERENCES merchants(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            merchant_id INTEGER,
            alert_type TEXT,
            message TEXT,
            fired_at TEXT DEFAULT CURRENT_TIMESTAMP,
            acknowledged INTEGER DEFAULT 0,
            FOREIGN KEY(merchant_id) REFERENCES merchants(id)
        )
    """)
    conn.commit()
    return conn

def load_merchants(conn):
    c = conn.cursor()
    c.execute("SELECT id, name, website, category, pitch, vol_tier FROM merchants WHERE active=1")
    return c.fetchall()

def get_last_scan(conn, merchant_id):
    c = conn.cursor()
    c.execute("""
        SELECT processors_detected, fallback_signals, page_hash
        FROM scans WHERE merchant_id=? ORDER BY scanned_at DESC LIMIT 1
    """, (merchant_id,))
    return c.fetchone()

def save_scan(conn, merchant_id, processors, fallbacks, page_hash, status, error=None):
    c = conn.cursor()
    c.execute("""
        INSERT INTO scans (merchant_id, scanned_at, processors_detected, fallback_signals, page_hash, http_status, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (merchant_id, datetime.now(timezone.utc).isoformat(),
          json.dumps(processors), json.dumps(fallbacks), page_hash, status, error))
    conn.commit()

def save_alert(conn, merchant_id, alert_type, message):
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (merchant_id, alert_type, message)
        VALUES (?, ?, ?)
    """, (merchant_id, alert_type, message))
    conn.commit()
    return c.lastrowid

# ─────────────────────────────────────────────────────────────────────────────
# SCANNING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def fetch_page(url):
    """Fetch a merchant checkout or homepage. Returns (html, status_code, error)"""
    headers = {"User-Agent": CONFIG["user_agent"]}
    # Try checkout page first (most signal-rich)
    for path in ["/checkout", "/cart", "/shop", ""]:
        try:
            target = f"https://{url.rstrip('/')}{path}" if not url.startswith("http") else url + path
            r = requests.get(target, headers=headers, timeout=CONFIG["request_timeout"],
                           allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 500:
                return r.text, r.status_code, None
        except Exception as e:
            continue
    # Fallback to plain homepage
    try:
        target = f"https://{url}" if not url.startswith("http") else url
        r = requests.get(target, headers=headers, timeout=CONFIG["request_timeout"])
        return r.text, r.status_code, None
    except Exception as e:
        return "", 0, str(e)

def detect_processors(html):
    """Returns dict of detected processors and fallback signals"""
    html_lower = html.lower()
    detected = {}
    for processor, signals in PROCESSOR_SIGNALS.items():
        hits = [s for s in signals if s.lower() in html_lower]
        if hits:
            detected[processor] = hits

    fallbacks = {}
    for signal_type, keywords in FALLBACK_SIGNALS.items():
        hits = [k for k in keywords if k.lower() in html_lower]
        if hits:
            fallbacks[signal_type] = hits

    return detected, fallbacks

def page_hash(html):
    """Hash of just the payment-relevant section of the page"""
    # Extract script tags and payment-related divs for comparison
    soup = BeautifulSoup(html, "html.parser")
    scripts = " ".join(s.get("src", "") for s in soup.find_all("script") if s.get("src"))
    forms   = str(soup.find_all("form"))
    relevant = scripts + forms
    return hashlib.md5(relevant.encode()).hexdigest()

def analyze_change(old_scan, new_processors, new_fallbacks, merchant):
    """Compare current scan to last scan. Return alert message or None."""
    if not old_scan:
        return None  # First scan, no baseline

    old_processors = json.loads(old_scan[0] or "{}")
    old_fallbacks  = json.loads(old_scan[1] or "{}")

    alerts = []
    name = merchant[1]
    url  = merchant[2]

    # LOST a processor that was there before
    lost = set(old_processors.keys()) - set(new_processors.keys())
    if lost:
        for p in lost:
            alerts.append(f"🚨 PROCESSOR DROP DETECTED: {name} ({url}) — {p} GONE from checkout page")

    # GAINED fallback signals that weren't there before
    new_fall = set(new_fallbacks.keys()) - set(old_fallbacks.keys())
    for f in new_fall:
        if f in ["crypto_accepted", "check_money_order", "wire_transfer", "no_card_available"]:
            alerts.append(f"⚠️  FALLBACK SIGNAL: {name} ({url}) — now showing '{f}' on site")

    # Had processors before, now has NONE
    if old_processors and not new_processors:
        alerts.append(f"🚨 CRITICAL: {name} ({url}) — ALL payment processors DISAPPEARED from checkout")

    return alerts if alerts else None

# ─────────────────────────────────────────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────────────────────────────────────────
def send_email_alert(subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"]    = CONFIG["alert_email_from"]
        msg["To"]      = CONFIG["alert_email_to"]
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))
        with smtplib.SMTP(CONFIG["smtp_host"], CONFIG["smtp_port"]) as s:
            s.starttls()
            s.login(CONFIG["smtp_user"], CONFIG["smtp_pass"])
            s.send_message(msg)
        print(f"  ✉️  Email alert sent: {subject}")
    except Exception as e:
        print(f"  ✉️  Email failed: {e}")

def send_sms_alert(message):
    """Requires: pip install twilio + fill in CONFIG"""
    if not CONFIG["twilio_sid"]:
        print(f"  📱 SMS (Twilio not configured): {message[:80]}")
        return
    try:
        from twilio.rest import Client
        client = Client(CONFIG["twilio_sid"], CONFIG["twilio_token"])
        client.messages.create(body=message[:1500],
                               from_=CONFIG["twilio_from"],
                               to=CONFIG["twilio_to"])
        print(f"  📱 SMS sent")
    except Exception as e:
        print(f"  📱 SMS failed: {e}")

def fire_alert(conn, merchant, alert_messages):
    merchant_id = merchant[0]
    name        = merchant[1]
    pitch       = merchant[4]
    category    = merchant[3]

    for msg in alert_messages:
        save_alert(conn, merchant_id, "processor_change", msg)
        print("="*60)
        print(f"ALERT FIRED: {msg}")
        print("="*60)

    full_body = f"""
    <h2 style="color:#c0392b">ProcessorWatch Alert — TakeCard</h2>
    <p><strong>Fired at:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
    <hr>
    {"".join(f"<p><strong>{m}</strong></p>" for m in alert_messages)}
    <hr>
    <h3>Your pitch for {name}:</h3>
    <p>{pitch}</p>
    <p><strong>Category:</strong> {category}</p>
    <p><strong>Website:</strong> {merchant[2]}</p>
    <br>
    <p style="color:#27ae60"><strong>Call them NOW — you have a 24-48hr window before a competitor does.</strong></p>
    """

    subject = f"🚨 ProcessorWatch: {name} may have lost processing — CALL NOW"
    send_email_alert(subject, full_body)
    sms_msg = f"PROCESSORWATCH ALERT: {name} ({merchant[2]}) - potential processor drop. CALL NOW. {alert_messages[0][:100]}"
    send_sms_alert(sms_msg)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN LOOP
# ─────────────────────────────────────────────────────────────────────────────
def run_scan(conn=None, verbose=True):
    own_conn = conn is None
    if own_conn:
        conn = init_db()
    try:
        merchants = load_merchants(conn)
        print(f"\n[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}] Scanning {len(merchants)} merchants...")
        alerts_fired = 0

        for merchant in merchants:
            mid, name, url, category, pitch, vol = merchant
            if verbose:
                print(f"  Checking {name} ({url})...", end=" ", flush=True)

            html, status, error = fetch_page(url)

            if error or not html:
                if verbose: print(f"ERROR ({error})")
                save_scan(conn, mid, {}, {}, "", status, error)
                continue

            processors, fallbacks = detect_processors(html)
            ph = page_hash(html)

            old_scan = get_last_scan(conn, mid)
            save_scan(conn, mid, processors, fallbacks, ph, status, error)

            alert_msgs = analyze_change(old_scan, processors, fallbacks, merchant)

            if alert_msgs:
                fire_alert(conn, merchant, alert_msgs)
                alerts_fired += 1
                if verbose: print(f"🚨 ALERT")
            else:
                procs = list(processors.keys()) if processors else ["none detected"]
                if verbose: print(f"OK ({', '.join(procs)})")

            time.sleep(0.5)  # Be respectful — don't hammer sites

        print(f"\nScan complete. {alerts_fired} alerts fired.")
        return alerts_fired
    finally:
        if own_conn:
            conn.close()

def run_scheduler():
    """Run on a schedule — call this for production deployment"""
    import threading
    hours = CONFIG["check_interval_hours"]
    print(f"ProcessorWatch running. Scanning every {hours} hours.")

    def loop():
        while True:
            run_scan(verbose=False)
            print(f"Next scan in {hours} hours...")
            time.sleep(hours * 3600)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    import sys
    conn = init_db()
    if "--scan" in sys.argv:
        run_scan(conn, verbose=True)
    elif "--schedule" in sys.argv:
        t = run_scheduler()
        t.join()  # Keep process alive
    else:
        print("Usage: python monitor.py --scan       (run once)")
        print("       python monitor.py --schedule   (run forever on timer)")
