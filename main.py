#!/usr/bin/env python3
"""
ProcessorWatch production entrypoint for Railway.
Serves the dashboard (required for Railway health checks) and runs scheduled scans.
"""

import os

from dashboard import app
from monitor import init_db, run_scheduler
from seed_merchants import seed_database


def ensure_database():
    conn = init_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM merchants").fetchone()[0]
        if count == 0:
            inserted = seed_database(conn)
            print(f"Auto-seeded {inserted} merchants on first deploy.")
        else:
            print(f"Database ready with {count} merchants.")
    finally:
        conn.close()


if __name__ == "__main__":
    ensure_database()
    run_scheduler()
    port = int(os.environ.get("PORT", 5000))
    print(f"ProcessorWatch live on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
