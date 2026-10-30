"""Application Runner Entrypoint

Executes the ClickjackShield web application server.
"""

import os
import sys

# Ensure user site-packages are accessible across different Python runners
user_site = os.path.expanduser(r"~\AppData\Local\Programs\Python\Python314\Lib\site-packages")
if os.path.isdir(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)

from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "True").lower() in ("true", "1", "yes")

    print("=" * 70)
    print("  CLICKJACKING DETECTION & PREVENTION PLATFORM (ClickjackShield)")
    print("=" * 70)
    print(f" * Server running on: http://{host}:{port}/")
    print(f" * Environment:       {os.environ.get('FLASK_ENV', 'development')}")
    print(f" * Database:          {app.config.get('DATABASE_PATH')}")
    print(" * Defensive mode:    SSRF defense active, HTTPS restricted")
    print("=" * 70)

    app.run(host=host, port=port, debug=debug)
