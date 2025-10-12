#!/usr/bin/env python3
"""
Start the FastAPI app with uvicorn in a background thread and run a quick smoke test.
This script is intended for local verification only.
"""
import threading
import time
import requests
import sys

def start_uvicorn():
    import uvicorn
    # Run uvicorn programmatically; this call blocks but will be run in a daemon thread.
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, log_level="info")

def run_smoke_tests():
    APP = "http://127.0.0.1:8000"
    session = requests.Session()
    session.headers.update({"Accept": "application/json"})
    print("== ROOT ==")
    try:
        r = session.get(APP + "/", timeout=10)
        print("GET /", r.status_code)
        print(r.text[:500])
    except Exception as e:
        print("GET / ERROR", e)

    print("\n== POST /auth/login ==")
    creds = {"email": "qa+smoketest@expedita.app", "password": "ExpeditaTest!123"}
    try:
        r = session.post(APP + "/auth/login", json=creds, timeout=10)
        print("POST /auth/login", r.status_code)
        try:
            print(r.json())
        except Exception:
            print(r.text)
    except Exception as e:
        print("LOGIN ERROR", e)
        return

    # If login returned a token, try both cookie and header flows
    token = None
    try:
        j = r.json()
        token = j.get("access_token")
    except Exception:
        token = None

    # Check Set-Cookie header presence
    set_cookie = r.headers.get("Set-Cookie")
    print("Set-Cookie header:", "present" if set_cookie else "absent")
    if set_cookie:
        print(set_cookie.split(";")[0])

    print("\n== GET /auth/me using cookie/session ==")
    try:
        r2 = session.get(APP + "/auth/me", timeout=10)
        print("GET /auth/me (cookie) ->", r2.status_code)
        try:
            print(r2.json())
        except Exception:
            print(r2.text)
    except Exception as e:
        print("ME (cookie) ERROR", e)

    if token:
        print("\n== GET /auth/me using Authorization header ==")
        try:
            h = {"Authorization": f"Bearer {token}"}
            r3 = requests.get(APP + "/auth/me", headers=h, timeout=10)
            print("GET /auth/me (header) ->", r3.status_code)
            try:
                print(r3.json())
            except Exception:
                print(r3.text)
        except Exception as e:
            print("ME (header) ERROR", e)
    else:
        print("\nNo token available from login; header test skipped.")

if __name__ == "__main__":
    # Start server in a daemon thread
    t = threading.Thread(target=start_uvicorn, daemon=True)
    t.start()
    # Wait for server to boot
    for i in range(12):
        try:
            requests.get("http://127.0.0.1:8000/", timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("Server did not start in time; aborting smoke tests.")
        sys.exit(1)

    # Run smoke tests
    run_smoke_tests()