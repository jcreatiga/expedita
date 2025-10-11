#!/usr/bin/env python3
import requests, json, sys

APP = "https://expedita-production.up.railway.app"

def do_get(path):
    url = APP + path
    try:
        r = requests.get(url, timeout=30)
        print(f"GET {path} {r.status_code}")
        print(r.text)
        return r
    except Exception as e:
        print(f"GET {path} ERROR: {e}")
        return None

if __name__ == "__main__":
    print("== ROOT ==")
    do_get("/")

    print("\n== POST /auth/login ==")
    token = None
    try:
        resp = requests.post(
            APP + "/auth/login",
            json={"email": "qa+smoketest@expedita.app", "password": "ExpeditaTest!123"},
            timeout=30
        )
        print("POST /auth/login", resp.status_code)
        print(resp.text)
        try:
            data = resp.json()
            token = data.get("access_token")
        except Exception:
            token = None
    except Exception as e:
        print("LOGIN ERROR", e)
        token = None

    print("\n== GET /auth/me ==")
    if token:
        try:
            resp = requests.get(APP + "/auth/me", headers={"Authorization": f"Bearer {token}"}, timeout=30)
            print("GET /auth/me", resp.status_code)
            print(resp.text)
        except Exception as e:
            print("ME ERROR", e)
    else:
        print("No token obtained; skipping /auth/me")