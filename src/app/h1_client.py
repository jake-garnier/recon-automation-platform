import os
import time
import requests
from dotenv import load_dotenv

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(_REPO_ROOT, ".env"))

BASE_URL = "https://api.hackerone.com/v1"
API_USERNAME = os.environ["H1_API_USERNAME"]
API_TOKEN = os.environ["H1_API_TOKEN"]


def _auth():
    return (API_USERNAME, API_TOKEN)


def _get(endpoint, params=None):
    url = f"{BASE_URL}{endpoint}"
    resp = requests.get(url, auth=_auth(), params=params, headers={
        "Accept": "application/json"
    })
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", 30))
        print(f"  Rate limited, sleeping {retry_after}s...")
        time.sleep(retry_after)
        return _get(endpoint, params)
    resp.raise_for_status()
    return resp.json()


def fetch_programs(page_size=100):
    """Fetch all hacktivity programs with pagination."""
    all_programs = []
    page = 1
    while True:
        print(f"  Fetching programs page {page}...")
        data = _get("/hackers/programs", params={
            "page[size]": page_size,
            "page[number]": page,
        })
        programs = data.get("data", [])
        if not programs:
            break
        all_programs.extend(programs)
        links = data.get("links", {})
        if not links.get("next"):
            break
        page += 1
        time.sleep(0.2)  # be nice to the API
    return all_programs


def fetch_structured_scopes(program_handle, page_size=100):
    """Fetch structured scopes for a specific program."""
    all_scopes = []
    page = 1
    while True:
        data = _get(f"/hackers/programs/{program_handle}/structured_scopes", params={
            "page[size]": page_size,
            "page[number]": page,
        })
        scopes = data.get("data", [])
        if not scopes:
            break
        all_scopes.extend(scopes)
        links = data.get("links", {})
        if not links.get("next"):
            break
        page += 1
        time.sleep(0.2)
    return all_scopes
