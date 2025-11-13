# append_subdomains.py
import json
import os

# Paths (use output/ folder)
BASE = os.path.dirname(__file__)
JSON_PATH = os.path.join(BASE, "output", "harvester_mckvie.json")
SUBDOMAINS_PATH = os.path.join(BASE, "output", "subdomains.txt")

# Load existing JSON safely
if not os.path.exists(JSON_PATH):
    print(f"❌ {JSON_PATH} not found. Please ensure harvester_mckvie.json exists in output/ folder.")
    exit(1)

with open(JSON_PATH, "r", encoding="utf-8") as f:
    try:
        data = json.load(f)
    except json.JSONDecodeError as e:
        print("❌ JSON decode error:", e)
        exit(1)

# Read subdomains file
if not os.path.exists(SUBDOMAINS_PATH):
    print(f"❌ {SUBDOMAINS_PATH} not found. Place your subdomains (one per line) into output/subdomains.txt")
    exit(1)

with open(SUBDOMAINS_PATH, "r", encoding="utf-8") as f:
    subdomains = [line.strip() for line in f if line.strip()]

if "subdomains" not in data:
    data["subdomains"] = []

existing = set(data["subdomains"])
added = 0
for sub in subdomains:
    if sub not in existing:
        data["subdomains"].append(sub)
        added += 1

with open(JSON_PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4)

print(f"✅ Appended {added} new subdomains to {JSON_PATH}")
