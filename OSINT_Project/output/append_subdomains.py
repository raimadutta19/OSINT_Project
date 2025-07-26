import json

# File paths
json_path = "harvester_mckvie.json"
subdomains_path = "subdomains.txt"

# Load existing JSON
with open(json_path, "r") as f:
    data = json.load(f)

# Read subdomains from txt
with open(subdomains_path, "r") as f:
    subdomains = [line.strip() for line in f if line.strip()]

# Append subdomains if not already there
if "subdomains" not in data:
    data["subdomains"] = []

# Add unique subdomains
existing = set(data["subdomains"])
for sub in subdomains:
    if sub not in existing:
        data["subdomains"].append(sub)

# Save updated JSON
with open(json_path, "w") as f:
    json.dump(data, f, indent=4)

print("✅ Subdomains appended to harvester_mckvie.json")
