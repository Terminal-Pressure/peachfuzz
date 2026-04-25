import json
from pathlib import Path

REPORTS = Path("reports")
OUT = REPORTS / "summary.json"

def load_json(p):
    try:
        return json.loads(p.read_text())
    except:
        return {}

def main():
    runs = 0
    crashes = 0
    minimized = 0
    reproducers = 0
    targets = set()

    for f in REPORTS.glob("*-summary.json"):
        data = load_json(f)

        runs += data.get("iterations", 0)
        crashes += len(data.get("crashes", []))
        targets.add(data.get("target_name", "unknown"))

    summary = {
        "runs": runs,
        "crashes": crashes,
        "minimized": minimized,
        "reproducers": reproducers,
        "targets": sorted(targets),
    }

    OUT.write_text(json.dumps(summary, indent=2))
    print("[+] summary updated:", OUT)

if __name__ == "__main__":
    main()
