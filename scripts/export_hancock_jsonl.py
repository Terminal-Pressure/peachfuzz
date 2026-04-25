import json
import argparse


def convert_record(r):
    meta = r.get("metadata", {})

    return {
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are Hancock, an AI cybersecurity assistant. "
                    "Analyze malformed or adversarial inputs safely and explain root causes."
                )
            },
            {
                "role": "user",
                "content": r.get("input", "")
            },
            {
                "role": "assistant",
                "content": r.get("output", "")
            }
        ],
        "metadata": {
            "mode": "fuzz",
            "category": meta.get("category"),
            "severity": meta.get("severity"),
            "weight": meta.get("weight"),
            "target": meta.get("target_name"),
            "exception": meta.get("exception"),
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with open(args.input, "r") as f:
        records = [json.loads(line) for line in f]

    with open(args.output, "w") as f:
        for r in records:
            out = convert_record(r)
            f.write(json.dumps(out, ensure_ascii=False) + "\n")

    print(f"[+] wrote {len(records)} records → {args.output}")


if __name__ == "__main__":
    main()
