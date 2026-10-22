"""Offline integrity checks over published receipts; read live state separately."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
config = json.loads((ROOT / "demo.json").read_text())
source = json.loads((EVIDENCE / "source.json").read_text())
contract_hash = hashlib.sha256((ROOT / config["contract_file"]).read_bytes()).hexdigest()
assert contract_hash == source["contract_sha256"]
transactions = []
operations = sorted(EVIDENCE.glob("*-transaction.json"))
assert len(operations) == 1 + 2 * len(config["cases"])
for path in operations:
    operation = json.loads(path.read_text())
    receipt_path = EVIDENCE / (operation["transaction_id"] + "-receipt.json")
    receipt = json.loads(receipt_path.read_text())
    assert receipt["status_name"] in ("ACCEPTED", "FINALIZED")
    assert receipt["result_name"] == "MAJORITY_AGREE"
    assert receipt["leader_only"] is False and receipt["value"] == 0
    assert any(r["mode"] == "leader" and r["execution_result"] == "SUCCESS" for r in receipt["executions"])
    if receipt["type"] == 1:
        assert receipt["deployed_source_sha256"] == contract_hash
    transactions.append({"operation": path.stem.replace("-transaction", ""),
        "transaction_id": receipt["hash"], "status": receipt["status_name"],
        "consensus": receipt["result_name"], "rotations": receipt["rotation_count"], "receipt": receipt_path.name})
for case, settings in config["cases"].items():
    p = json.loads((EVIDENCE / (case + "-policy-onchain.json")).read_text())
    result = json.loads((EVIDENCE / (case + "-onchain.json")).read_text())
    canonical = json.dumps(p, sort_keys=True, separators=(",", ":"))
    assert result["policy_sha256"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert p["source"]["url"] == "https://raw.githubusercontent.com/" + source["repository"] + "/" + source["commit"] + "/" + settings["report"]
    assert p["source"]["sha256"] == hashlib.sha256((ROOT / settings["report"]).read_bytes()).hexdigest()
    for key, expected in settings["expected"].items():
        assert result[key] == expected, (case, key, result[key])
(EVIDENCE / "index.json").write_text(json.dumps({"network": "StudioNet", "chain_id": 61999,
    "fixtures": "synthetic", "source_sha256_verified": True, "results_verified": True,
    "contract": (ROOT / ".local/contract.address").read_text().strip(),
    "transactions": transactions}, indent=2) + "\n", encoding="utf-8", newline="\n")
print("Verified deployed source, seven zero-value consensus transactions, frozen policies, and three onchain results.")
