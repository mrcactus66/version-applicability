"""Zero-value StudioNet reproduction. Never use a funded account with this script.

deploy | wait TX | inspect TX | register CASE | review CASE | read CASE
Each invocation performs at most one write. An uncertain write is not retried.
"""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from eth_account import Account
from genlayer_py.client import GenLayerClient
from genlayer_py.chains import studionet
from genlayer_py.provider import GenLayerProvider
from genlayer_py.abi import calldata
import requests

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "demo.json").read_text())
LOCAL, EVIDENCE = ROOT / ".local", ROOT / "evidence"
LOCAL.mkdir(exist_ok=True)
EVIDENCE.mkdir(exist_ok=True)
key_file = LOCAL / "studio.key"
if not key_file.exists():
    key_file.write_text(Account.create().key.hex(), encoding="ascii")
account = Account.from_key(key_file.read_text(encoding="ascii"))


class StudioProvider(GenLayerProvider):
    def make_request(self, method, params):
        response = requests.post(self.url, json={"jsonrpc": "2.0", "id": 1,
            "method": method, "params": params}, timeout=(15, 30))
        response.raise_for_status()
        value = response.json()
        self._raise_on_error(value, method)
        return value


client = GenLayerClient(studionet, account)
client.provider = StudioProvider(studionet.rpc_urls["default"]["http"][0])
client.w3.provider = client.provider
client.initialize_consensus_smart_contract()


def save(name, value):
    (EVIDENCE / name).write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8", newline="\n")


def log(operation, tx):
    save(operation + "-transaction.json", {"network": "StudioNet", "chain_id": 61999,
        "transaction_id": tx, "demo_account": account.address})
    print(tx, flush=True)


def execution(row):
    return {key: row.get(key) for key in ("mode", "vote", "execution_result",
        "genvm_result", "nondet_disagree", "contract_state_hash")}


command = sys.argv[1]
if command == "deploy":
    code = (ROOT / CONFIG["contract_file"]).read_bytes()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    save("source.json", {"repository": CONFIG["repository"], "fixtures": "synthetic",
        "commit": commit, "contract_sha256": hashlib.sha256(code).hexdigest()})
    tx = client.deploy_contract(code, args=[CONFIG["repository"]], leader_only=False)
    log("deploy", tx)
elif command in ("inspect", "wait"):
    tx = sys.argv[2]
    raw = (client.wait_for_transaction_receipt(tx, interval=3000, retries=12, full_transaction=True)
           if command == "wait" else client.get_transaction(tx))
    raw_dir = LOCAL / "raw-receipts"
    raw_dir.mkdir(exist_ok=True)
    (raw_dir / (tx + ".json")).write_text(json.dumps(raw, indent=2, default=str), encoding="utf-8")
    public = {key: raw.get(key) for key in ("hash", "from_address", "to_address", "value",
        "type", "status_name", "result_name", "leader_only", "rotation_count", "num_of_rounds", "last_round")}
    public["explorer"] = "https://explorer-studio.genlayer.com/tx/" + tx
    consensus = raw.get("consensus_data") or {}
    public["executions"] = [execution(r) for r in (consensus.get("leader_receipt") or []) + (consensus.get("validators") or [])]
    encoded = raw["data"]["calldata"]
    public["calldata"] = encoded.get("readable") if isinstance(encoded, dict) else calldata.decode(base64.b64decode(encoded))
    if raw["type"] == 1:
        public["deployed_source_sha256"] = hashlib.sha256(base64.b64decode(raw["data"]["contract_code"])).hexdigest()
        assert public["deployed_source_sha256"] == hashlib.sha256((ROOT / CONFIG["contract_file"]).read_bytes()).hexdigest()
        if raw["result_name"] == "MAJORITY_AGREE" and raw["status_name"] in ("ACCEPTED", "FINALIZED"):
            (LOCAL / "contract.address").write_text(raw["to_address"], encoding="ascii")
    save(tx + "-receipt.json", public)
    print(json.dumps({k: v for k, v in public.items() if k in (
        "hash", "to_address", "status_name", "result_name", "rotation_count", "executions")}, indent=2))
elif command in ("register", "review", "read"):
    case = sys.argv[2]
    settings = CONFIG["cases"][case]
    contract = (LOCAL / "contract.address").read_text().strip()
    if command == "register":
        source = json.loads((EVIDENCE / "source.json").read_text())
        p = settings["policy"]
        filename = settings["report"]
        p["source"] = {"url": "https://raw.githubusercontent.com/" + CONFIG["repository"] + "/" + source["commit"] + "/" + filename,
            "sha256": hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()}
        args = [case, json.dumps(p)]
        save(case + "-input.json", {"contract": contract, "method": "register", "args": args})
        log(case + "-register", client.write_contract(contract, "register", args=args, value=0, leader_only=False))
    elif command == "review":
        log(case + "-review", client.write_contract(contract, "review", args=[case], value=0, leader_only=False))
    else:
        policy_json = client.read_contract(contract, "get_policy", args=[case])
        save(case + "-policy-onchain.json", json.loads(policy_json))
        result = json.loads(client.read_contract(contract, "get_review", args=[case]))
        assert result["policy_sha256"] == hashlib.sha256(policy_json.encode()).hexdigest()
        save(case + "-onchain.json", result)
        print(json.dumps({k: v for k, v in result.items() if k not in ("rows", "evidence")}, indent=2))
else:
    raise SystemExit("Unknown command")
