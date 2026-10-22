import copy
import hashlib
import json
from pathlib import Path
import re
import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO = "mrcactus66/version-applicability"
URL = "https://raw.githubusercontent.com/" + REPO + "/" + "b"*40 + "/examples/branches.txt"
BODY = (ROOT / "examples/branches.txt").read_text()
RANGE_QUOTE = BODY[BODY.index("AsterCache is affected"):BODY.index("Only Linux")].strip()
SCOPE_QUOTE = BODY[BODY.index("Only Linux"):].strip()


def policy(body=BODY):
    return {"product": "AsterCache", "inventory": [
        {"id": "lower", "version": "2.4.0", "deployment": "Linux; optional shared-cache plugin enabled"},
        {"id": "fixed", "version": "2.4.7", "deployment": "Linux; optional shared-cache plugin enabled"},
        {"id": "branch3", "version": "3.0.2", "deployment": "Linux; optional shared-cache plugin enabled"},
        {"id": "excluded", "version": "3.0.1", "deployment": "Windows; optional shared-cache plugin enabled"},
    ], "source": {"url": URL, "sha256": hashlib.sha256(body.encode()).hexdigest()}}


def evidence():
    return {"coverage": "EXACT", "ranges": [
        {"lower": "2.4.0", "upper": "2.4.7", "lower_inclusive": True, "upper_inclusive": False},
        {"lower": "3.0.0", "upper": "3.0.2", "lower_inclusive": True, "upper_inclusive": True}],
        "range_quote": RANGE_QUOTE, "items": [{"id": i, "scope": s, "quote": SCOPE_QUOTE} for i,s in
            [("lower", "APPLIES"), ("fixed", "APPLIES"), ("branch3", "APPLIES"), ("excluded", "DOES_NOT_APPLY")]]}


@pytest.fixture
def contract(direct_deploy):
    return direct_deploy(str(ROOT / "contracts/version_applicability.py"), REPO, sdk_version="v0.2.12")


def mock(vm, row=None, body=BODY, status=200):
    vm.mock_web("^"+re.escape(URL)+"$", {"status": status, "body": body})
    vm.mock_llm("Read one software advisory", json.dumps(row or evidence()))


def setup(contract, vm, p=None, row=None, body=BODY):
    contract.register("case", json.dumps(p or policy(body)))
    mock(vm, row, body)


def review(contract):
    contract.review("case")
    return json.loads(contract.get_review("case"))


def test_boundaries_multiple_branches_and_platform(contract, direct_vm):
    assert contract.get_item_status("case", "lower") == "UNREVIEWED"
    setup(contract, direct_vm)
    r = review(contract)
    assert [x["status"] for x in r["items"]] == ["AFFECTED", "OUTSIDE_REPORTED_RANGE", "AFFECTED", "NOT_APPLICABLE"]
    assert [x["matched_ranges"] for x in r["items"]] == [[0], [], [1], []]
    assert r["policy_sha256"] == hashlib.sha256(contract.get_policy("case").encode()).hexdigest()
    assert direct_vm.run_validator() is True


@pytest.mark.parametrize("v,affected", [("2.3.99", False), ("2.4.0", True), ("2.4.6", True), ("2.4.7", False),
    ("2.4.10", False), ("3.0.0", True), ("3.0.2", True), ("3.0.3", False), ("10.0.0", False)])
def test_membership_uses_numeric_versions(contract, direct_vm, v, affected):
    p = policy(); p["inventory"][0]["version"] = v
    setup(contract, direct_vm, p)
    assert (review(contract)["items"][0]["status"] == "AFFECTED") is affected


def test_unknown_prerequisite_is_not_treated_as_unaffected(contract, direct_vm):
    row = evidence(); row["items"][0].update(scope="UNKNOWN", quote="")
    setup(contract, direct_vm, row=row)
    assert review(contract)["items"][0]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("coverage", ["UNKNOWN", "UNSUPPORTED"])
def test_unsupported_or_unknown_ranges_withhold_numeric_classification(contract, direct_vm, coverage):
    row = evidence(); row.update(coverage=coverage, ranges=[], range_quote="")
    setup(contract, direct_vm, row=row)
    assert [r["status"] for r in review(contract)["items"]] == ["INCOMPLETE"]*3+["NOT_APPLICABLE"]
    assert direct_vm.run_validator() is True


def test_permissionless_review_and_sealed_policy(contract, direct_vm, direct_bob):
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("Only owner"):
        contract.register("case", json.dumps(policy()))
    setup(contract, direct_vm)
    with direct_vm.prank(direct_bob):
        review(contract)
    with direct_vm.expect_revert("already reviewed"):
        review(contract)
    with direct_vm.expect_revert("duplicate"):
        contract.register("case", json.dumps(policy()))
    with direct_vm.expect_revert("Unknown inventory"):
        contract.get_item_status("case", "missing")


@pytest.mark.parametrize("v", ["2.4", "v2.4.0", "02.4.0", "2.4.0-rc.1", "2.4.0+build", "2.4.0 ", "1000000.0.0", 240])
def test_noncanonical_inventory_version_rejected(contract, direct_vm, v):
    p = policy(); p["inventory"][0]["version"] = v
    with direct_vm.expect_revert():
        contract.register("case", json.dumps(p))


@pytest.mark.parametrize("mutation", [
    {"coverage": "SAFE"}, {"range_quote": "Made-up advisory range"}, {"ranges": []},
    {"items": []}, {"extra": True}, {"coverage": "UNKNOWN"},
])
def test_invalid_envelope_aborts(contract, direct_vm, mutation):
    row = evidence(); row.update(mutation)
    setup(contract, direct_vm, row=row)
    with direct_vm.expect_revert():
        review(contract)
    assert contract.get_item_status("case", "lower") == "UNREVIEWED"


@pytest.mark.parametrize("mutation", [
    {"lower": "2.4.1"}, {"lower": "4.0.0"}, {"upper": "2.4.0", "lower_inclusive": False},
    {"lower": "", "lower_inclusive": True}, {"lower_inclusive": 1}, {"upper": "2.4.7-rc.1"},
])
def test_malformed_or_unanchored_range_aborts(contract, direct_vm, mutation):
    row = evidence(); row["ranges"][0].update(mutation)
    setup(contract, direct_vm, row=row)
    with direct_vm.expect_revert():
        review(contract)


def test_disjoint_ranges_must_be_ordered(contract, direct_vm):
    row = evidence(); row["ranges"].reverse()
    setup(contract, direct_vm, row=row)
    with direct_vm.expect_revert("sorted"):
        review(contract)


def test_version_substring_cannot_anchor_boundary(contract, direct_vm):
    body = BODY.replace("2.4.7", "12.4.7")
    row = evidence(); row["range_quote"] = row["range_quote"].replace("2.4.7", "12.4.7")
    setup(contract, direct_vm, p=policy(body), row=row, body=body)
    with direct_vm.expect_revert("exact anchor"):
        review(contract)


@pytest.mark.parametrize("mutation", [{"id": "wrong"}, {"scope": "SAFE"}, {"quote": "invented"}, {"quote": ""}])
def test_bad_scope_evidence_aborts(contract, direct_vm, mutation):
    row = evidence(); row["items"][0].update(mutation)
    setup(contract, direct_vm, row=row)
    with direct_vm.expect_revert():
        review(contract)


@pytest.mark.parametrize("bad", ["main/examples/a.txt", "b"*40+"/../a.txt", "b"*40+"/a.txt#x"])
def test_source_must_be_pinned_and_bounded(contract, direct_vm, bad):
    p = policy(); p["source"]["url"] = "https://raw.githubusercontent.com/"+REPO+"/"+bad
    with direct_vm.expect_revert():
        contract.register("case", json.dumps(p))


@pytest.mark.parametrize("mode", ["hash", "http", "empty", "oversize"])
def test_source_failure_preserves_retry(contract, direct_vm, mode):
    setup(contract, direct_vm)
    direct_vm.clear_mocks()
    mock(direct_vm, body={"hash": BODY+"changed", "http": BODY, "empty": "", "oversize": "x"*16001}[mode], status=503 if mode == "http" else 200)
    with direct_vm.expect_revert():
        review(contract)
    direct_vm.clear_mocks(); mock(direct_vm)
    assert review(contract)["items"][0]["status"] == "AFFECTED"


def test_validator_accepts_alternate_quote_but_rejects_scope_or_boundary_change(contract, direct_vm):
    setup(contract, direct_vm); review(contract)
    row = evidence(); row["items"][0]["quote"] = SCOPE_QUOTE.splitlines()[0]
    direct_vm.clear_mocks(); mock(direct_vm, row)
    assert direct_vm.run_validator() is True
    row["items"][0]["scope"] = "DOES_NOT_APPLY"
    direct_vm.clear_mocks(); mock(direct_vm, row)
    assert direct_vm.run_validator() is False
    direct_vm.clear_mocks(); mock(direct_vm)
    forged = evidence(); forged["ranges"][0]["upper_inclusive"] = True
    assert direct_vm.run_validator(leader_result=forged) is False
    forged = evidence(); forged["ranges"] = forged["ranges"][:1]
    assert direct_vm.run_validator(leader_result=forged) is False
    assert direct_vm.run_validator(leader_result={}) is False
    assert direct_vm.run_validator(leader_error=ValueError("failed")) is False


@pytest.mark.parametrize("lower,upper,li,ui,v,affected", [
    ("", "2.4.7", False, False, "0.0.0", True),
    ("3.0.0", "", True, False, "10.0.0", True),
    ("3.0.2", "3.0.2", True, True, "3.0.2", True),
    ("2.4.0", "2.4.7", False, True, "2.4.0", False),
    ("2.4.0", "2.4.7", False, True, "2.4.7", True),
])
def test_endpoint_modes(contract, direct_vm, lower, upper, li, ui, v, affected):
    p = policy(); p["inventory"][0]["version"] = v
    row = evidence(); row["ranges"] = [{"lower": lower, "upper": upper, "lower_inclusive": li, "upper_inclusive": ui}]
    setup(contract, direct_vm, p=p, row=row)
    assert (review(contract)["items"][0]["status"] == "AFFECTED") is affected


def test_duplicate_inventory_and_wrong_repository_rejected(contract, direct_vm):
    p = policy(); p["inventory"][1]["id"] = p["inventory"][0]["id"]
    with direct_vm.expect_revert("Duplicate"):
        contract.register("case", json.dumps(p))
    p = policy(); p["source"]["url"] = URL.replace(REPO, "other/repository")
    with direct_vm.expect_revert("pinned"):
        contract.register("case", json.dumps(p))
