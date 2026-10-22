# Version applicability

An installed version is not enough to decide whether a software advisory applies.
The affected range may have several release branches, and the issue may require
a particular platform or optional feature. This contract keeps those decisions
separate and records their evidence.

## Review flow

The owner freezes a named product, up to eight inventory records, and a
commit-pinned advisory with SHA-256. Each inventory record has an ID, installed
version and deployment description. Anyone may trigger the immutable review.

GenLayer validators independently read the advisory and interpret its complete
affected ranges and deployment prerequisites. They check the leader's verbatim
witnesses and extract their own facts. Whitespace-only quote reflow is mapped back
to the contiguous original source span before storage; words and punctuation must
still match exactly. Scope decisions, all bounds and inclusivity
flags must agree. Quote wording itself is not compared for equality.

Code then compares numeric version tuples; it does not ask the model to decide
whether `2.4.10` is before `2.4.7`. Inclusive/exclusive endpoints, multiple release
branches and explicit unbounded endpoints are represented separately. Only
canonical stable three-part releases are supported. An advisory needing
pre-release/build semantics or an unrepresentable range remains incomplete.

| Item result | Meaning |
| --- | --- |
| `AFFECTED` | Prerequisites match and installed version belongs to a reported interval |
| `OUTSIDE_REPORTED_RANGE` | Prerequisites match; version belongs to none of the complete encoded intervals |
| `NOT_APPLICABLE` | Explicitly contradicted prerequisite or excluded deployment |
| `INCOMPLETE` | Unknown prerequisites or incomplete/unsupported version coverage |
| `UNREVIEWED` | No completed review yet |

None of these states says a deployment is secure. Scope never depends on installed
version; version membership is a separate deterministic step. Unsupported ranges
cannot accidentally become an empty affected set. Known excluded deployments may
still be `NOT_APPLICABLE` when version syntax is unsupported in the advisory.

## Interface and state

`register(id, policy_json)` is owner-only; policies cannot be edited or reused.
`review(id)` is permissionless and cannot overwrite a completed receipt.
`get_policy(id)` returns canonical JSON. `get_review(id)` includes the policy hash,
per-item result, matched interval indexes and extraction witnesses.
`get_item_status(id, item_id)` is the consumer-facing query.

HTTP, size, UTF-8, digest or malformed-response failures revert, preserving a
retry. A completed `INCOMPLETE` observation needs a fresh ID and evidence for a
new review. Reports are capped at 16 KB, ranges at four, inventory at eight.

## Run locally

Python 3.13 was used for 56 direct-mode tests and the GenVM linter/SDK validation.
Tests use actual SDK storage and mocked external responses, including numeric
boundaries, disjoint branches, uncertain prerequisites, retry behavior, fake
witnesses and independent validator disagreement. These are not live consensus
claims.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m pytest -q
$env:GENVM_VERSION='v0.2.12'
.\.venv\Scripts\genvm-lint check contracts/version_applicability.py
```

Use `demo.json` with `scripts/studio_demo.py` for a zero-value StudioNet run:
`deploy`, `wait TX`, then `register CASE`, `wait TX`, `review CASE`, `wait TX`,
`read CASE`. Cases are `branches`, `prerelease`, `unclear`. The script generates a
disposable account under ignored `.local/`; never supply a funded key. It sends
one write per invocation and does not retry uncertain writes. Inspect an existing
transaction when its outcome is unknown. Reads and compact receipts are public
under `evidence/`; full RPC receipts stay local. `verify_evidence.py` checks saved
evidence offline and does not query the network.

## Limits and provenance

The fictional AsterCache advisories and deployment inventory are synthetic and
operator-controlled. This is a reproducible applicability primitive, not a real
vulnerability detector, exploitability test or remediation recommendation. It
trusts the frozen inventory and cannot detect dishonest source authors. Hashes
and quotes establish provenance, not truth; validators may share semantic errors.
No package-manager-specific ordering, pre-release/build suffixes, version aliases
or dependency resolution is provided. StudioNet state can be reset.

The source-pinning pattern, Windows test cleanup and receipt tooling build on
[Benchmark pair](https://github.com/mrcactus66/benchmark-pair). Advisory semantics,
version interval rules, inventory state and tests are new here. Reproduction
scripts are shared with Incident window; each contract is standalone.

References: [custom consensus](https://docs.genlayer.com/developers/intelligent-contracts/features/non-determinism),
[direct testing](https://docs.genlayer.com/api-references/genlayer-test/direct).
