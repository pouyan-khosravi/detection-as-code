# Detection-as-Code — Automated Testing for SIEM Detection Rules

**Author:** Pouyan Khosravi
**Repository:** https://github.com/pouyan-khosravi/detection-as-code
**Stack:** Sigma · pySigma · Wazuh · OpenSearch · GitHub Actions · Python · pytest
**MITRE ATT&CK:** T1003.006 · T1558.003 · T1558.004

---

## Summary

Security detection rules are usually written directly in a SIEM console. That means no version history, no peer review, and no way to know when a rule has silently stopped working. The failure mode is quiet and expensive: an alert that should have fired doesn't, and nobody finds out until the incident review.

This project applies software engineering practice to that problem. Detection rules live in Git as vendor-neutral Sigma files. Every rule ships with two sample event files — one containing the attack it must catch, one containing benign activity it must ignore. On every pull request, CI validates the rule structure, converts it into the target SIEM's data model, and runs it against both samples.

A rule that stops detecting its attack, or starts firing on legitimate traffic, fails the build and cannot be merged.

---

## Architecture

```
  Sigma rule (.yml)                  vendor-neutral source of truth
        |
        |  sigma check
        v
  Structural validation              schema, ATT&CK tags, duplicate IDs
        |
        |  pySigma + custom Wazuh pipeline
        v
  Field-mapped query                 Sigma field names -> Wazuh JSON paths
        |
        +--> SQLite  --> pytest against sample alerts   (regression gate)
        |
        +--> OpenSearch Lucene / DSL / monitor rules    (deployable artifact)
```

Two conversion targets, two purposes. The SQLite backend turns each rule into a SQL predicate that can be evaluated against sample events in an in-memory database — fast, dependency-free, and runnable on a CI worker that has no access to any SIEM. The OpenSearch backend produces the artifacts that get imported into the Wazuh indexer.

That separation is deliberate. CI infrastructure cannot reach a production SIEM, so detection testing has to be self-contained to be automatable at all.

Both workflows run on every push and pull request to `main`.

---

## Detection coverage

| Rule | ATT&CK Technique | Windows Event | Detection logic | Severity |
|---|---|---|---|---|
| AS-REP Roasting | T1558.004 | 4768 | TGT requested for an account with Kerberos pre-authentication disabled; machine accounts excluded | High |
| DCSync | T1003.006 | 4662 | Directory replication extended rights requested by a non-DC principal; machine accounts and directory-sync service accounts excluded | Critical |
| Kerberoasting | T1558.003 | 4769 | Service ticket requested with RC4-HMAC encryption for a user-backed SPN; machine accounts and krbtgt excluded | High |

Every rule declares its false positives explicitly. The Kerberoasting rule, for instance, is only low-noise in a domain baselined to AES — that constraint is documented in the rule itself rather than discovered in production.

---

## The Wazuh field-mapping pipeline

There is no official Sigma backend for Wazuh. The SigmaHQ plugin directory has none, the available third-party converters are unmaintained, and Wazuh's own guidance is to write rules manually.

This project solves that with a custom pySigma processing pipeline that maps Sigma's generic Windows schema onto Wazuh's decoded field paths. It handles three differences:

**Nested structure.** Wazuh decodes Windows Event Log records into `data.win.system.*` and `data.win.eventdata.*` rather than flat field names.

**Case transformation.** Sigma's `TargetUserName` becomes Wazuh's `data.win.eventdata.targetUserName`.

**Type mismatch.** Wazuh stores `eventID` as a string; Sigma rules express it as an integer.

The third is subtler than it looks. The type conversion has to execute *before* the field rename — running it after means the transformation searches for a field that no longer exists under that name and silently does nothing, producing a query that compiles cleanly and matches nothing. Ordering the transformations correctly is the fix.

```bash
sigma convert -t opensearch_lucene -p pipelines/wazuh_windows.yml \
  detections/windows/credential_access/dcsync.yml
```

That command takes one portable Sigma rule and emits the target SIEM's query language.

Because the rules themselves stay in standard Sigma, they are not locked to Wazuh. Migrating to a different SIEM means writing a new pipeline file, not rewriting the detection library.

---

## Testing strategy

Each rule is paired with two sample files in `tests/test_cases.yml`:

```yaml
- rule: detections/windows/credential_access/dcsync.yml
  sample: samples/dcsync_true_positive.json
  expected_matches: 1

- rule: detections/windows/credential_access/dcsync.yml
  sample: samples/dcsync_benign.json
  expected_matches: 0
```

The harness converts the rule, flattens the nested Wazuh alert JSON into dotted-path columns, loads it into SQLite, and asserts the match count. The benign case is the important half — it is what stops a rule from becoming an alert-fatigue generator.

Six tests in total: three rules, each evaluated against a true-positive and a benign sample.

---

## Demonstrated regression catch

To verify the pipeline does real work, I deliberately introduced a regression: removing the exclusion filters from the DCSync rule and opening a pull request.

The change was a single line: removing the filters that exclude machine accounts and directory-sync service accounts.

The rule still detected the attack. But CI failed the benign test:

```
rule:     detections/windows/credential_access/dcsync.yml
sample:   samples/dcsync_benign.json
expected: 0 match(es)
got:      2
```

Two false positives, from two different legitimate sources: a second domain controller performing normal directory replication, and an Entra Connect synchronisation account. Both hold replication rights by design. Both would have generated critical-severity alerts.

This is what detection regressions actually look like in production. The rule was not broken — it was noisy. Noise is what causes analysts to stop trusting alerts, and it is far harder to notice than a rule that fires zero times.

The pull request was closed without merging.

---

## Branch protection

`main` is governed by a ruleset requiring a pull request and a passing status check. Direct pushes are rejected, including from the repository owner.

This is what makes the difference between a folder of scripts and a pipeline: the guarantee is enforced by the platform, not by discipline.

---

## Known limitations

- The SQLite-based harness is a faithful model of rule matching, not the Wazuh rule engine itself. It catches logic regressions; decoder-level behaviour is verified separately with `wazuh-logtest`.
- Sample events are currently synthetic, constructed to Wazuh's alert schema. Replacing them with telemetry captured from a live lab domain controller is the next milestone.
- Deployment is manual. CI produces importable query artifacts; they are loaded into the indexer by hand, since a home lab is not reachable from GitHub-hosted runners.

---

## Roadmap

- Golden Ticket detection (T1558.001) with matching sample pair
- Replace synthetic samples with captured lab telemetry
- Self-hosted CI runner on the lab network for automated rule deployment
- Upstream contribution of a rule to the SigmaHQ repository

---

## Running it

```bash
git clone https://github.com/pouyan-khosravi/detection-as-code.git
cd detection-as-code
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

sigma check detections/      # validate rule structure
pytest tests/ -v             # run detection tests
./scripts/build.sh           # build deployable query artifacts
```
