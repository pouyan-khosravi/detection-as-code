# Detection-as-Code — Active Directory

Version-controlled, unit-tested Sigma detection rules for a Wazuh-based home SOC,
with a CI pipeline that blocks any rule change which breaks detection.

**[Full project writeup →](docs/PORTFOLIO.md)** — architecture, detection coverage, and a demonstrated regression catch.

The rules cover credential-access attacks against Active Directory, validated
against real alert telemetry from a lab running a Windows Server 2022 domain
controller, Sysmon, and a Wazuh manager.

## Why this exists

Detection rules written directly in a SIEM console have no version history, no peer
review, and no regression testing. A rule silently stops firing after a schema change
and nobody notices until an incident. Treating detections as code fixes that: rules
live in Git, every change opens a pull request, and CI proves the rule still catches
its attack before the change can merge.

## Pipeline

```
  Sigma rule (.yml)                  <- vendor-neutral source of truth
        |
        |  sigma check
        v
  Structural validation              <- schema, ATT&CK tags, duplicate IDs
        |
        |  pySigma + pipelines/wazuh_windows.yml
        v
  Field-mapped query                 <- Sigma field names -> Wazuh JSON paths
        |
        +--> SQLite  --> pytest against sample alerts   (regression gate)
        |
        +--> OpenSearch Lucene / DSL / monitor rules    (deployable artifact)
```

Both branches run on every pull request. A rule that no longer matches its
true-positive sample, or starts matching benign traffic, fails the build.

## Layout

| Path | Purpose |
|---|---|
| `detections/` | Sigma rules, by platform and ATT&CK tactic |
| `pipelines/wazuh_windows.yml` | Maps Sigma field names onto Wazuh's decoded field paths |
| `samples/` | Real Wazuh alert JSON — one true-positive and one benign file per rule |
| `tests/` | Pytest harness and the rule-to-sample test manifest |
| `scripts/build.sh` | Emits deployable query artifacts into `build/` |
| `.github/workflows/` | Validation and build pipelines |

## The Wazuh pipeline

Wazuh decodes Windows Event Log records into nested JSON under `data.win.system.*`
and `data.win.eventdata.*`, and lower-cases the first letter of every `eventdata`
field. It also stores `eventID` as a string. `pipelines/wazuh_windows.yml` handles
all three, so the rules themselves stay written in portable Sigma and are not
locked to one SIEM.

Order matters in that pipeline: the numeric-to-string conversion on `EventID` has
to run *before* the field is renamed, or the transformation finds no field to act on.

## Usage

```bash
# One-time setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

make check     # validate rule structure
make test      # run detection unit tests
make build     # emit deployable queries into build/
make all       # all three
```

Preview what a single rule becomes:

```bash
sigma convert -t opensearch_lucene -p pipelines/wazuh_windows.yml \
  detections/windows/credential_access/dcsync.yml
```

## Adding a rule

1. Write the Sigma rule under `detections/<platform>/<tactic>/`.
2. Trigger the attack in the lab, then pull the resulting alert out of
   `/var/ossec/logs/alerts/alerts.json` on the Wazuh manager. Save it as a
   true-positive sample.
3. Capture normal activity that looks superficially similar and save it as the
   benign sample. This is the part that catches false positives.
4. Register both pairs in `tests/test_cases.yml`.
5. Open a pull request. CI has to be green before merge.

Extracting a sample from the manager:

```bash
sudo jq -c 'select(.data.win.system.eventID == "4662")' \
  /var/ossec/logs/alerts/alerts.json | tail -1 | jq . > sample.json
```

## Current coverage

| Rule | ATT&CK | Event ID | Severity |
|---|---|---|---|
| AS-REP Roasting | T1558.004 | 4768 | high |
| DCSync | T1003.006 | 4662 | critical |
| Kerberoasting (RC4) | T1558.003 | 4769 | high |

## Known limitations

- The Kerberoasting rule depends on the domain being baselined to AES. In a domain
  that still permits RC4 for legacy applications it will be noisy.
- The test harness evaluates rules through the SQLite backend, which is a faithful
  but not identical model of how the Wazuh rule engine matches. It catches logic
  regressions, not decoder-level differences. End-to-end verification is done in the
  lab with `/var/ossec/bin/wazuh-logtest`.
- Deployment is manual: CI builds the query artifacts, and they are imported into
  the Wazuh indexer by hand, because the lab is not reachable from GitHub-hosted
  runners.
