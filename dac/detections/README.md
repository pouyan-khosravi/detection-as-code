# Detection rules

One Sigma rule per file, organised as `<platform>/<attack-tactic>/<rule_name>.yml`.

Every rule must have:

- a unique `id` (generate with `python3 -c "import uuid;print(uuid.uuid4())"`)
- `logsource` matching a product/service the Wazuh pipeline maps
- `tags` with the relevant MITRE ATT&CK technique
- an honest `falsepositives` list
- at least one true-positive and one benign test case in `tests/test_cases.yml`

Rules that convert but have no test cases will pass `sigma check` and still be
worthless. The test case is part of the rule.
