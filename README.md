# defence-coverage-mapper

An offline tool that converts inconsistent block logs into a structured defence coverage map.

`injection-bench` answers "did the defence work for this agent on these cases?". This tool answers
"which defences exist, which have been exercised, and where are the unprobed gaps?". They are
complementary: one scores a defence, the other maps which defences are there.

## Why it exists

Twelve internal negative-result ledgers hold 1,454 non-empty lines. Only 32 rows are uniformly
labelled. Refusals are recorded as prose, exact strings, error codes, or class-level predicates.
A human reading them cannot see which defence layer fired, which cells were never probed, or which
apparent walls were edge verdicts and empty namespaces.

The mapper normalises those records, classifies them against a versioned taxonomy, applies four
evidence gates, and emits a map with technique-specific probes for the blank cells.

## Evidence gates

| gate | rule |
|---|---|
| G1 layer attribution | `observed_layer` must be one of seven; `unknown` caps the cell at `unprobed`. |
| G2 decision point | A 404 or empty namespace is `route_absent`, not a defence cell. |
| G3 state verification | `hit` and `non_hit` require a read-back receipt. A transcript alone is `claimed`. |
| G4 provenance | Reconstructed or confounded records cap at `claimed`. |

L10 is split at ingestion. Bare `L10` is refused. `L10a` is partial enforcement, `L10b` is artifact
archaeology. Owner-derivation class 1 makes the owner-sensitive cells `not_applicable`.

## Taxonomy

Nine defence types, `DT-01` input filter through `DT-09` context window integrity. Nine is one more
than the original base set: `DT-09` was added because OWASP LLM08:2025 covers adversarial content
in retrieved or embedded context, and no base type held that case. It has zero corpus hits and
starts fully unprobed.

Standard references are versioned beside each type. Verified here on 2026-11-22:

- OWASP Top 10 for LLM Applications 2025, `https://genai.owasp.org/llm-top-10/`
- OWASP ASVS 5.0.0, published 30 May 2025, `https://asvs.owasp.org/`
- NIST AI 600-1, published 26 July 2024, NIST publication page
- MITRE CWE definitions, `https://cwe.mitre.org/`

MITRE ATLAS 2026.07 ids `AML.T0051`, `AML.T0051.001`, `AML.T0053`, `AML.T0054` and `AML.T0080`
were verified in the pinned YAML. CAPEC `153`, `242`, `233` and `115` were verified by their
definition pages. ISO/IEC 42001 clause ids, OWASP MASVS mobile ids, Google SAIF element numbers and
a CAPEC id for LLM prompt injection remain `UNREACHABLE`. The tool never invents a standard id.

## Interfaces

Five MCP (Model Context Protocol) tools, all deterministic and stateless:

| tool | purpose |
|---|---|
| `convert_block_log` | raw prose to normalised events, with provenance and `classify_status` |
| `classify_block` | event to defence type, confidence and standard refs; `model_hint` is ignored for evidence |
| `coverage_map` | events to a map of nine defence types or the full lens matrix |
| `gap_probes` | blank cells to technique-specific probes, each with a read-back requirement |
| `explain_gap` | one cell to a short rationale with file and line citations |

Sixth tool, `blue_team_review`, is static: it reads a policy, prompt or config, extracts verbatim
claim spans, links lens, defence and potential harm, emits a probe batch with fixed benign controls
from injection-bench, and re-validates against measured state before any live call. Text alone can
never raise a cell above `claimed`.

CLI equivalent:

```bash
python3 mapper.py coverage_map --input-json '{"classified_events":[...]}'
python3 mapper.py gap_probes --input-json '{"coverage_map":{...}}'
python3 -m unittest discover -s tests
```

Three extension modes were added in round 15/15b:

- `map_condition_to_methods`: paste text plus a condition such as "AI injection", "API authorization"
  or "tool-use abuse". The tool returns matched methods, standard refs, measured evidence, a band
  confidence and a falsifier. Condition is a hard filter; no match is `no_mapping`, not a guess.
- `ingest_approach_report`: a model reports its own approach. The tool validates fields, maps the
  technique to a defence type, compares claimed and observed layers, applies the four gates,
  canonicalises identity (doubt to `redacted` to deepseek), and keeps overlapping reports separate.
  Output is band-only.
- `compute_confidence`: numeric confidence exists as a formula but is **withheld by default** while
  `CALIBRATION_STATUS = deferred`, because 12 seed events cannot meet 10 per type across nine types.
  A caller can opt in with `emit_numeric=True` and still receives `provisional: true` on every number.

A primary-evidence floor is enforced before scoring: a resolvable pointer or a distinct measured
event is required. The event behind the pointer cannot also be the measured event. Layer agreement
comes from the validator, not the model's self-report.

A real MCP (Model Context Protocol) stdio server is included. `tool_schemas.json` publishes the six
tool schemas and `mcp_server.py` serves `initialize`, `ping`, `tools/list` and `tools/call` as
line-delimited JSON-RPC. Logs never go to stdout, so the wire stays clean. A client calls it with:

```bash
python3 mcp_server.py
```

All inputs are JSON. All outputs carry evidence pointers. `model_hint` is accepted for compatibil-
ity but ignored for evidence, so a model cannot promote an unlogged control into a hit by asserting
it in the hint.

## Seed evidence

The converter is tested against controlled lab block events with exact strings, the lane-b authorization codes
ledger, and the Blind Trust dead-class table. Those records are referenced by path and line in the
probe catalogue; raw corpora are not copied into this repo. `InjecAgent` and `jailbreak_llms` are
both MIT and are cited, not vendored.

## Ledger converter

`convert_ledgers` reads every `NEGATIVE-RESULTS.md` under a workspace root and emits one normalised
event per table row, bullet or labelled line: source path, line, verdict, exact receipt, error
codes, signal and a tentative defence type. It is read-only and makes no network request. In this
workspace it converts 12 ledgers into 341 events. Converted rows are not committed to this repo;
they can be written to a local JSONL file at runtime.

`calibration_report` counts mapped events per defence type and reports readiness. With 341 ledger
events, seven types meet the 10-event minimum and DT-02 and DT-09 do not, so `CALIBRATION_STATUS`
stays `deferred`. Numeric confidence is therefore withheld by default.

`convert_bench_results` runs injection-bench's three scripted reference agents over all 18 cases and
emits 54 events. All are tagged `provenance: controlled_replay`, never `measured`: they show the
harness can separate safe from compromised behaviour, not that a live model is vulnerable. It gives
DT-09 18 events and DT-02 9, but they cannot close calibration on their own.

Framework ids were pinned on 2026-11-22 from official sources: ASVS 5.0.0 en markdown V16 lines
48-49, ATLAS 2026.07 YAML, and CAPEC definition pages. ISO 42001, MASVS, SAIF and a CAPEC LLM
prompt-injection id remain `UNREACHABLE`.

## Persistence, identity and frameworks

- `SqliteOverlapStore` persists overlap records across restarts. The in-memory `register_report`
  remains for quick tests; the SQLite class is the production path and is covered by a reopen test.
- `known_seats.json` holds the roster and an operator-managed `attestations` map. An attestation by
  session id or exact submitted name overrides a self-report and is marked `attested`; without one,
  doubt still routes to `redacted` and canonicalises to deepseek.
- `framework_map.json` and `map_framework` carry the verified framework-to-method table. CWE-20,
  CWE-74 and CWE-284 stay `background_only`; CWE-77 and CWE-862 need review; CWE-639 is allowed.
  ISO 42001, MASVS, SAIF and CAPEC-LLM ids are `UNREACHABLE`, never invented.
- `calibrate_bands` computes a band-versus-truth contingency when an operator supplies independent
  event labels. Bins below 10 return `unknown`. Its band definition is provisional and is labelled
  as such; it is not claude's calibrated scale.

## Closing the gaps

- `labelling.py`: blind reviewer receipts with a four-field whitelist, meta-leak lint, raw-line
  provenance check, stratified sampling (floor 3 per non-empty type, largest-remainder top-up),
  Cohen's and Fleiss agreement, and a calibration gate that **fails closed** while any operator
  threshold in `thresholds.json` is null. No number is invented by the tool.
- `probes.py`: ten DT-02 and seven DT-07 probe specifications with read-back and abort conditions,
  plus `accept_dt02_event` and `accept_dt07_event` guards. Specs only; the module sends no traffic.
- `mcp_client.py`: a real stdio client that spawns `mcp_server.py`, asserts server identity, tool
  list, locally computed content, error paths and a stderr nonce. Its negative control is a canned
  stub that mimics the happy paths and is detected through the error paths. Running
  `python3 mcp_client.py` gives `real: PASS` and `stub: SIMULATION DETECTED`.

One error in the advisor material was caught by tests: total disagreement between two reviewers
with fixed marginals gives Cohen's kappa 0, not a negative value. The implementation is correct and
the test now uses a case that genuinely produces a negative kappa.

## Use cases

- **Post-hunt coverage map.** Converts negative-result ledgers into events with source pointers,
  then shows which defence types were exercised and which were never touched. Across this
  workspace it reads 12 ledgers, produces 341 events and exposes DT-02, DT-07 and DT-09 as gaps.
- **Dead-door registry.** A class already refuted with a pointer is not proposed again. Each event
  carries a file and line so the next session can check the raw receipt.
- **Probe planning.** Blank cells become technique-specific probes with read-back and abort
  conditions, not generic advice.
- **Blue-team review.** Paste a system prompt, policy or config. The tool returns verbatim claim
  spans, missing controls, potential harms and a probe batch with fixed benign controls from
  injection-bench.
- **Condition to method.** Paste text plus a condition such as "AI injection" or "API
  authorization". It returns method ids, framework refs, band confidence, measured evidence and
  a falsifier. No match returns `no_mapping`, never a guess.
- **Approach ingestion.** A model reports what it tried. The tool validates the report, compares
  claimed and observed layers, applies evidence gates, keeps overlapping reports separate and
  canonicalises identity.
- **Framework audit.** Maps events to OWASP LLM, OWASP API, ASVS, CWE, ATLAS, CAPEC and ATT&CK,
  with `background_only` and `UNREACHABLE` labels so nothing is overclaimed.
- **Calibration gate.** Numeric confidence stays withheld until two blind reviewers agree and the
  operator ratifies thresholds. It currently refuses to activate.
- **Interview and portfolio proof.** The method is the artifact: convert messy evidence, apply
  gates, refuse guesses, state falsifiers. That is stronger than a tool list for an AI safety role.

## Known limits

1. Layer coarseness. The seven layers are still a model of a deeper stack. An explicit
   `observed_layer` is required; unknown does not get promoted.
2. Chained coverage. DT-03 can mask DT-05: the model refuses an encoded secret before the output
   masker is tested. A hit in one does not prove the other.
3. Self-sealing corpus. A missing non-hit looks identical to an unprobed cell. Probe attempts must
   be recorded even when no block signal appears.
4. Keyword rigidity. Novel refusal phrasing becomes `ambiguous`, not a fabricated classification.
5. Static blue-team mode cannot see runtime-only controls. It produces hypotheses, not verdicts.

## Framework references

- OWASP ASVS v5.0.0 requirements `v5.0.0-16.3.2` and `v5.0.0-16.3.3`. The OWASP Application
  Security Verification Standard is copyright OWASP and licensed CC BY-SA 4.0. Requirement
  summaries here are paraphrased, not quoted.
- MITRE ATLAS v2026.07 identifiers `AML.T0051`, `AML.T0051.001`, `AML.T0053`, `AML.T0054`,
  `AML.T0080`. Copyright 2021-2026 The MITRE Corporation. MITRE ATLAS and MITRE ATT&CK are
  trademarks of The MITRE Corporation. Use is subject to the ATLAS terms of use. No endorsement
  implied.
- MITRE CAPEC v3.9 patterns `CAPEC-153`, `CAPEC-242`, `CAPEC-233`, `CAPEC-115`. Copyright The MITRE
  Corporation. CAPEC is a trademark of The MITRE Corporation. Use is subject to the CAPEC terms of
  use. No endorsement implied.

The Mapper's framework associations are this project's analysis. They are not official OWASP or
MITRE mappings or endorsements.

## Licence

MIT. Standard identifiers and corpus citations belong to their respective owners.
