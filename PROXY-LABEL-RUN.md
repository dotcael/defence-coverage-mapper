# Proxy label run, 2026-11-22

The operator directed: pick a label from GLM's vocabulary and close the mechanical loop. This file
records exactly what was done. It is not an independent human labelling run.

## Vocabulary

GLM's four labels were used verbatim: `blocked`, `bypassed`, `partial`, `indeterminate`.

## Method

Two deterministic proxy rules were applied to 50 stratified events from the 165 typed ledger
events:

- `proxy-status`: reads receipt status and refusal words.
- `proxy-signal`: reads the converter's `signal_type`.

Both are tagged `independent: false`. They exercise the pipeline; they do not substitute for
blind human review.

## Measured result

| measure | value |
|---|---|
| sampled events | 50 |
| label records | 100 |
| proxy status labels | indeterminate 30, blocked 18, bypassed 1, partial 1 |
| proxy signal labels | blocked 31, indeterminate 19 |
| Cohen's kappa between the two proxies | 0.5262 |
| agreed labels | 37 |
| discarded disagreements | 13 |
| agreed per type | DT-06 14, DT-04 7, DT-01 4, DT-05 5, DT-03 3, DT-08 3, DT-07 1 |

`calibration_decision` returned `deferred` with reason `threshold_unratified`. That is correct:
the three bars in `thresholds.json` are still `null`, and the tool refuses to invent them.

## Live MCP test

`python3 mcp_client.py` spawned the real server and returned:

```
real: PASS
stub: SIMULATION DETECTED
ok: true
```

Five assertions passed on the real server: server identity, tool list, locally computed content,
error paths and stderr nonce. The canned stub passed identity, list, content and nonce, and failed
only on error paths, which is what proves the harness detects simulation.

## What this closes

- The labelling schema, sampling, agreement statistic and decision gate now run end to end.
- The live MCP server has been driven by a real stdio client process, not fixtures alone.
- The negative control demonstrably fails a simulated server.

## What this does not close

- The proxy labels are not independent. Real calibration still needs two blinded reviewers.
- The thresholds remain unratified. They must be set before labels are unblinded.
- DT-02 and DT-07 still need live events. DT-07 has one agreed proxy label, not ten.
- `CALIBRATION_STATUS` stays `deferred`, so numeric confidence stays withheld.

Raw proxy label records were written to `tmp/proxy-labels.jsonl`, not committed.
