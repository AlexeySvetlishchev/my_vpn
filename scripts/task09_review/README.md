# TASK 09 migration and maintenance sources

The RU maintenance cutover was completed under explicit owner approval.
See [deployment evidence and addressed rollback](../../docs/TASK_09_DEPLOYMENT_RESULT.md).

## Active components

- `task09_maintenance.py`: fixed RU maintenance/deployment and addressed rollback.
  It backs up protected state on RU, stops client ingress and relevant timers,
  applies the coordinated change, activates SQLite startup, verifies invariants,
  and restores the baseline on failure. It never flushes global firewall rules.
- `task09_transition_v5.py`: package validation, durable journal, sequential
  file/ledger installation and recovery using fresh nft snapshots/handles.
- `task09_integrity.py`: checks exact source/hash/helper-pin dependencies.
- `task09_nft_plan.py`: six rule replacements plus reserved-address DROP guard;
  exact post-transition comparison against the saved owned baseline, including
  all dynamic `ru_set` and `force_egress` contents.
- `task09_linux_storage.py`: fsynced atomic files/journal and the real TASK08
  prefix updater lock followed by the migration lock, both nonblocking.
- `task09_linux_nft.py`, `task09_linux_backend.py`: explicitly named namespace
  adapter for isolated tests. Maintenance supplies fixed host nft commands only
  while client ingress is stopped. Preserve nft JSON handles in ownership hashes:
  this is TASK08's deployed format; normalize them only for snapshot comparisons.
- `task09_probe.py`: disposable real AWG client namespace, DNS/HTTPS egress and
  actual disable/enable data checks. It creates only its named test objects.
- `task09_verify.py`: deployment-specific verification and protected backup /
  staged restore exercise; its baseline path identifies the accepted deployment.

`task09_migrate_core.py` and its unit tests retain the earlier offline model for
regression reference. Its static reverse batch is not a deployment entry point;
actual maintenance uses `Transition` and fresh runtime handles.

## Pinned source fixtures and delivery sources

`fixtures/` contains public source-code inputs for deterministic staging/tests,
not VPS configuration backups. `staged-task09/` contains the exact reviewed
source-code delivery set and manifest used by maintenance. These are required
inputs to tests and addressed rollback; neither directory contains private keys,
SQLite state, runtime logs, compiled binaries, or server-generated backups.

`task09_stage.py` reproduces a delivery set into an absent directory:

```sh
python3 -B task09_stage.py --source-dir fixtures --output-dir /tmp/task09-stage-new
```

## Tests and boundaries

Run on Linux because storage and Manager use `fcntl`. Ordinary offline suite:

```sh
python3 -B -m unittest discover -s scripts/task09_review -v
python3 -B -m unittest discover -s tests -p 'task09_*_test.py' -v
```

The real kernel nft test requires both `TASK09_ISOLATED_NFT=1` and Docker's
`/.dockerenv` marker. Use a disposable container with NET_ADMIN, Python and nft;
it applies the real planners, reverses using fresh handles and verifies hashes
and populated dynamic sets. Do not set the opt-in on a production container.

The deployed maintenance path allows downtime; it does not implement automatic
boot-time migration recovery or a zero-downtime maintenance gate. A process crash
requires explicit addressed recovery through SSH while ingress remains stopped.
If baseline rules, files or dynamic sets drift after deployment, rollback refuses
rather than overwrite later administration. No secrets are printed by these tools.
