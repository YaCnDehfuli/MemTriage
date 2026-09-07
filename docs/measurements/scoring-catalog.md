# Implemented scoring catalog

The native scoring catalog contains **27 enabled rules** across **16 process, 8 connection, and 3 persistence** object rules, counted from [`default_rules`](../../backend/memtriage/scoring/catalog.py) with:

```bash
PYTHONPATH=backend python -c 'from memtriage.scoring.catalog import default_rules; rules=default_rules(); from collections import Counter; print(f"default_rules={len(rules)}"); print("by_object_type=" + repr(dict(sorted(Counter(r.object_type for r in rules).items())))); print("enabled=" + str(sum(r.enabled for r in rules)))'
# default_rules=27
# by_object_type={'connection': 8, 'persistence': 3, 'process': 16}
# enabled=27
```

An investigation accepts one dump or up to **5 interval snapshots**, enforced by [`max_dumps_per_investigation`](../../backend/memtriage/config.py); the worker consolidates the selected process's regions from those snapshots.
