
# ComfyUI GPU Capacity Report v2

This version uses a fixed host inventory and queries VictoriaLogs host-by-host.

## Why this version is different

A wildcard query can be truncated by `limit`, which makes total host and container counts unstable. This version avoids that by:

1. Treating `inventory_hosts` as the source of truth.
2. Running one query batch per host.
3. Aggregating all returned containers under each host.
4. Treating a container as active when it emits logs in a bucket.
5. Treating a host as active when at least one ComfyUI container under it emits logs.

This is much better for arguing that the effective GPU fleet is too small to carry more workload safely.

## Run

```bash
cp config/config.yaml.example config/config.yaml
go run ./cmd/server -config ./config/config.yaml
```

Open `http://127.0.0.1:8080`.

## Notes

- Put the full fleet into `inventory_hosts` if you want stable host totals.
- `query_limit` is applied to every host-scoped query.
- The page supports bilingual output and per-container log sample drill-down.
# comfyui_usage_report_v2
# comfyui_usage_report_v2
