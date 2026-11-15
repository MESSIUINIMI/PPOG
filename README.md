# ProxyIP Optimizer (GitHub Actions)

A scheduled GitHub Actions project that collects **ProxyIP candidates**, checks HTTP CONNECT forwarding, checks the endpoint's GeoIP country and the actual egress country reported by Cloudflare Trace, then emits country-specific TXT files.

This project does **not** generate VLESS/UUID/subscription/client-node configurations.

## Important technical scope

- This implementation tests IPv4 `IP:PORT` candidates that support the standard HTTP `CONNECT host:port` proxy method.
- It does not assume that a TCP-open port is a working proxy. A candidate must complete CONNECT, establish TLS to `speed.cloudflare.com`, and return both `ip` and `loc` from `/cdn-cgi/trace`.
- `loc` is Cloudflare's country report for the request's observed egress. It is not a Cloudflare colo code.
- The endpoint country is looked up separately through ip-api.com.
- `both` means endpoint country AND actual egress country must be in `TARGET_COUNTRIES`.
- Some ProxyIP implementations use a different protocol or do not expose a conventional HTTP CONNECT interface. Those candidates will fail this validator. Add protocol-specific validation only after confirming the actual protocol.
- Public source availability, source formats, GeoIP coverage, and proxy behavior can change. A successful run is not a guarantee of future availability.
- Only use candidate sources and active tests you are authorized to use. The workflow deliberately does not scan arbitrary IP ranges.

## Setup

1. Create a **public** GitHub repository and upload this project.
2. In `Settings -> Actions -> General`, ensure workflow permissions allow read and write access to repository contents (or keep the workflow's `permissions: contents: write`).
3. In `Settings -> Secrets and variables -> Actions -> Variables`, optionally define:

| Variable | Default | Meaning |
|---|---|---|
| `TARGET_COUNTRIES` | `TW,SG,JP,US,KR,GB,DE,FR,AU,BR,IN,NL,TH,CA,TR,ZA,AE` | Comma-separated ISO country codes |
| `COUNTRY_MATCH_MODE` | `both` | Strict endpoint + egress country match |
| `OUTPUT_FORMAT` | `ipport-country` | Documented output convention |
| `MAX_CANDIDATES` | `300` | Maximum unique candidates tested per run |
| `MAX_WORKERS` | `10` | Concurrent proxy validations (hard-capped at 30) |
| `CONNECT_TIMEOUT` | `5` | Per connection/read timeout in seconds |

The workflow runs daily at **02:17 UTC** (`17 2 * * *`) and can also be started manually from `Actions -> ProxyIP Optimizer -> Run workflow`.

4. Add custom candidates to `config/custom_candidates.txt`, one `IP:PORT` per line, or add public candidate-list URLs to `config/sources.txt`.
5. Commit and push the repository. The schedule is evaluated from the default branch.

## Results

- `results/all.txt`: all qualified entries.
- `results/JP.txt`, `results/SG.txt`, etc.: one file per country actually found.
- `results/audit.json`: endpoint country, egress country, egress IP, verification time and run counts.

TXT output format:

```text
IP:PORT#COUNTRY
```

The suffix country is the **actual egress country**. The audit file records both endpoint and egress countries to make the BOTH decision auditable.

## Sources

The starter list includes the xgonce Cloudflare_IP CSV and the 030101 bestproxy endpoint as candidate feeds. They are untrusted candidate sources, not proof of proxy validity. Add/remove sources after reviewing their provenance and terms.

`cmliu/all.txt` and `tiancheng/all.txt` are BestIP lists in the BestCF index, not automatically treated as ProxyIP feeds.

## Safety and GitHub usage

This workflow performs bounded checks only against explicitly collected candidates. It does not perform CIDR-wide port scanning, high-rate probing, traffic relaying, or expose the runner as a proxy. Keep candidate limits and concurrency conservative. GitHub may delay scheduled workflows under load; the cron time is not an exact start-time guarantee.

## Troubleshooting

- **No output entries:** candidate feeds may be unavailable, candidate ports may not implement HTTP CONNECT, endpoint country may be outside the allowlist, or Cloudflare Trace may not return a country.
- **No candidates collected:** check source URLs and their current formats.
- **GeoIP errors:** ip-api.com free service is rate-limited and uses HTTP; use an appropriately licensed GeoIP provider if you need stronger reliability.
- **Workflow cannot push:** check repository Actions permissions and branch protection rules.
- **Private/custom protocol:** adapt `read_trace_over_connect()` to the confirmed protocol instead of treating TCP reachability as validity.

## License

Use, modify and maintain this repository at your own risk. Respect upstream source terms and the policies of GitHub and tested network operators.
