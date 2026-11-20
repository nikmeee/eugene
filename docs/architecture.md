# Eugene architecture

Eugene is split into four layers:

- `app.py` — command-line arguments, the Rich live view, and the final report;
- `doctor.py` — check order, the thread-safe `Report`, and diagnostic conclusions;
- `probes.py` — system commands and low-level DNS, TCP, TLS, and HTTP checks;
- `report.py` — the result model, the score, and JSON serialization.

## Execution and state

In interactive mode, `Doctor.run()` works on a background thread. The main thread
draws only deep copies of `Report`. The chain nodes are created in the `Doctor`
constructor, so the first frame always has the full structure. Changes to composite
data and the progress that depends on them are published under one lock.

An unhandled diagnosis error returns to the main thread, is printed to `stderr`,
and exits with code `2`.

## Direct checks around the VPN

On macOS, sockets are bound to the physical interface with `IP_BOUND_IF`.
A domain's address is requested from several public DNS servers. Eugene removes
duplicates and tries up to three A records, so one bad CDN node does not look
like the whole site is blocked. If every address fails, the diagnosis keeps the
attempt that got furthest along DNS → TCP → TLS → HTTP.

## Exit codes

- `0` — the diagnosis finished and the network score is at least 60;
- `1` — the score is below 60, or the network cannot be scored;
- `2` — an internal diagnosis error;
- `130` — the user interrupted the run.

JSON is written only to `stdout`. Error messages go to `stderr`.

## Tests

```bash
python -m unittest discover -s tests -v
```

The unit tests cover the DNS parser, scoring, JSON, diagnosis-pipeline transitions,
the initial TUI frame, background-error propagation, IP fallback, and atomic
progress publication.
