# network-checker

A small, dependency-free (Python ≥ 3.9 standard library only) internet health
checker for **Linux, macOS and Windows**.

1. **Ping-like check:** every interval it probes several highly reliable
   endpoints at once:
   * content-verified HTTP connectivity checks used by the OSes themselves
     (`connectivitycheck.gstatic.com/generate_204`, `captive.apple.com`,
     `www.msftconnecttest.com`). Because the response is verified, captive
     portals and intercepting proxies count as failures. These checks also
     exercise DNS.
   * raw-IP TCP reachability to `1.1.1.1` and `8.8.8.8`. These are supporting
     signals that help tell "DNS is broken" apart from "no route at all".

   The network is healthy when at least one content-verified check passes.
   No ICMP, admin rights or CA certificate store are needed.
2. **Automatic diagnostics on failure:** it runs the platform's native tools
   and writes `logs/diag-<UTC timestamp>.log` (readable) and `.json` (structured).
   Missing tools and timeouts are recorded rather than aborting the run.
   Proxy credentials are redacted.

   | Platform | Tools |
   | -------- | ----- |
   | Linux    | `ip addr`, `ip route`, `/etc/resolv.conf`, `ping`, `nslookup`, `traceroute`, `curl` |
   | macOS    | `ifconfig`, `netstat -rn`, `route get default`, `scutil --dns/--proxy`, `ping`, `nslookup`, `traceroute`, `curl` |
   | Windows  | `ipconfig /all`, `route print`, `netsh` (DNS, Wi-Fi, WinHTTP proxy), `ping -n`, `nslookup`, `tracert`, `curl.exe` |
3. **Optimistic agent invocation:** if an agent command is configured, it is
   run straight away with the log paths. The network is down at that moment,
   so the agent may well fail. Any failure (missing binary, timeout, non-zero
   exit) is caught and saved to `diag-*.agent.txt`, so an agent run later can
   pick up the logs and continue.

Every check, diagnosis and agent outcome is also added to `logs/health.log`.
Repeated diagnostics during one long outage are rate-limited by `--cooldown`.

## Usage

```sh
python -m network_checker                 # monitor every 60s (Ctrl+C to stop)
python -m network_checker --once          # single check (see exit codes below)
python -m network_checker --interval 30 --log-dir /var/log/netcheck
# add extra TCP probes (the built-in content-verified checks stay on)
python -m network_checker --target intranet.example:443 --target [2606:4700:4700::1111]:443
# probe only your own endpoints (TCP connect only: a captive portal may look healthy)
python -m network_checker --no-default-targets --target 10.0.0.1:53
```

Exit codes: `0` = healthy, `1` = unhealthy, `2` = usage error (including a
malformed agent command). An interrupted run returns `128 + signal`, so it is never mistaken for
healthy, and any running diagnostic or agent process tree is killed:

* Linux/macOS: Ctrl+C gives `130`, SIGTERM `143`, SIGHUP `129`.
* Windows: Ctrl+C gives `130`, Ctrl+Break `149`. Windows cannot deliver
  SIGTERM to another process: `taskkill /F` and `os.kill` terminate the
  process immediately, so no clean-up runs.

### Configuring the agent

Use `--agent-cmd` or the `NETWORK_CHECKER_AGENT_CMD` environment variable.
The placeholders `{log}`, `{json}` and `{prompt}` are replaced; `{prompt}`
becomes ready-made instructions that point the agent at the logs. Examples:

```sh
# macOS / Linux
python -m network_checker --agent-cmd "copilot -p {prompt}"
```

```powershell
# Windows (backslashes in paths are kept literally)
$env:NETWORK_CHECKER_AGENT_CMD = '"C:\Tools\my agent.exe" --log {log}'
python -m network_checker
```

The command runs without a shell. If it is still running after
`--agent-timeout` seconds (default 600), it is killed along with all its child
processes. Very large output is trimmed to the first and last 512 KiB, with a
`[... N bytes truncated ...]` marker in between. A malformed command, such as one with unbalanced quotes, is rejected
at startup with exit code 2.

On Windows the program name is looked up with `PATHEXT`, so `.cmd` shims
installed by npm (e.g. `copilot.cmd`) work. `cmd.exe` re-parses arguments
passed to `.bat`/`.cmd` files, so for those agents any argument containing
`% ^ & | < > " ! ( )` or a newline is refused. The refusal is logged as a
failed agent attempt. Prefer `.exe` agents, or a `--log-dir` path without
those characters.

## Development

The project was built test-first (red/green TDD).

```sh
python -m pip install -r requirements-dev.txt
python -m pytest
```

CI runs the suite on Ubuntu, macOS and Windows (`.github/workflows/tests.yml`).
