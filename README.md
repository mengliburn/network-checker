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
python -m network_checker --once          # single check; exit code 0 = healthy, 1 = unhealthy
python -m network_checker --interval 30 --log-dir /var/log/netcheck
python -m network_checker --target example.com:443 --target [2606:4700:4700::1111]:443
```

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

The command runs without a shell. It is abandoned after `--agent-timeout`
seconds (default 600).

## Development

The project was built test-first (red/green TDD).

```sh
python -m pip install -r requirements-dev.txt
python -m pytest
```

CI runs the suite on Ubuntu, macOS and Windows (`.github/workflows/tests.yml`).
