# network-checker

A small, dependency-free (Python 3.8+ standard library only) internet/network health checker.

1. **Check:** every `--interval` seconds it "pings" reliable external providers. By default these are Cloudflare
   `1.1.1.1:443`, Google DNS `8.8.8.8:53`, `www.google.com:443` and `www.yahoo.com:443`. Each probe opens a TCP
   connection, so no root/ICMP privileges are needed. The network counts as healthy if **any** target answers, so one
   flaky provider doesn't raise a false alarm.
2. **Diagnose:** when the check fails, it collects diagnostics into a timestamped log
   (`logs/diagnostics-YYYYMMDDTHHMMSSZ.log`): the health summary, DNS resolution, interfaces, routes, DNS config,
   ping and traceroute. Every step has a timeout, and missing tools are recorded rather than aborting the run, so an
   agent (or a human) can work out later what went wrong.
3. **Ask an agent (optimistically):** it then runs an AI agent CLI (by default the GitHub Copilot CLI:
   `copilot -p {prompt}`) with a prompt that includes the diagnostics. The network is down, so this may well fail.
   Every outcome is written to `logs/diagnostics-*.agent.log` and never crashes the monitor.

While an outage lasts, diagnostics are collected at most once per `--cooldown` seconds (default 900). After the
network recovers, the next failure is diagnosed immediately. A running history is kept in `logs/network-checker.log`.

## Usage

```bash
python3 -m network_checker                 # monitor forever (Ctrl-C to stop)
python3 -m network_checker --once          # single check; exit 0 = healthy, 1 = unhealthy (cron-friendly)
python3 -m network_checker -t 9.9.9.9:53 -t example.com --interval 30 --log-dir /var/log/netcheck
python3 -m network_checker --no-agent      # diagnostics only
python3 -m network_checker --agent-cmd "my-agent --input {log_file}"
```

The `--agent-cmd` value is split shell-style but **never run through a shell**. In each argument, `{prompt}` is
replaced with an analysis prompt that embeds the diagnostics (truncated to stay within OS argument limits), and
`{log_file}` is replaced with the path to the full log. Run `python3 -m network_checker --help` for all options.

## Development

The project was built test-first (red/green TDD). Run the tests with:

```bash
python3 -m unittest discover -s tests
```
