# No retained data

The servers are built so that there is nothing to hand over.

- Runtime state (status, PIDs, leaves, resolver files) lives only in RAM, under `/run/advanced-vpn`.
- Server units run with `LogLevelMax=emerg`, so they write no connection logs to the journal.
- Servers created by `avpn cloud` keep the whole system journal in RAM. `sshd` logs every admin login with its source address, and the admin is you. On a server you set up yourself, set `Storage=volatile` in `/etc/systemd/journald.conf.d/`, and keep `sudo`'s command log in mind: it records what you typed.
- Servers keep no byte counters. The optional daily cap lives on the client only.
- The only thing on a server's disk is its enrollment: public certificates and its own sealed keys.

The no-retained-data audit (`tools/throughput_bench.py`) checks this on every CI run.
