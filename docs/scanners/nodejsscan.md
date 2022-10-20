# [nodejsscan](https://github.com/ajinabraham/nodejsscan)

[nodejsscan](https://github.com/ajinabraham/nodejsscan) is a static security code scanner (SAST) for Node.js applications powered by [libsast](https://github.com/ajinabraham/libsast) and [semgrep](https://github.com/returntocorp/semgrep).

## Configuration

odejsscan supports, both, a web-based UI and a CLI that outputs reports in JSON, HTML, and SARIF formats. We use the latter mode to scan our code bases.

```yaml
  scanner_configs:
    Nodejsscan:
      missing-controls: true or false # Whether to enable missing security control checks
      # exceptions:
      #   - advisory_id: test_id1
      #     changed_by: security-team
      #     notes: Currently no patch exists and determined that this vulnerability is not exploitable.
      #     expiration: "2021-04-27"
```

The following nodejsscan config options are currently NOT supported.
```yaml
--output # We rely on the process's output to STDOUT. So, we set this to /dev/stdout
--json/sarif/sonarqube/html # Always set to JSON
--config # No configuration files specified
--exit-warning # Leave the default of exit code 0
```

## Exceptions

The skips configuration is supported for backwards compatibility and will be deprecated in the future. Salus exceptions are being normalized to the new exceptions configuration