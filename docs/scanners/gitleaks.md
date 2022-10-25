# [Gitleaks](https://github.com/zricethezav/gitleaks)

[Gitleaks](https://github.com/zricethezav/gitleaks) is a SAST tool for detecting and preventing hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an easy-to-use, all-in-one solution for detecting secrets, past or present, in your code.

## Configuration

There are two commands you will use to detect secrets; `detect` and `protect`.

### Detect 

The `detect` command is used to scan repos, directories, and files. This command can be used on developer machines and in CI environments.

When running detect on a git repository, gitleaks will parse the output of a `git log -p command`. `git log -p` generates patches which gitleaks will use to detect secrets. You can configure what commits `git log` will range over by using the `--log-opts` flag. `--log-opts` accepts any option for `git log -p`. For example, if you wanted to run gitleaks on a range of commits you could use the following command: `gitleaks detect --source . --log-opts="--all commitA..commitB`. See the git log documentation for more information.

### Protect

The `protect` command is used to uncommitted changes in a git repo. This command should be used on developer machines in accordance with shifting left on security. When running protect on a git repository, gitleaks will parse the output of a `git diff` command. You can set the `--staged` flag to check for changes in commits that have been git added. The `--staged` flag should be used when running Gitleaks as a pre-commit.

**NOTE**: the `protect` command can only be used on git repos, running protect on files or directories will result in an error message.

Since, at gridX, we are running salus in the CI/CD pipeline, we use the `detect` command by default.

```yaml
  scanner_configs:
    Gitleaks:
      no-git: true or false # Whether to treat the target directory as a non Git repository
      redact: true or false # Whether to redact the actual secrets found in the repo
      verbose: true or false # Whether to output the STDOUT of the tool
      exit-code: 'integer_value'
      log-opts: 'commitA...commitB' # The commit range to scan (e.g., HEAD^...HEAD)
      # exceptions:
      #   - advisory_id: test_id1
      #     changed_by: security-team
      #     notes: Currently no patch exists and determined that this vulnerability is not exploitable.
      #     expiration: "2021-04-27"
```

The following Gitleaks config options are currently NOT supported.
```yaml
--report-path # We rely on the process's output to STDOUT. So, we set this to /dev/stdout
--no-banner # Always ignored/not set
--report-format   # Currently always defaults to JSON and manually converted to SARIF
--max-target-megabytes # No limit on how large a file can be to be scanned
--format {csv,custom,html,screen,txt,xml,yaml}   # We always export to JSON
--source # Left to default
```

## Exceptions

The skips configuration is supported for backwards compatibility and will be deprecated in the future. Salus exceptions are being normalized to the new exceptions configuration