# dsh-remote

DSH Host-plugin bundle: run commands, read and edit files, sync paths, and run
tests on remote machines over the locally installed `ssh` and `rsync`.

## Tools

| Tool | Purpose |
| --- | --- |
| `remote_exec` | Run a command, return exit code with captured stdout/stderr. |
| `remote_read` | Read a text file as line-numbered content. |
| `remote_edit` | `replace` (exact literal match), `create`, or `overwrite` a remote file. |
| `remote_rsync` | Copy paths `up`/`down` through rsync; `delete` and `dryRun` flags. |
| `remote_test` | Run a project's test suite, autodetected from `cwd` or given explicitly. |

## Hosts

`host` is always an SSH-config `Host` alias, never an ad-hoc `user@host`, so
keys, ports, and `ProxyJump` stay in ssh's own configuration. The allowlist is
the set of aliases in `~/.ssh/config`, optionally narrowed by `allowHosts`
globs (`!` negates). The active set is also written into the system prompt, so
the model knows which machines it may reach.

## Security

- Remote execution is **not sandboxed**: the local DSH file policy does not
  apply, and commands run as the configured remote user.
- `remote_edit` needs an exact, unique match for `replace`, so a stale
  `old_string` fails instead of corrupting the file.
- Commands matching `approvalPatterns` (default: `rm -rf`, `mkfs`, `dd of=/dev`,
  shutdown/reboot, disk partitioning, firewall flush, `git reset --hard` /
  `git clean -fd`, `DROP`/`TRUNCATE`, user management, `kill -9`, and
  `rsync --delete`) ask for approval before dispatch. Other remote commands run
  without asking.
- Caller cancellation and per-call deadlines kill the whole process group, so
  no orphaned remote client survives a stopped turn.

## Why this bundle imports nothing

A profile bundle installed from a local directory is linked as a **symlink**, so
Node resolves its bare imports from the link's realpath. For a bundle outside
the profile directory that realpath has no `node_modules` above it, and every
`import '@deepseek-ai/...'` fails with `ERR_MODULE_NOT_FOUND`. This bundle
therefore imports only `node:` builtins and registers tools through the raw
registry shape.

## `ssh` inside the DSH bash sandbox

An `ssh` call made from the sandboxed `bash` tool can fail with
`Bad owner or permissions on /etc/ssh/ssh_config.d/...` and exit 255. That is a
sandbox artifact, not a system fault: the sandbox maps the host root uid, so a
root-owned file appears as `65534:nobody` and OpenSSH rejects the chain. The
tools here are unaffected — they spawn `ssh` from the host process.

`sshConfigFile` exists only for the rare deployment whose real system
`ssh_config` is genuinely unreadable. Setting it to the user config path makes
ssh read that file alone, replacing the whole chain. The default `''` keeps
ssh's own configuration.

## Configuration

Override the plugin row's `config` in the profile's `cordis.patch.yml`:

```yaml
- id: dsh-remote
  config:
    allowHosts: ['jetson-*', '!jetson-prod-*']
    allowFromSshConfig: true
    sshConfig: ~/.ssh/config
    sshConfigFile: ''
    approvalPatterns: ['\\brm\\s+-[a-zA-Z]*[rf]']
    reuseConnections: true
    connectTimeoutSec: 10
    timeoutMs: 120000
    maxOutputBytes: 65536
```

The default `allowHosts: []` with `allowFromSshConfig: true` means exactly the
aliases declared in `sshConfig`. A single `"*"` allows any alias that resolves.
`sshConfigFile: ''` keeps ssh's own config chain.

## Install

Through the plugin manager with the absolute bundle directory as the target;
`install_bundle` performs the package installation and bundle selection. The
row's patch applies through the loader on the next boot: an install that lands
in a running host reports `profile reload requires the root Include entry` and
needs a restart, which `dsh <profile> --dump-config` verifies without booting.
