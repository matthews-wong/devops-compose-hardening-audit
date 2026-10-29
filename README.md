# devops-compose-hardening-audit

A small, dependency-free Python script that audits a Docker Compose project
for missing container hardening and prints one finding per service per rule.

It reads the output of `docker compose config --format json`, so variable
interpolation, `extends`, profiles and multiple `-f` files are already
resolved before the checks run. No Docker daemon is needed for that step.

## Usage

```sh
docker compose -f docker-compose.yml config --format json | python3 audit.py
python3 audit.py rendered.json          # or read a saved file
```

Exit code is `1` when any finding is reported, `0` otherwise.

## Rules

| id     | what it flags                                            |
| ------ | -------------------------------------------------------- |
| CH001  | image uses `:latest` or has no tag or digest             |
| CH002  | service runs as root (no `user`, or `user: 0`)           |
| CH003  | root filesystem is writable (`read_only` not true)       |
| CH004  | `cap_drop` does not include `ALL`                        |
| CH005  | `privileged: true`                                       |
| CH006  | no `healthcheck` defined                                 |
| CH007  | no memory limit under `deploy.resources.limits` / `mem_limit` |
| CH008  | `security_opt` lacks `no-new-privileges:true`            |

## Caveats

- Checks are per service and static: they do not inspect the image, so a
  `user` set in the Dockerfile still counts as root here (CH002). Set `user`
  in Compose to make the intent explicit.
- CH001 treats a digest as pinned; a version tag is accepted but not
  immutable.

## Validate

```sh
make validate
```

Runs the unit tests, then audits `examples/hardened.yml` (must pass) and
`examples/insecure.yml` (must fail). CI runs the same target.
