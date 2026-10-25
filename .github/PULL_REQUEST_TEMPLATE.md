## Summary

Describe the change and why it is needed. Explain the problem from the user's
point of view, not only the implementation.

## Linked issue

Closes #

## Change type

- [ ] Bug fix
- [ ] New feature or tool
- [ ] Documentation
- [ ] Refactor or test-only change
- [ ] Packaging, installer, or CI
- [ ] Security hardening

## Audience impact

- [ ] Security practitioners
- [ ] MCP/AI developers
- [ ] Both

If this changes a tool name, argument, result field, environment variable, CLI
flag, or documented default, describe the change and the migration path.

## Verification

List the commands you ran and their results.

```sh
python -m unittest discover -s tests -v
make check
```

## Checklist

- [ ] Tests cover the new behavior or the regression being fixed.
- [ ] The unittest suite passes locally.
- [ ] `make check` passes, or I listed the equivalent commands that passed.
- [ ] Documentation, configuration references, and `CHANGELOG.md` are updated
      where behavior changed.
- [ ] Generated documentation is current
      (`PYTHONPATH=src python3 scripts/generate-tool-docs.py --check`).
- [ ] No secrets, credentials, customer data, or engagement artifacts are
      included in the diff or this description.
- [ ] No restricted component is added (`burpsuite`, `maltego`, `wpscan`,
      `waybackurls`), and any new third-party component has a license review.
- [ ] Container smoke tests were run if the runtime, Dockerfile, launcher,
      installer, or hardware support changed.
- [ ] Commits are signed off with `git commit -s`.
- [ ] I have read `CONTRIBUTING.md` and agree to the Code of Conduct.

## Security impact

Describe the effect on authorization, scope enforcement, audit logging, network
exposure, privileges, device access, or untrusted input handling. Call out any
new executable, subprocess call, download, or host capability. Note whether
`docs/SECURITY_MODEL.md` needs an update.

If there is no security impact, state "No security impact" and explain why.
