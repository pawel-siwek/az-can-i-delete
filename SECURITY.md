# Security Policy

## Supported versions

Only the latest release receives security fixes. The project is pre-1.0, so a
fix ships as a new release rather than a backport.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's
[security advisory form](https://github.com/pawel-siwek/az-can-i-delete/security/advisories/new)
("Report a vulnerability" on the Security tab). If that is not available to you,
contact a maintainer listed in [MAINTAINERS.md](MAINTAINERS.md) privately and
ask for a channel.

Please include what you found, how to reproduce it, and which version or
commit it affects. You will get an acknowledgement within five working days,
and a fix or a plan within thirty. Reporters are credited in the advisory
unless they ask not to be.

## What counts

This tool reads Azure and prints a verdict. Beyond the usual — code execution,
credential exposure, a supply-chain weakness in the release — these are
security bugs here:

- anything in the `check` path that writes to Azure (ADR-0005);
- any account key, shared access signature or other secret reaching an output,
  a log or an error (ADR-0006);
- Azure free-form text reaching a report outside the sanitized `untrusted`
  field (ADR-0007);
- a failure reported as an absence, so that a resource in use can come out as
  `yes` (ADR-0004);
- an installer or release artifact that can be substituted without the
  checksum noticing (ADR-0011, ADR-0014).

A verdict that is wrong under the published rules is a bug, and can be reported
as an ordinary issue unless it could be used to make somebody delete a resource
that is in use.
