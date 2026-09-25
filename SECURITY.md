# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private vulnerability
reporting on this repository (*Security* → *Report a vulnerability*). That channel is private
between you and the maintainers until a fix exists.

Useful in a report:

- what an attacker gains, and from which position (web page in the browser, another local
  user or process, the network, a malicious server response)
- the smallest sequence that reproduces it, the version or commit, the system and the browser
- the effect you actually saw, rather than the effect you expect

Please do not include third-party data, real prompts or credentials in a report.

## What is in scope

The sources in this repository: the agent, the detection engine and the browser extension,
as built from this tree. The server and console have their own repository. Signed packages,
installers, hosted instances and the Enterprise modules are out of scope here.

Findings that we treat as expected behavior rather than vulnerabilities:

- an administrator of the machine reading or changing the agent's configuration
- the absence of Enterprise capabilities in this edition

## Supported versions

The tip of the default branch. Fixes go to the default branch, and a release is cut from it.

## Handling

We acknowledge a report, investigate, and tell you what we found — including when we conclude
that there is nothing to fix. When a fix ships, the advisory credits the reporter unless they
ask otherwise.
