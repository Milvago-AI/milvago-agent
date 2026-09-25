# Milvago browser extension

One Manifest V3 source tree for Chromium browsers (Chrome, Edge, Brave, Vivaldi, Arc) and
Firefox. It talks only to the local Milvago agent, never to the server with credentials of its
own.

## Build and test

```bash
npm ci
npm test                            # Node's built-in test runner, no browser needed
node build-editions.js              # -> ../extension-community/ and ../extension-firefox-community/
node ../scripts/verify-community-package.mjs
```

`build-editions.js` assembles both packages from these sources: the Chromium one keeps the
public key that fixes its extension ID, the Firefox one carries its Gecko identity and update
channel. Never edit the generated directories; change the sources and rebuild.

## Coverage in this edition

- **Capture** on ChatGPT and Claude: the package carries the adapters, catalogue entries and
  content-script matches of these two sites only.
- **Presence** of the other AI platforms listed in the signed detection catalogue
  (`known_platforms`): the host was reached, nothing of the page is read.
- **Model observation**: the model that answered is recorded. Deciding which model is allowed
  is an Enterprise capability; `model-rules.js` here is the Community contract, with no decision.

## Installing

Load the unpacked `extension-community/` directory from `chrome://extensions` (Developer mode),
or `extension-firefox-community/` from `about:debugging` in Firefox. Managed deployment by
browser policy uses the signed packages served by the agent.
