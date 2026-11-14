# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue: use GitHub's
"Report a vulnerability" (Security tab -> Advisories) on this repository. Include the
version, what you did, and what you expected. You will get an answer within a few days.

Please do not test against servers you do not own.

## Supported versions

Only the latest release receives fixes. The protocol is versioned (`v: 1`); a fix that
needs a protocol change ships with a new version number.

## Scope and design

What the server can and cannot do if it is compromised is described in
[PROTOCOL.md](PROTOCOL.md) section 8 and summarised in the README. In short: it cannot run
commands, pair a device (not even with a photographed QR code: the link key comes from a key
agreement between the phone and the desktop, and the desktop pairs only the device whose user types
the random number that device shows), or read or alter relayed screen text and prompts (relayed
bodies are sealed end to end between the desktop and each device). It can delay a command by up to
30 s or withhold it, see who is connected and when and the size and timing of messages, read
notification titles, link several pairings of one phone through the shared push endpoint, send
fake notifications, keep a phone or desktop from connecting, and serve a modified web app (which
can use the keys while the page runs or show a false number while pairing). Host it yourself and
keep it updated.
