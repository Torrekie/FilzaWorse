# FilzaWorse

FilzaWorse is a small project based on Filza 5.0.1 b3. It adds worse_query-backed
file access.

It is an unofficial modified build. It is not made, sold, or supported by tigisoftware.
If you somehow paid for FilzaWorse somewhere, then you are dumb.

## Changes

- Adds read/write entries for supported system and application containers.
- Tries a bounded directory scan when a supported parent directory cannot be
  listed. Scan results may be incomplete.

## Installation

- **LiveContainer:** import the IPA through iloader or in LiveContainer.
- **Direct sideload:** install the IPA with AltStore or SideStore.

The installer must provide the App Group entitlement used by the build. File
access still depends on the permissions and sandbox extensions available to
the host environment.

## Supported versions

- The upstream worse_query README lists iOS/iPadOS 26.0 through 26.7.2 and
  27.2. Tested only on 27.0.1.
- FilzaWorse selects the upstream 26.x flags on iOS/iPadOS 26.x and the 27.x
  flags on 27.x.
- On other system versions, the worse_query backend stays disabled and Filza
  keeps its normal sandbox behavior. You may wait for jailbreak and use official
  Filza instead.
- LiveContainer, AltStore, and SideStore use is supported in principle; other
  installers are untested.

The System, SystemGroup, and shared App Group entries are listed by upstream
as iOS 27 paths. On iOS 26.x those entries may return the normal system error;
the other supported container paths remain available when the host grants them.

## Notes

FilzaWorse does not include the official Filza purchase or activation flow.
Use the official Filza app for any purchase or activation.

The public source contains the worse_query integration and directory discovery
code. The original Filza app, its bundled components, and signing materials are
not included.

## DISCLAIMER
NO WARRANTY GUARANTEE, USE AT YOUR OWN RISK.

## License and sources

The included source is released under GPL-3.0-or-later. See `LICENSE` and
`THIRD_PARTY_NOTICES.md`.

- https://github.com/forcequitOS/worse_query
- https://github.com/LiveContainer/LiveContainer
