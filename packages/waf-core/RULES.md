# JianFlow Rule Provenance

## Built-in rules

The built-in rules shipped in `@jev-waf/core` are original JianFlow implementations. The
`CRS-compatible` label describes the request variables and attack categories they cover; it
does not mean that OWASP CRS rule text, regular expressions, data files, or GPL code was copied.
The built-in implementations are distributed under the repository MIT license.

| Package ID | Scope | License | Source boundary |
| --- | --- | --- | --- |
| `jianflow-original` | SQL injection, XSS, SSTI, NoSQL, command injection, traversal and SSRF patterns | MIT | JianFlow-authored patterns |
| `jianflow-crs-compatible-original` | A small CRS-compatible request inspection subset | MIT | JianFlow-authored patterns and metadata |
| `modsecurity-import` | User-provided imported rules | User supplied | The importer stores the user-declared source and license |

Imported rules are not relicensed by JianFlow. Operators must verify that the source license
permits deployment and must retain any required upstream notices.

## Offline map data

The web console uses the `world-atlas` Natural Earth-derived TopoJSON package for the offline
world outline. The package is distributed under its declared ISC license. It is an application
dependency and is not part of the JianFlow rule license.

## Runtime dependencies

The project keeps dependency license metadata in package manifests and lockfiles. In particular,
`re2-wasm` is used for bounded regular-expression evaluation, `ipaddr.js` for IP/CIDR parsing,
and MaxMind readers for operator-supplied MMDB files. MMDB files are not bundled and remain the
operator's responsibility to license and update.
