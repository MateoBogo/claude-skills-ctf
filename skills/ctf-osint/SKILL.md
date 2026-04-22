---
name: ctf-osint
description: OSINT for CTF: social media tracking (X/Tumblr/BlueSky/Discord), username enumeration, reverse image search, geolocation (EXIF/MGRS/Plus Codes/What3Words), DNS/WHOIS, Wayback, FEC/Tor/GitHub mining.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for OSINT lookups.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF OSINT

Quick reference for OSINT CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [social-media.md](social-media.md) - Twitter/X (user IDs, Snowflake timestamps, Nitter, memory.lol, Wayback CDX), Tumblr (blog checks, post JSON, avatars), BlueSky search + API, Unicode homoglyph steganography, Discord API, username OSINT (namechk, whatsmyname, Osint Industries), username metadata mining (postal codes), platform false positives, multi-platform chains, Strava fitness route OSINT
- [geolocation-and-media.md](geolocation-and-media.md) - Image analysis, reverse image search (including Baidu for China), Google Lens cropped region search, reflected/mirrored text reading, geolocation techniques (railroad signs, infrastructure maps, MGRS), Google Plus Codes, EXIF/metadata, hardware identification, newspaper archives, IP geolocation, Google Street View panorama matching, What3Words micro-landmark matching, Google Maps crowd-sourced photo verification, Overpass Turbo spatial queries
- [web-and-dns.md](web-and-dns.md) - Google dorking (including TBS image filters), Google Docs/Sheets enumeration, DNS recon (TXT, zone transfers), Wayback Machine, FEC research, Tor relay lookups, GitHub repository analysis, Telegram bot investigation, WHOIS investigation (reverse WHOIS, historical WHOIS, IP/ASN lookup)

---

## Pattern Recognition Index

Dispatch on the **kind of clue** in the prompt/image, not on the story.

| Signal | Technique → file |
|---|---|
| Only a username / handle given | Username OSINT (namechk, whatsmyname, Osint Industries) → social-media.md |
| Twitter/X profile URL, numeric user ID, or snowflake-looking timestamp | Snowflake decode + Nitter + memory.lol → social-media.md |
| Tumblr blog name, Mastodon/BlueSky handle | Platform-specific JSON/API lookups → social-media.md |
| Unicode-rich post text (Cyrillic or mathematical letters in ASCII-looking words) | Homoglyph steganography → social-media.md |
| Image with distinct building, sign, mountain, or road layout | Reverse image + Google Lens / Baidu → geolocation-and-media.md |
| Railroad/road sign text, mileage markers, regional infrastructure | Geolocation via infrastructure maps + MGRS → geolocation-and-media.md |
| `WxYyyy` style or three-random-words string | Google Plus Codes / What3Words → geolocation-and-media.md |
| EXIF present with GPS / camera serial | ExifTool + metadata chain → geolocation-and-media.md |
| Target is a domain / host IP | WHOIS + reverse DNS + ASN → web-and-dns.md |
| Tor `.onion` address or relay fingerprint | Tor relay lookups + Wayback of hidden services → web-and-dns.md |
| GitHub org/user URL, or leaked GitHub token | GitHub repo analysis + commit mining → web-and-dns.md |
| FEC / SEC / public-record style clue (US political or financial) | FEC research → web-and-dns.md |
| Cryptocurrency address + transaction context | On-chain tx tracing → (see ctf-forensics/disk-and-memory.md cross-ref) |
| Strava / fitness route image | Route OSINT via Strava heatmap → social-media.md |

Recognize the **kind of artefact**; don't chase the story's names.

---

---

For inline snippets and quick-reference tables, see [quickref.md](quickref.md). The Pattern Recognition Index above is the dispatch table — always consult it first.
