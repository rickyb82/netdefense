# kali-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes common Kali Linux
security tools to any MCP client (Claude Desktop, Claude Code, etc.) over stdio.

It is a thin, safe wrapper: each tool call becomes a direct subprocess
invocation (no shell, so no shell-injection surface), with captured output and a
hard timeout. The MCP client decides *which* scan to run; this server just runs
the underlying binary.

> **Authorised use only.** These are real offensive security tools. Only point
> them at hosts, networks and services you own or have **explicit written
> permission** to test. Scanning or brute-forcing systems without authorisation
> is illegal in most jurisdictions. Typical legitimate uses: testing and
> hardening your own network, CTFs, lab environments, and authorised pentest
> engagements.

## Exposed tools

| Tool             | Binary     | Purpose                                   |
|------------------|------------|-------------------------------------------|
| `nmap_scan`      | `nmap`     | Port/service discovery                    |
| `masscan_scan`   | `masscan`  | High-rate port sweeps                     |
| `whatweb`        | `whatweb`  | Web technology fingerprinting             |
| `dnsrecon`       | `dnsrecon` | DNS enumeration                           |
| `gobuster`       | `gobuster` | Directory / DNS / vhost brute forcing     |
| `nikto`          | `nikto`    | Web server vuln scanning                  |
| `sqlmap`         | `sqlmap`   | SQL injection testing (`--batch` default) |
| `ffuf`           | `ffuf`     | Web fuzzing (url must contain `FUZZ`)     |
| `wpscan`         | `wpscan`   | WordPress vuln scanning                   |
| `hydra`          | `hydra`    | Network login brute forcing               |
| `john`           | `john`     | Password hash cracking                    |
| `hashcat`        | `hashcat`  | GPU/CPU password hash cracking            |
| `testssl`        | `testssl.sh` | TLS/SSL config + vuln testing           |
| `sslscan`        | `sslscan`  | Enumerate SSL/TLS protocols, ciphers, cert |
| `enum4linux_ng`  | `enum4linux-ng` | SMB/NetBIOS/LDAP enumeration         |
| `amass`          | `amass`    | Subdomain enumeration (`amass enum`)      |
| `feroxbuster`    | `feroxbuster` | Fast recursive content discovery       |
| `nuclei`         | `nuclei`   | Template-based vuln scanner (CVEs, exposures) |
| `yara`           | `yara`     | Scan files for webshell/malware signatures |
| `clamscan`       | `clamscan` | ClamAV malware/webshell scan of files     |
| `searchsploit`   | `searchsploit` | Exploit-DB lookup by term/CVE         |
| `httpx`          | `httpx`    | Fast HTTP probing/fingerprint             |
| `naabu`          | `naabu`    | Fast port scanner                         |
| `subfinder`      | `subfinder`| Passive subdomain enumeration             |
| `dnsx`           | `dnsx`     | Fast DNS resolution/queries               |
| `dalfox`         | `dalfox`   | XSS scanner                               |
| `arjun`          | `arjun`    | Hidden HTTP parameter discovery           |
| `katana`         | `katana`   | Web crawler / endpoint discovery          |
| `gau`            | `gau`      | Known-URL harvesting from web archives    |
| `gowitness`      | `gowitness`| Screenshot a web page                     |
| `wafw00f`        | `wafw00f`  | WAF detection/fingerprint                 |
| `tlsx`           | `tlsx`     | TLS certificate data (SAN/CN/expiry)      |
| `netexec`        | `nxc`      | SMB/WinRM/LDAP/SSH enum + cred testing    |
| `smbmap`         | `smbmap`   | SMB share enumeration                     |
| `joomscan`       | `joomscan` | Joomla CMS vulnerability scanner          |
| `fierce`         | `fierce`   | DNS reconnaissance                        |
| `dnsenum`        | `dnsenum`  | DNS enumeration                           |
| `theharvester`   | `theHarvester` | OSINT emails/hosts/subdomains         |
| `assetfinder`    | `assetfinder` | Related subdomains                     |
| `waybackurls`    | `waybackurls` | Known URLs from Wayback                 |
| `gospider`       | `gospider` | Web crawler                               |
| `dirsearch`      | `dirsearch`| Web path brute forcer                     |
| `wfuzz`          | `wfuzz`    | Web fuzzer (FUZZ keyword)                 |
| `wapiti`         | `wapiti`   | Web app vulnerability scanner             |
| `xsstrike`       | `xsstrike` | XSS detection                             |
| `commix`         | `commix`   | Command-injection testing                 |
| `cmseek`         | `cmseek`   | CMS detection/enumeration                 |
| `droopescan`     | `droopescan` | Drupal/SilverStripe/etc scanner         |
| `rustscan`       | `rustscan` | Very fast port scanner                    |
| `netdiscover`    | `netdiscover` | ARP host discovery                     |
| `arp_scan`       | `arp-scan` | Local-network ARP discovery               |
| `snmpwalk`       | `snmpwalk` | Walk an SNMP tree                         |
| `onesixtyone`    | `onesixtyone` | SNMP community scanner                  |
| `smbclient`      | `smbclient`| List SMB shares                           |
| `rpcclient`      | `rpcclient`| MS-RPC client queries                     |
| `ldapsearch`     | `ldapsearch` | Query LDAP/AD                           |
| `kerbrute`       | `kerbrute` | Kerberos user enum / spraying             |
| `medusa`         | `medusa`   | Parallel login brute forcer               |
| `cewl`           | `cewl`     | Custom wordlist from a site               |
| `hashid`         | `hashid`   | Identify hash types                       |
| `sslyze`         | `sslyze`   | Deep TLS configuration analysis           |

Every tool also accepts:
- `extra_args`: an array of raw CLI flags appended verbatim — the escape hatch
  for anything not modelled as a typed parameter.
- `timeout_secs`: integer; the process is killed after this many seconds
  (default **300**). Raise it for long cracking/fuzzing runs.

The underlying binaries are **not bundled**. Install the ones you need
(they ship with Kali, or `sudo apt install nmap masscan nikto ...`). If a binary
is missing, the tool returns a clear "not installed" message instead of failing
the whole server. Some scans (e.g. `nmap -sS`/`-O`, `masscan`) need root.

## Build

```sh
cargo build --release
# binary at ./target/release/kali-mcp
```

## Register with an MCP client

The server speaks JSON-RPC over stdio. Point your client at the built binary.

**Claude Code:**
```sh
claude mcp add kali -- /home/user/kali-mcp/target/release/kali-mcp
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "kali": {
      "command": "/home/user/kali-mcp/target/release/kali-mcp"
    }
  }
}
```

## Defensive context

These recon tools are exactly what you need to understand your own exposure
after a DoS/DDoS incident: `nmap_scan` / `masscan_scan` to inventory what is
actually reachable from outside, `whatweb` / `nikto` / `wpscan` to see what an
attacker fingerprints on your web stack. Mitigating the DoS/DDoS itself is a
separate job (upstream/provider filtering, rate limiting, a CDN/scrubbing
service) — this server maps the attack surface; it does not generate attack
traffic.

## Protocol notes

- Transport: newline-delimited JSON-RPC 2.0 over stdio.
- Implements `initialize`, `tools/list`, `tools/call`, `ping`.
- Requests are handled concurrently; a long scan does not block other calls.
- Tool failures are returned as results with `isError: true` (per MCP), so the
  client sees the command line, stdout, stderr and exit code.

## Extending

Add a `ToolDef` to `registry()` in `src/tools.rs`: give it a name, the binary,
a description, a JSON-Schema for its arguments, and a `build` function mapping
the arguments object to a `Vec<String>` of CLI args. No protocol code to touch.
