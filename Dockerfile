# syntax=docker/dockerfile:1
# Multi-stage: build the self-contained netdefense binary, then run it on a Kali
# base that carries the actual tool binaries the MCP wrappers shell out to.

# ---- build ----
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
# Builds netdefense (+ the kali-mcp lib it depends on). SQLite is bundled, so the
# builder's C toolchain (present in the rust image) is all that's needed.
RUN cargo build --release --bin netdefense

# ---- runtime (Kali, with the tools) ----
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive

# Install the binaries the tool registry wraps. The loop installs each package
# best-effort: a name that differs in the current Kali repo is skipped rather
# than failing the whole image (the wrapper then reports "not installed"), so
# the image always builds. Trim or extend this list as you like.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    for p in \
      nmap masscan whatweb dnsrecon dnsenum fierce theharvester amass \
      subfinder dnsx assetfinder waybackurls gau gospider katana \
      gobuster feroxbuster ffuf dirsearch wfuzz wafw00f \
      nikto nuclei wapiti sqlmap commix xsstrike dalfox arjun \
      wpscan joomscan cmseek droopescan \
      testssl.sh sslscan sslyze \
      hydra medusa john hashcat hashid cewl crunch \
      enum4linux-ng smbclient samba-common-bin smbmap netexec ldap-utils kerbrute \
      snmp onesixtyone rustscan netdiscover arp-scan naabu httpx-toolkit \
      yara clamav exploitdb gowitness tlsx \
      openssh-client sshpass \
    ; do apt-get install -y --no-install-recommends "$p" || echo "skip (not in repo): $p"; done; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/netdefense /usr/local/bin/netdefense

# Persist the SQLite DB in a volume; listen on all interfaces inside the container
# (map to 127.0.0.1 on the host — see docker-compose.yml).
RUN mkdir -p /data
WORKDIR /data
ENV NETDEFENSE_ADDR=0.0.0.0:8088 \
    NETDEFENSE_DB=/data/netdefense.db
VOLUME ["/data"]
EXPOSE 8088

# Default: the HTTP service + built-in gestionale at / .
# MCP server instead: `docker run -i netdefense netdefense mcp`
CMD ["netdefense"]
