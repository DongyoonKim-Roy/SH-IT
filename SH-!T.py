#!/usr/bin/env python3
"""Basic enumeration starter
Usage: python3 auto_enum.py <targets.txt>

Do not name this file enum.py — it shadows the Python stdlib 'enum' module.
"""

from __future__ import annotations

import re
import sys
import subprocess
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
RED = "\033[0;31m"
NC = "\033[0m"

VERSION = "v0.1"
AUTHOR = "roy"

MAGENTA = "\033[1;35m"
BLUE = "\033[1;34m"

def _vis_len(text: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def _box_line(text: str, width: int) -> str:
    pad = width - _vis_len(text)
    if pad < 0:
        pad = 0
    return f"    {CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}"


def build_banner() -> str:
    width = 62
    rows = [
        f"{YELLOW}   ███████╗{GREEN}██╗  ██╗{MAGENTA}  ██╗{RED}  ████████╗",
        f"{YELLOW}   ██╔════╝{GREEN}██║  ██║{MAGENTA}  ██║{RED}  ╚══██╔══╝",
        f"{YELLOW}   ███████╗{GREEN}███████║{MAGENTA}  ██║{RED}     ██║   ",
        f"{YELLOW}   ╚════██║{GREEN}██╔══██║{MAGENTA}  ╚═╝{RED}     ██║   ",
        f"{YELLOW}   ███████║{GREEN}██║  ██║{MAGENTA}  ██╗{RED}     ██║   ",
        f"{YELLOW}   ╚══════╝{GREEN}╚═╝  ╚═╝{MAGENTA}  ╚═╝{RED}     ╚═╝   ",
        "",
        f"{YELLOW}              E N U M{NC}   and   {MAGENTA}S H !{RED} T",
        "",
        f"{BLUE}             {VERSION}{NC}                         {GREEN}by {AUTHOR}",
    ]
    top = f"    {CYAN}╔{'═' * width}╗{NC}"
    bot = f"    {CYAN}╚{'═' * width}╝{NC}"
    body = [_box_line(row, width) for row in rows]
    return "\n".join(["", top, *body, bot, ""])


BANNER = build_banner()

COMMAND_LOG = Path("command.txt")
REPORT_FILE = Path("report.md")
SUGGESTED_LOG = Path("next_commands.txt")
OUT_DIR = Path("nmap")
PCT_RE = re.compile(
    r"(?P<phase>.+?)\s+Timing:\s+About\s+(?P<pct>[0-9.]+)%\s+done"
)

NEXT_STEPS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "smb",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    464: "kpasswd",
    593: "rpc-http",
    636: "ldaps",
    1433: "mssql",
    2049: "nfs",
    3268: "ldap-gc",
    3269: "ldaps-gc",
    3306: "mysql",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9389: "adws",
}

HIGHLIGHT_SCRIPTS = {
    "http-title",
    "http-server-header",
    "http-methods",
    "http-auth",
    "http-cookie-flags",
    "ssl-cert",
    "ssl-date",
    "ftp-anon",
    "ftp-syst",
    "smb-os-discovery",
    "smb-security-mode",
    "smb2-security-mode",
    "smb2-time",
    "smb-enum-shares",
    "smb-enum-users",
    "clock-skew",
    "rdp-ntlm-info",
    "rdp-enum-encryption",
    "ms-sql-info",
    "mysql-info",
    "ldap-rootdse",
    "dns-nsid",
    "ssh2-enum-algos",
}

# {ip} {hostname} {domain} {domain_dn} 치환. 실행하지 않고 제안만 한다.
# 워드리스트/커맨드 스타일은 개인 노트(Recon/Web/SMB/LDAP/DNS) 기준.
WEB_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SUB_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

COMMAND_TEMPLATES = {
    21: [
        "nxc ftp {ip}",
        "hydra -L users.txt -P /usr/share/wordlists/seclists/Passwords/probable-v2-top1575.txt -s 21 ftp://{ip}",
    ],
    22: [
        "nxc ssh {ip}",
        "ssh {ip}",
    ],
    25: [
        "nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay {ip}",
        "smtp-user-enum -M VRFY -U users.txt -t {ip}",
        "swaks --to victim --from attacker --header 'Subject: Testing!' --body 'ignore this message' --server {ip}",
    ],
    53: [
        "dig @{ip} -x {ip}",
        "dig @{ip} axfr {domain}",
        "dig @{ip} {domain} ANY",
        "nslookup -type=SRV _ldap._tcp.dc._msdcs.{domain} {ip}",
    ],
    80: [
        "whatweb http://{ip}",
        "curl -I http://{ip}",
        "curl -s http://{ip}/robots.txt",
        "gobuster dir -u http://{ip} -w " + WEB_WORDLIST + " -x txt,php,html -t 30",
        "feroxbuster -u http://{ip} -w " + WEB_WORDLIST + " -t 10",
        "nikto -h http://{ip}",
    ],
    88: [
        "nxc ldap {ip}",
        "impacket-GetNPUsers {domain}/ -dc-ip {ip} -usersfile users.txt -no-pass",
        "kerbrute userenum --dc {ip} -d {domain} users.txt",
    ],
    110: [
        "telnet {ip} 110",
    ],
    111: [
        "rpcinfo -p {ip}",
        "showmount -e {ip}",
    ],
    135: [
        "impacket-rpcdump {ip}",
        "impacket-lookupsid {ip} -no-pass",
    ],
    139: [
        "nxc smb {ip}",
        "nxc smb {ip} -u '' -p '' --shares",
        "smbclient -N -L //{ip}",
        "nmap --script smb-vuln* -p 139,445 -oN nmap/smb-vuln-{ip} {ip}",
    ],
    143: [
        "telnet {ip} 143",
    ],
    161: [
        "snmpwalk -v 2c -c public {ip}",
    ],
    389: [
        "nxc ldap {ip}",
        "ldapsearch -x -H ldap://{ip} -s base namingcontexts",
        "ldapsearch -x -H ldap://{ip} -b '{domain_dn}' '(objectClass=*)'",
        "ldapdomaindump -o ldap {ip}",
    ],
    443: [
        "whatweb https://{ip}",
        "curl -Ik https://{ip}",
        "curl -sk https://{ip}/robots.txt",
        "gobuster dir -u https://{ip} -w " + WEB_WORDLIST + " -x txt,php,html -k -t 30",
        "feroxbuster -u https://{ip} -w " + WEB_WORDLIST + " -k -t 10",
        "nikto -h https://{ip}",
    ],
    445: [
        "nxc smb {ip}",
        "nxc smb {ip} -u '' -p '' --shares",
        "nxc smb {ip} --users",
        "nxc smb {ip} --pass-pol",
        "smbclient -N -L //{ip}",
        "nmap --script smb-vuln* -p 139,445 -oN nmap/smb-vuln-{ip} {ip}",
    ],
    636: [
        "nxc ldap {ip}",
        "ldapsearch -x -H ldaps://{ip} -s base namingcontexts",
    ],
    1433: [
        "nxc mssql {ip}",
    ],
    2049: [
        "showmount -e {ip}",
        "nxc nfs {ip}",
    ],
    3268: [
        "nxc ldap {ip}",
        "ldapsearch -x -H ldap://{ip} -s base namingcontexts",
    ],
    3306: [
        "nxc mysql {ip}",
        "mysql -h {ip} -u root --skip-ssl",
    ],
    3389: [
        "nxc rdp {ip}",
    ],
    5985: [
        "nxc winrm {ip}",
    ],
    5986: [
        "nxc winrm {ip}",
    ],
    6379: [
        "redis-cli -h {ip} info",
        "nxc redis {ip}",
    ],
    8080: [
        "whatweb http://{ip}:8080",
        "curl -I http://{ip}:8080",
        "gobuster dir -u http://{ip}:8080 -w " + WEB_WORDLIST + " -x txt,php,html -t 30",
        "feroxbuster -u http://{ip}:8080 -w " + WEB_WORDLIST + " -t 10",
    ],
    8443: [
        "whatweb https://{ip}:8443",
        "curl -Ik https://{ip}:8443",
        "gobuster dir -u https://{ip}:8443 -w " + WEB_WORDLIST + " -x txt,php,html -k -t 30",
        "feroxbuster -k -u https://{ip}:8443 -w " + WEB_WORDLIST + " -t 10",
    ],
    9389: [
        "nxc ldap {ip}",
        "bloodhound-python -d {domain} -ns {ip} -dc {hostname} -c all --zip --dns-tcp",
    ],
}


@dataclass
class PortInfo:
    port: int
    proto: str
    state: str
    service: str
    version: str
    scripts: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class HostInfo:
    ip: str
    hostname: str
    state: str
    ports: list[PortInfo] = field(default_factory=list)
    os_guess: str = ""
    raw_xml: str = ""
    host_scripts: list[tuple[str, str]] = field(default_factory=list)


def usage() -> None:
    print(f"Usage: {sys.argv[0]} <targets.txt>")
    print("Example: python3 auto_enum.py targets.txt")
    print()
    print("targets.txt format (one IP per line):")
    print("  10.10.10.10")
    print("  10.10.10.11")
    print("  # comments and empty lines are ignored")
    sys.exit(1)


def load_targets(path: Path) -> list[str]:
    if not path.is_file():
        print(f"{RED}[-] File not found: {path}{NC}")
        sys.exit(1)

    targets: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line.split()[0])

    if not targets:
        print(f"{RED}[-] No targets found in {path}{NC}")
        sys.exit(1)

    return targets


def safe_name(ip: str) -> str:
    return ip.replace("/", "_").replace(":", "_")


def save_command(cmd: list[str]) -> None:
    with COMMAND_LOG.open("a", encoding="utf-8") as f:
        f.write(" ".join(cmd) + "\n")


def strip_cpe(basename: Path) -> None:
    """nmap 결과에서 cpe:/ 항목을 제거한다."""
    xml_path = Path(str(basename) + ".xml")
    nmap_path = Path(str(basename) + ".nmap")

    if xml_path.is_file():
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for parent in root.iter():
                for child in list(parent):
                    if child.tag == "cpe":
                        parent.remove(child)
            tree.write(xml_path, encoding="utf-8", xml_declaration=True)
        except ET.ParseError:
            text = xml_path.read_text(encoding="utf-8", errors="replace")
            text = re.sub(r"\s*<cpe>.*?</cpe>", "", text)
            xml_path.write_text(text, encoding="utf-8")

    if nmap_path.is_file():
        kept = []
        for line in nmap_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "cpe:/" in line.lower():
                continue
            kept.append(line)
        nmap_path.write_text("\n".join(kept) + "\n", encoding="utf-8")


def print_bar(pct: float, phase: str = "", final: bool = False) -> None:
    width = 28
    pct = max(0.0, min(100.0, pct))
    filled = int(width * pct / 100)
    bar = "#" * filled + "-" * (width - filled)
    extra = f"  {phase.strip()}" if phase.strip() else ""
    line = f"{YELLOW}[*] [{bar}] {pct:5.1f}%{extra}{NC}"
    padded = f"\r{line:<120}"
    print(padded, end="\n" if final else "", flush=True)


def run_nmap(cmd: list[str]) -> int:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        text = line.rstrip("\n")
        match = PCT_RE.search(text)
        if match:
            try:
                pct = float(match.group("pct"))
            except ValueError:
                pct = 0.0
            print_bar(pct, match.group("phase"))
    return proc.wait()


def service_version(svc: ET.Element | None) -> tuple[str, str]:
    if svc is None:
        return "", ""
    name = svc.get("name", "")
    parts = [
        svc.get("product", ""),
        svc.get("version", ""),
        svc.get("extrainfo", ""),
    ]
    version = " ".join(p for p in parts if p).strip()
    return name, version


def parse_nmap_xml(xml_path: Path, fallback_ip: str) -> HostInfo:
    if not xml_path.is_file():
        return HostInfo(ip=fallback_ip, hostname="", state="unknown")

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return HostInfo(ip=fallback_ip, hostname="", state="parse-error")

    host_el = root.find("host")
    if host_el is None:
        return HostInfo(ip=fallback_ip, hostname="", state="down")

    addr = fallback_ip
    for address in host_el.findall("address"):
        if address.get("addrtype") in {"ipv4", "ipv6"}:
            addr = address.get("addr", fallback_ip)
            break

    hostname = ""
    for hn in host_el.findall("./hostnames/hostname"):
        name = hn.get("name", "")
        if name:
            hostname = name
            break

    state = "unknown"
    status_el = host_el.find("status")
    if status_el is not None:
        state = status_el.get("state", "unknown")

    os_guess = ""
    osmatch = host_el.find("./os/osmatch")
    if osmatch is not None:
        os_guess = osmatch.get("name", "")

    ports: list[PortInfo] = []
    for port_el in host_el.findall("./ports/port"):
        state_el = port_el.find("state")
        port_state = state_el.get("state", "") if state_el is not None else ""
        if port_state != "open":
            continue
        try:
            portnum = int(port_el.get("portid", "0"))
        except ValueError:
            continue
        proto = port_el.get("protocol", "tcp")
        name, version = service_version(port_el.find("service"))
        scripts: list[tuple[str, str]] = []
        for script in port_el.findall("script"):
            sid = script.get("id", "")
            output = (script.get("output") or "").strip()
            if sid and output:
                scripts.append((sid, output))
        ports.append(
            PortInfo(
                port=portnum,
                proto=proto,
                state=port_state,
                service=name,
                version=version,
                scripts=scripts,
            )
        )

    ports.sort(key=lambda p: (p.proto, p.port))

    host_scripts: list[tuple[str, str]] = []
    for script in host_el.findall("./hostscript/script"):
        sid = script.get("id", "")
        output = (script.get("output") or "").strip()
        if sid and output:
            host_scripts.append((sid, output))

    return HostInfo(
        ip=addr,
        hostname=hostname,
        state=state,
        ports=ports,
        os_guess=os_guess,
        raw_xml=str(xml_path),
        host_scripts=host_scripts,
    )


def notable_for(host: HostInfo) -> list[str]:
    notes: list[str] = []
    for p in host.ports:
        label = p.service or "unknown"
        notes.append(f"{p.port}/{p.proto} {label}")
        for sid, output in p.scripts:
            if sid not in HIGHLIGHT_SCRIPTS:
                continue
            first = output.splitlines()[0].strip() if output else ""
            if first:
                notes.append(f"{sid}: {first}")
    for sid, output in host.host_scripts:
        if sid not in HIGHLIGHT_SCRIPTS:
            continue
        first = output.splitlines()[0].strip() if output else ""
        if first:
            notes.append(f"{sid}: {first}")
    return notes


def extract_domain(host: HostInfo) -> str:
    blob = " ".join(
        [host.hostname or ""]
        + [out for _, out in host.host_scripts]
        + [out for p in host.ports for _, out in p.scripts]
        + [p.version for p in host.ports]
    )
    patterns = [
        r"DNS_Domain_Name:\s*([A-Za-z0-9._-]+)",
        r"Domain name:\s*([A-Za-z0-9._-]+)",
        r"Domain:\s*([A-Za-z0-9._-]+)",
        r"DNS_Tree_Name:\s*([A-Za-z0-9._-]+)",
    ]
    for pat in patterns:
        m = re.search(pat, blob)
        if m:
            return m.group(1).strip().strip(".")
    if host.hostname and "." in host.hostname:
        return host.hostname.split(".", 1)[1]
    return "domain.local"


def domain_dn(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    if not parts:
        return "DC=domain,DC=local"
    return ",".join(f"DC={p}" for p in parts)


def suggest_by_port(host: HostInfo) -> list[tuple[PortInfo, list[str]]]:
    domain = extract_domain(host)
    values = {
        "ip": host.ip,
        "hostname": host.hostname or host.ip,
        "domain": domain,
        "domain_dn": domain_dn(domain),
    }
    grouped: list[tuple[PortInfo, list[str]]] = []
    for p in host.ports:
        cmds: list[str] = []
        seen: set[str] = set()
        for tmpl in COMMAND_TEMPLATES.get(p.port, []):
            try:
                cmd = tmpl.format(**values)
            except KeyError:
                cmd = tmpl
            if cmd not in seen:
                seen.add(cmd)
                cmds.append(cmd)
        if cmds:
            grouped.append((p, cmds))
    return grouped


def suggest_commands(host: HostInfo) -> list[str]:
    cmds: list[str] = []
    seen: set[str] = set()
    for _, port_cmds in suggest_by_port(host):
        for cmd in port_cmds:
            if cmd not in seen:
                seen.add(cmd)
                cmds.append(cmd)
    return cmds


def next_actions(host: HostInfo) -> list[str]:
    return suggest_commands(host)


def print_grouped(grouped: list[tuple[PortInfo, list[str]]]) -> None:
    if not grouped:
        print(f"{YELLOW}[*] Suggested commands : none{NC}")
        return
    print(f"{YELLOW}[*] Suggested commands{NC}")
    for i, (port, cmds) in enumerate(grouped, start=1):
        label = port.service or NEXT_STEPS.get(port.port, "unknown")
        print(f"{CYAN}[{i}] {port.port}/{port.proto} {label}{NC}")
        for cmd in cmds:
            print(f"    {cmd}")


def print_suggestions(host: HostInfo) -> list[tuple[PortInfo, list[str]]]:
    grouped = suggest_by_port(host)
    print_grouped(grouped)
    return grouped


def run_selected(grouped: list[tuple[PortInfo, list[str]]]) -> None:
    if not grouped:
        return

    while True:
        print()
        print(f"{YELLOW}Run suggested commands?{NC}")
        print("    number, comma list, a=all, n=done")
        print("    example: 1    or    1,2")
        try:
            choice = input("> ").strip().lower()
        except EOFError:
            print()
            return

        if not choice or choice in {"n", "no", "skip", "q", "quit", "done"}:
            print(f"{YELLOW}[*] done selecting{NC}")
            return

        if choice in {"a", "all"}:
            indexes = list(range(1, len(grouped) + 1))
        else:
            indexes = []
            bad = False
            for part in choice.replace(" ", "").split(","):
                if not part.isdigit():
                    print(f"{RED}[-] invalid choice: {part}{NC}")
                    bad = True
                    break
                indexes.append(int(part))
            if bad:
                continue

        selected: list[tuple[PortInfo, list[str]]] = []
        out_of_range = False
        for idx in indexes:
            if idx < 1 or idx > len(grouped):
                print(f"{RED}[-] out of range: {idx}{NC}")
                out_of_range = True
                break
            selected.append(grouped[idx - 1])
        if out_of_range:
            continue

        for port, cmds in selected:
            print(f"{CYAN}[*] running {port.port}/{port.proto}{NC}")
            for cmd in cmds:
                print(f"{YELLOW}[>] {cmd}{NC}")
                save_command(cmd)
                subprocess.run(cmd, shell=True)
                print(f"{GREEN}[+] completed : {cmd}{NC}")
                print()

        print(f"{CYAN}[*] back to menu{NC}")
        print_grouped(grouped)


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", "<br>")


def trim_script(output: str, max_lines: int = 8) -> str:
    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join(lines[:max_lines]) + "\n..."


def build_report(hosts: list[HostInfo], target_file: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines: list[str] = [
        "# Enumeration Report",
        "",
        f"- Date: {now}",
        f"- Targets: `{target_file}`",
        f"- Scan: `nmap -sCV -p- -oA nmap/<ip> <ip>`",
        f"- Raw output: `{OUT_DIR}/`",
        "",
        "## Summary",
        "",
        "| IP | Hostname | State | Open ports | Notable |",
        "|----|----------|-------|------------|---------|",
    ]

    for host in hosts:
        ports = ", ".join(f"{p.port}/{p.proto}" for p in host.ports) or "-"
        notable = "; ".join(notable_for(host)[:4]) or "-"
        lines.append(
            f"| {host.ip} | {host.hostname or '-'} | {host.state} | "
            f"{md_escape(ports)} | {md_escape(notable)} |"
        )

    for host in hosts:
        lines += [
            "",
            f"## {host.ip}",
            "",
            f"- Hostname: {host.hostname or '-'}",
            f"- State: {host.state}",
            f"- OS guess: {host.os_guess or '-'}",
            f"- Raw: `{host.raw_xml or '-'}`",
            "",
            "### Open Ports",
            "",
        ]
        if not host.ports:
            lines.append("_No open ports found._")
        else:
            lines += [
                "| Port | Proto | Service | Version |",
                "|------|-------|---------|---------|",
            ]
            for p in host.ports:
                lines.append(
                    f"| {p.port} | {p.proto} | {p.service or '-'} | "
                    f"{md_escape(p.version or '-')} |"
                )

        interesting = [
            (f"{p.port}/{p.proto}", sid, out)
            for p in host.ports
            for sid, out in p.scripts
            if sid in HIGHLIGHT_SCRIPTS
        ]
        interesting += [
            ("host", sid, out)
            for sid, out in host.host_scripts
            if sid in HIGHLIGHT_SCRIPTS
        ]
        lines += ["", "### Interesting"]
        if not interesting:
            lines += ["", "_No highlighted script output._"]
        else:
            for where, sid, out in interesting:
                lines += [
                    "",
                    f"**{where} — {sid}**",
                    "",
                    "```",
                    trim_script(out),
                    "```",
                ]

        actions = next_actions(host)
        lines += ["", "### Next commands"]
        grouped = suggest_by_port(host)
        if not grouped:
            lines += ["", "_No suggested follow-up._"]
        else:
            for port, cmds in grouped:
                label = port.service or NEXT_STEPS.get(port.port, "unknown")
                lines += ["", f"#### {port.port}/{port.proto} {label}", "", "```bash"]
                lines.extend(cmds)
                lines.append("```")

    lines.append("")
    return "\n".join(lines)


def write_report(hosts: list[HostInfo], target_file: str) -> None:
    REPORT_FILE.write_text(build_report(hosts, target_file), encoding="utf-8")


def print_host_summary(host: HostInfo) -> None:
    print(f"{CYAN}---------- readable summary ----------{NC}")
    print(f"{YELLOW}[*] Host     : {host.ip}{NC}")
    print(f"{YELLOW}[*] Hostname : {host.hostname or '-'}{NC}")
    print(f"{YELLOW}[*] State    : {host.state}{NC}")
    if not host.ports:
        print(f"{YELLOW}[*] Ports    : none open{NC}")
    else:
        print(f"{YELLOW}[*] Open ports{NC}")
        print(f"    {'PORT':<11} {'SERVICE':<16} VERSION")
        for p in host.ports:
            port = f"{p.port}/{p.proto}"
            print(f"    {port:<11} {(p.service or '-'):<16} {p.version or '-'}")
    print_suggestions(host)
    print(f"{CYAN}--------------------------------------{NC}")


def scan_ip(ip: str) -> tuple[int, Path]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    basename = OUT_DIR / safe_name(ip)
    cmd = ["nmap", "-sCV", "-p-", "-oA", str(basename), ip]
    save_command(cmd)
    live_cmd = [
        "nmap",
        "-sCV",
        "-p-",
        "-oA",
        str(basename),
        "-v",
        "--stats-every",
        "3s",
        ip,
    ]

    print(f"{CYAN}========================================{NC}")
    print(f"{YELLOW}[*] Target : {ip}{NC}")
    print(f"{YELLOW}[*] Output : {basename}.nmap / .xml / .gnmap{NC}")
    print(f"{YELLOW}[*] Command: {' '.join(cmd)}{NC}")
    print(f"{YELLOW}[*] Starting nmap scan...{NC}")
    print(f"{CYAN}========================================{NC}")

    rc = run_nmap(live_cmd)
    strip_cpe(basename)

    if rc == 0:
        print_bar(100.0, "completed", final=True)
    else:
        print()

    print(f"{CYAN}========================================{NC}")
    if rc == 0:
        print(f"{GREEN}[+] nmap completed : {ip}{NC}")
    else:
        print(f"{RED}[-] nmap finished with exit code {rc} : {ip}{NC}")
    print(f"{CYAN}========================================{NC}")
    print()
    return rc, Path(str(basename) + ".xml")


def main() -> None:
    print(BANNER)
    if len(sys.argv) < 2:
        usage()

    if shutil.which("nmap") is None:
        print(f"{RED}[-] nmap not found in PATH{NC}")
        sys.exit(1)

    target_file = sys.argv[1]
    targets = load_targets(Path(target_file))

    print(f"{YELLOW}[*] Loaded {len(targets)} target(s){NC}")
    COMMAND_LOG.write_text("", encoding="utf-8")
    SUGGESTED_LOG.write_text("", encoding="utf-8")
    print(f"{YELLOW}[*] Command log : {COMMAND_LOG}{NC}")
    print(f"{YELLOW}[*] Next cmds   : {SUGGESTED_LOG}{NC}")
    print(f"{YELLOW}[*] Report      : {REPORT_FILE}{NC}")
    print()

    hosts: list[HostInfo] = []
    failed = 0
    total = len(targets)

    for i, ip in enumerate(targets, start=1):
        overall = (i - 1) / total * 100
        print(f"{CYAN}[*] Target {i}/{total} ({overall:.0f}% hosts done){NC}")
        rc, xml_path = scan_ip(ip)
        if rc != 0:
            failed += 1
        host = parse_nmap_xml(xml_path, ip)
        hosts.append(host)
        print_host_summary(host)
        grouped = suggest_by_port(host)
        run_selected(grouped)
        write_report(hosts, target_file)
        suggested = suggest_commands(host)
        if suggested:
            with SUGGESTED_LOG.open("a", encoding="utf-8") as f:
                f.write(f"# {host.ip}\n")
                f.write("\n".join(suggested) + "\n\n")
        print(f"{GREEN}[+] report updated : {REPORT_FILE}{NC}")
        print(f"{CYAN}[*] Hosts finished: {i}/{total} ({i / total * 100:.0f}%){NC}")
        print()

    print(f"{GREEN}[+] All scans finished (100%){NC}")
    print(f"{YELLOW}[*] Success: {len(targets) - failed} / Failed: {failed}{NC}")
    print(f"{GREEN}[+] Readable report : {REPORT_FILE.resolve()}{NC}")
    print(f"{GREEN}[+] Raw nmap files  : {OUT_DIR.resolve()}{NC}")


if __name__ == "__main__":
    main()
