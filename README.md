# SH-!T
Python wrapper that runs a full TCP nmap scan, hides the raw output, and turns the result into a readable summary plus suggested follow-up commands.

`v0.1` by roy

Authorized testing only. Scan hosts you own or have written permission to test.

## What it does

For each IP in a target file it:

1. Runs `nmap -sCV -p- -oA nmap/<ip> <ip>`
2. Shows a one-line progress bar instead of raw nmap output
3. Strips `cpe:/` entries from the `.xml` and `.nmap` files
4. Prints open ports, service versions, and highlighted script output
5. Suggests next commands by port (web, SMB, LDAP, DNS, and others)
6. Lets you run those commands from a menu, then keeps the menu open until you quit
7. Writes a Markdown report after every host

Domain names used in LDAP, DNS, and Kerberos commands are pulled from nmap hostnames and script output (`DNS_Domain_Name`, `Domain name`, and similar). If nothing is found, the placeholder is `domain.local`.

## Requirements

- Python 3.10+
- `nmap` on `PATH`

Suggested commands call other tools only if you choose to run them. Install what you actually use:

- `nxc` (NetExec)
- `gobuster`, `feroxbuster`, `nikto`, `whatweb`
- Impacket (`impacket-GetNPUsers`, `impacket-rpcdump`, `impacket-lookupsid`)
- `ldapsearch`, `ldapdomaindump`, `dig`, `snmpwalk`, `smbclient`

Wordlists referenced by the web templates:

- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

## Usage

```bash
python3 auto_enum.py targets.txt
