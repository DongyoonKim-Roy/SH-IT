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


## TODO

Checked items are done in v0.1.

### Done

- [x] Read targets from a text file
- [x] Run `nmap -sCV -p- -oA`
- [x] Log the nmap command to `command.txt`
- [x] Hide raw nmap output and show a one-line progress bar
- [x] Write `report.md` with a per-host summary and next commands
- [x] Strip `cpe:/` from `.xml` and `.nmap`
- [x] Suggest follow-up commands by open port
- [x] Interactive menu that stays open until `n`
- [x] Pull domain / hostname into command templates
- [x] Startup banner

### Next

- [ ] Add a `.gitignore` for `nmap/`, `command.txt`, `next_commands.txt`, `report.md`
- [ ] Add `--no-menu` so a scan can finish without prompts
- [ ] Add `--skip-existing` so a rerun does not rescan hosts that already have XML
- [ ] Move command templates out of the script into `templates.yaml` (or `.txt`) so they can be edited without touching code
- [ ] Make the wordlist path a flag, not a hardcoded Kali path
- [ ] Accept hostnames and CIDR in `targets.txt`, not only single IPs
- [ ] Add a timeout and a clear message when nmap is still on the first host with no stats yet
- [ ] Stop using `shell=True` for follow-up commands
- [ ] Confirm before `a` (run all), since some groups fire several loud tools
- [ ] Add a sample `nmap/*.xml` fixture and a parser test that does not need a live host
- [ ] Note the scan start time and elapsed time in `report.md`

### Later

- [ ] Optional UDP top-ports pass (`-sU --top-ports 20`) behind a flag
- [ ] Optional `-O` OS detection behind a flag (needs root)
- [ ] HTML report next to `report.md`
- [ ] Per-port notes field so a manual finding can be appended to the report
- [ ] Color off when stdout is not a TTY
