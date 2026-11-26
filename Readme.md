# LDAPDomainDump
<img width="350" height="350" alt="image" src="https://github.com/user-attachments/assets/cab2f220-7326-4e19-883f-a4a047c2554a" />

Active Directory information dumper via LDAP. Same arguments and output formats as [adwsdomaindump](https://github.com/mverschu/adwsdomaindump), using LDAP instead of ADWS.

## Install

```sh
pipx install .
# or
pip install -r requirements.txt
```

## Usage

```sh
ldapdomaindump -u 'corp.local\jsmith' -p 'password' -n 10.0.0.1 dc01.corp.local
[*] Connecting to LDAP host...
[+] LDAPS port 636 is reachable
[*] Binding to LDAP host
[*] Trying LDAPS with channel binding (dc01.corp.local:636)
[+] Bind OK (LDAPS with channel binding)
[*] Starting domain dump
[+] Domain dump finished
```

`HOSTNAME` may be a hostname, an IP, or an `ldap://` / `ldaps://` URL. LDAPS on port 636 is always tried first. Authentication is NTLM (password or `LM:NT` hash).

Use `--force` to skip the port connectivity check.

### Connection security

The bind stops at the first method that succeeds. A rejected password is not retried on a weaker channel.

1. LDAPS (636) with TLS channel binding (`tls-server-end-point`)
2. LDAP (389) upgraded with StartTLS, then channel binding
3. LDAP (389) with SASL signing and sealing
4. Plain LDAP (389) when the directory does not support the options above

## Collection

| Data | Default | With `--all` | BloodHound extras |
|------|---------|--------------|-------------------|
| Users, groups, computers | Yes | Yes | `--bloodhound` |
| Domain policy, trusts | Yes | Yes | `--bloodhound` |
| GPOs, OUs, containers | No | Yes | `--bloodhound --all` |
| DACL / object-control edges | No | Yes (with `--bloodhound` and/or `--markdown`) | `--bloodhound` or `--markdown --acl` |
| AD CS (templates, enterprise CAs, …) | No | Yes* | `--bloodhound --all` or `--adcs` |

\* AD CS requires `--bloodhound`. `--all` enables `--adcs` automatically.

## Output formats

| Format | Flag | Use for |
|--------|------|---------|
| **HTML** | default | Browse users, groups, computers, policy, trusts in a browser |
| **JSON** | default | Scripting and automation on raw AD attributes |
| **Greppable** | default | `grep` / `cut` pipelines (`-d` sets delimiter) |
| **Markdown** | `--markdown` | Notes or docs from the same data as HTML |
| **Markdown ACLs** | `--markdown --all` | Human-readable DACL / ACE tables (`domain_*_aces.md`) |
| **BloodHound** | `--bloodhound` | Import into BloodHound CE (`bloodhound_<domain>.zip`) |

Disable defaults with `--no-html`, `--no-json`, or `--no-grep`.

```sh
ldapdomaindump -u 'corp.local\Administrator' -p 'password' dc01.corp.local \
  --all --bloodhound -o ./out
```

## Full OS build numbers (`--full-build`)

Active Directory stores only the major build in `operatingSystemVersion` (for example `10.0 (14393)`). `--full-build` reads the full cumulative-update build (for example `14393.8246`) from the remote registry over SMB. Any authenticated domain user can read it. The value is included in HTML, JSON, greppable, and Markdown output, and omitted from the BloodHound export.

## Credits

Output and arguments follow [adwsdomaindump](https://github.com/mverschu/adwsdomaindump), which is an adaptation of [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) by Dirk-jan Mollema.

Original work: Copyright (c) 2017 Dirk-jan Mollema

## License

MIT
