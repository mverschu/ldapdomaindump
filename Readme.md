# LDAPDomainDump
Active Directory information dumper via LDAP **with Channel Binding / Kerberos support!**

## Help menu

```shell
usage: ldapdomaindump.py [-h] [-u USERNAME] [-p PASSWORD] [-at {NTLM,SIMPLE}] [--user-dn USER_DN] [-o DIRECTORY] [--no-html] [--no-json] [--no-grep] [--grouped-json] [-d DELIMITER] [-r]
                         [-n DNS_SERVER] [-m]
                         HOSTNAME

Domain information dumper via LDAP. Dumps users/computers/groups and OS/membership information to HTML/JSON/greppable output.

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to connect to (use ldaps:// to use SSL)

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username for authentication, leave empty for anonymous authentication
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified
  -at {NTLM,SIMPLE}, --authtype {NTLM,SIMPLE}
                        Authentication type (NTLM or SIMPLE, default: NTLM)
  --user-dn USER_DN     Distinguished Name (DN) of the user for authentication

Output options:
  -o DIRECTORY, --outdir DIRECTORY
                        Directory in which the dump will be saved (default: current)
  --no-html             Disable HTML output
  --no-json             Disable JSON output
  --no-grep             Disable Greppable output
  --grouped-json        Also write json files for grouped files (default: disabled)
  -d DELIMITER, --delimiter DELIMITER
                        Field delimiter for greppable output (default: tab)

Misc options:
  -r, --resolve         Resolve computer hostnames (might take a while and cause high traffic on large networks)
  -n DNS_SERVER, --dns-server DNS_SERVER
                        Use custom DNS resolver instead of system DNS (try a domain controller IP)
  -m, --minimal         Only query minimal set of attributes to limit memmory usage
```

## How to use

```shell
python3 ldapdomaindump.py --user-dn "CN=BEAR,OU=USERS,DC=DOMAIN,DC=LOCAL" -p 'mysupersecurepassword' ldaps://dc1.domain.local
can be ignored ----- > [*] Connecting as anonymous user, dumping will probably fail. Consider specifying a username/password to login with <----- can be ignored
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
