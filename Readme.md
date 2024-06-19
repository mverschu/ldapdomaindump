# LDAPDomainDump
Active Directory information dumper via LDAP **with Channel Binding support!**

## Help menu

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
