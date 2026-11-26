"""
LDAP connection layer with the same entry/search surface as the ADWS dumper.

Security order, strongest first, stopping on a bad password so credentials are
not retried over a weaker channel:

1. LDAPS (636) with TLS channel binding (tls-server-end-point)
2. LDAP (389) upgraded with StartTLS, then channel binding
3. LDAP (389) with SASL signing and sealing
4. Plain LDAP (389) when the directory does not support the options above
"""
import logging
import re
from typing import Any, List, Optional
from uuid import UUID

logger = logging.getLogger(__name__)

CORE_OBJECT_ATTRIBUTES = [
    'cn', 'name', 'sAMAccountName', 'distinguishedName', 'objectClass',
    'objectSid', 'objectGUID', 'memberOf', 'primaryGroupId', 'userAccountControl',
    'whenCreated', 'whenChanged', 'lastLogon', 'pwdLastSet', 'description',
    'servicePrincipalName', 'operatingSystem', 'operatingSystemServicePack',
    'operatingSystemVersion', 'dNSHostName', 'member',
]

DOMAIN_POLICY_ATTRIBUTES = CORE_OBJECT_ATTRIBUTES + [
    'lockOutObservationWindow', 'lockoutDuration', 'lockoutThreshold',
    'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties',
    'msDS-Behavior-Version', 'gPLink',
]

TRUST_OBJECT_ATTRIBUTES = [
    'cn', 'name', 'distinguishedName', 'objectClass', 'objectSid', 'objectGUID',
    'flatName', 'securityIdentifier', 'trustAttributes', 'trustDirection', 'trustType',
    'whenCreated', 'whenChanged',
]

DEFAULT_ATTRIBUTES = list(CORE_OBJECT_ATTRIBUTES)

# Synthetic or names the dumper never requests. Kept so attribute sets match.
LDAP_UNSUPPORTED_ATTRIBUTES = frozenset({
    'msDS-MachineAccountQuota',
    'ms-DS-MachineAccountQuota',
    'operatingSystemBuildNumber',
})

LDAP_ATTRIBUTE_ALIASES = {
    'ms-DS-Behavior-Version': 'msDS-Behavior-Version',
}

# LDAP syntaxes that are not UTF-8 text. objectGUID is formatted to a string later.
BINARY_ATTRIBUTES = frozenset({
    'objectsid',
    'objectguid',
    'ntsecuritydescriptor',
    'sidhistory',
    'securityidentifier',
    'cacertificate',
    'usercertificate',
    'msds-allowedtoactonbehalfofotheridentity',
    'msds-groupmsamembership',
    'pkiexpirationperiod',
    'pkioverlapperiod',
    'thumbnailphoto',
    'jpegphoto',
    'logonhours',
    'msexchmailboxsecuritydescriptor',
    'msds-generationid',
    'repluptodatevector',
    'dnsrecord',
    'trustauthincoming',
    'trustauthoutgoing',
})

SD_ATTRIBUTES = frozenset({
    'ntsecuritydescriptor',
    'msds-groupmsamembership',
})

_RANGE_RE = re.compile(
    r'^(?P<attr>.+);range=(?P<low>\d+)-(?P<high>\*|\d+)$',
    re.IGNORECASE,
)

# Directory replies that mean the password/account was rejected. Do not fall back.
_CREDENTIAL_MARKERS = (
    'data 525',   # user not found
    'data 52e',   # wrong password
    'data 530',   # not permitted at this time
    'data 531',   # not permitted at this workstation
    'data 532',   # password expired
    'data 533',   # account disabled
    'data 701',   # account expired
    'data 773',   # must change password
    'data 775',   # locked
    '8009030c',   # SEC_E_LOGON_DENIED
)

# Policy or transport failures where a different LDAP protection may still work.
_POLICY_MARKERS = (
    '80090346',  # SEC_E_BAD_BINDINGS (channel binding)
    'strongerauthrequired',
    'confidentialityrequired',
    'unwillingtoperform',
    'authmethodnotsupported',
    'inappropriateauthentication',
    'channel binding',
    'signing required',
    'integrity',
)


def normalize_ldap_attributes(attributes):
    if not attributes:
        return attributes
    normalized = [LDAP_ATTRIBUTE_ALIASES.get(attr, attr) for attr in attributes]
    return [attr for attr in normalized if attr not in LDAP_UNSUPPORTED_ATTRIBUTES]


def resolve_ldap_attributes(attributes):
    """
    Expand a lone ``*`` to the default attribute set before the LDAP search.

    A real LDAP ``*`` also returns every user attribute, including large ones
    the reports never print. The dumper's wildcard means the same default set
    used by the ADWS tool, plus any extra names merged into the list.
    """
    if attributes is None:
        return list(DEFAULT_ATTRIBUTES)
    resolved = []
    if '*' in attributes:
        resolved.extend(DEFAULT_ATTRIBUTES)
    for attr in attributes:
        if attr == '*':
            continue
        if attr not in resolved:
            resolved.append(attr)
    if not resolved:
        resolved = list(DEFAULT_ATTRIBUTES)
    return normalize_ldap_attributes(resolved)


def parse_ldap_target(host):
    """
    Split a host, ``ldap://`` URL, or ``ldaps://`` URL into bare host, scheme, port.

    Returns ``(host, scheme, port)`` where scheme is ``'ldap'``, ``'ldaps'``, or None
    and port is an int or None.
    """
    text = (host or '').strip()
    scheme = None
    lower = text.lower()
    if lower.startswith('ldaps://'):
        scheme = 'ldaps'
        text = text[8:]
    elif lower.startswith('ldap://'):
        scheme = 'ldap'
        text = text[7:]
    text = text.split('/')[0]
    port = None
    if text.startswith('['):
        end = text.find(']')
        if end != -1:
            rest = text[end + 1:]
            text = text[:end + 1]
            if rest.startswith(':') and rest[1:].isdigit():
                port = int(rest[1:])
    elif text.count(':') == 1:
        bare, port_text = text.rsplit(':', 1)
        if port_text.isdigit():
            port = int(port_text)
            text = bare
    if scheme is None and port == 636:
        scheme = 'ldaps'
    elif scheme is None and port == 389:
        scheme = 'ldap'
    return text, scheme, port


_SID_FILTER_RE = re.compile(
    r'(?P<attr>objectSid|securityIdentifier)\s*=\s*(?P<sid>S-1-(?:\d+-)+\d+)',
    re.IGNORECASE,
)


def security_attempts(scheme=None, port=None):
    """
    Connection attempts, strongest first.

    ``scheme`` and ``port`` come from the host URL. The client speaks 636 and 389
    only, and always tries LDAPS with channel binding before any weaker option.
    """
    del scheme, port
    attempts = []
    seen = set()

    def add(use_ssl, attempt_port, signing, start_tls, label):
        key = (use_ssl, attempt_port, signing, start_tls)
        if key in seen:
            return
        seen.add(key)
        attempts.append({
            'use_ssl': use_ssl,
            'port': attempt_port,
            'signing': signing,
            'start_tls': start_tls,
            'label': label,
        })

    add(True, 636, False, False, 'LDAPS with channel binding')
    add(False, 389, False, True, 'StartTLS with channel binding')
    add(False, 389, True, False, 'LDAP with signing')
    add(False, 389, False, False, 'LDAP (no signing)')
    return attempts


def canonical_sid_bytes(sid):
    """Pack an ``S-1-...`` SID into the binary form LDAP filters require."""
    parts = (sid or '').split('-')
    if len(parts) < 3 or parts[0].upper() != 'S':
        return None
    try:
        revision = int(parts[1])
        authority = int(parts[2])
        subauths = [int(part) for part in parts[3:]]
    except ValueError:
        return None
    if revision > 255 or not 0 <= authority < 2 ** 48 or len(subauths) > 255:
        return None
    if any(sub < 0 or sub > 0xFFFFFFFF for sub in subauths):
        return None
    packed = bytes([revision, len(subauths)]) + authority.to_bytes(6, 'big')
    for sub in subauths:
        packed += sub.to_bytes(4, 'little')
    return packed


def rewrite_string_sid_filters(search_filter):
    """
    Turn ``(objectSid=S-1-5-...)`` into the escaped binary form LDAP expects.

    The dump queries use the same string SID filters as the ADWS tool. Active
    Directory LDAP matches ``objectSid`` against the binary value.
    """
    if not search_filter or 'S-1-' not in search_filter and 's-1-' not in search_filter:
        return search_filter

    def repl(match):
        raw = canonical_sid_bytes(match.group('sid'))
        if raw is None:
            return match.group(0)
        escaped = ''.join('\\%02x' % byte for byte in raw)
        return '%s=%s' % (match.group('attr'), escaped)

    return _SID_FILTER_RE.sub(repl, search_filter)


def ldap_octets(raw):
    """Bytes payload of one LDAP attribute value, including pyasn1 octet strings."""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if hasattr(raw, 'asOctets'):
        return raw.asOctets()
    return bytes(raw)


def is_credential_rejection(exc):
    """True when the directory rejected the account itself, not the LDAP protection."""
    text = str(exc).lower()
    if any(marker in text for marker in _POLICY_MARKERS):
        return False
    if any(marker in text for marker in _CREDENTIAL_MARKERS):
        return True
    if 'invalidcredentials' in text:
        return True
    return False


def decode_ldap_value(attr_name, raw):
    """Turn one LDAP octet string into the value the report code expects."""
    raw = ldap_octets(raw)
    name = (attr_name or '').split(';')[0].lower()
    if name == 'objectguid' and len(raw) == 16:
        return str(UUID(bytes_le=bytes(raw))).upper()
    if name in BINARY_ATTRIBUTES:
        return bytes(raw)
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return bytes(raw)


def split_credentials(user, password, default_domain):
    """Return ``(username, domain, password, lm_hash, nt_hash)``."""
    domain = default_domain or ''
    username = user or ''
    if '\\' in username:
        domain, username = username.split('\\', 1)
    elif '@' in username:
        username, domain = username.rsplit('@', 1)

    lm_hash = ''
    nt_hash = ''
    secret = password or ''
    if secret.count(':') == 1:
        left, right = secret.split(':', 1)
        hexdigits = '0123456789abcdefABCDEF'
        if len(right) == 32 and len(left) in (0, 32) and all(c in hexdigits for c in left + right):
            lm_hash, nt_hash = left, right
            secret = ''
    return username, domain, secret, lm_hash, nt_hash


class LDAPAttribute:
    """Mimics ldap3's Attribute (and the ADWS attribute wrapper)."""

    def __init__(self, key, value):
        self.key = key
        self._value = value
        self._raw_values = [value] if not isinstance(value, list) else value

    @property
    def value(self):
        if isinstance(self._value, list):
            return self._value[0] if self._value else None
        return self._value

    @property
    def values(self):
        if isinstance(self._value, list):
            return self._value
        return [self._value]

    @property
    def raw_values(self):
        return self._raw_values


class LDAPEntry:
    """Mimics ldap3's Entry using a plain attribute dictionary."""

    def __init__(self, attributes):
        self._attributes = attributes

    def __getitem__(self, key):
        if key in self._attributes:
            return self._attributes[key]
        raise KeyError("Attribute '%s' not found" % key)

    def __contains__(self, key):
        return key in self._attributes

    def get(self, key, default=None):
        return self._attributes.get(key, default)

    def entry_to_json(self):
        import json
        import base64
        result = {}
        for key, attr in self._attributes.items():
            if isinstance(attr, LDAPAttribute):
                value = attr.value
                if isinstance(value, bytes):
                    result[key] = base64.b64encode(value).decode('ascii')
                else:
                    result[key] = value
            else:
                result[key] = attr
        return json.dumps(result)


class LDAPServerInfo:
    def __init__(self, domain):
        self.other = {
            'defaultNamingContext': ["DC=%s" % ',DC='.join((domain or '').split('.'))],
        }


class LDAPServer:
    def __init__(self, host, domain, scheme=None, port=None):
        bare, parsed_scheme, parsed_port = parse_ldap_target(host)
        self.host = bare
        self.domain = domain
        self.scheme = scheme if scheme is not None else parsed_scheme
        self.port = port if port is not None else parsed_port
        self.info = LDAPServerInfo(domain)

    def __repr__(self):
        return 'LDAPServer(host=%s, domain=%s)' % (self.host, self.domain)


def _default_log(level, message):
    prefix = {'info': '[*]', 'warn': '[!]', 'success': '[+]'}.get(level, '[*]')
    print('%s %s' % (prefix, message))


class LDAPConnection:
    """ldap3-shaped connection that binds through impacket's LDAP client."""

    def __init__(self, server: LDAPServer, user: Optional[str] = None,
                 password: Optional[str] = None, authentication: Any = None,
                 log=None):
        self.server = server
        self.user = user
        self.password = password
        self.authentication = authentication
        self.entries = []
        self._ldap = None
        self._bound = False
        self.result = None
        self.security_label = None
        self._log = log or _default_log

    def bind(self) -> bool:
        username, domain, password, lm_hash, nt_hash = split_credentials(
            self.user, self.password, self.server.domain
        )
        if not username:
            self.result = {'description': 'Username is required'}
            return False

        if self.server.port and self.server.port not in (389, 636):
            self._log('warn', 'Port %s is not used; trying LDAPS 636, then LDAP 389' % self.server.port)
        attempts = security_attempts(self.server.scheme, self.server.port)
        errors = []
        for attempt in attempts:
            label = attempt['label']
            target = '%s:%s' % (self.server.host, attempt['port'])
            self._log('info', 'Trying %s (%s)' % (label, target))
            try:
                ldap = self._open_attempt(attempt, username, password, domain, lm_hash, nt_hash)
            except _CredentialRejected as exc:
                self._close_quiet(getattr(exc, 'connection', None))
                self.result = {'description': str(exc)}
                self._log('warn', 'Authentication rejected: %s' % exc)
                return False
            except Exception as exc:
                errors.append('%s: %s' % (label, exc))
                logger.debug('LDAP attempt %s failed', label, exc_info=True)
                self._log('warn', '%s failed: %s' % (label, exc))
                continue

            self._ldap = ldap
            self._bound = True
            self.security_label = self._effective_label(ldap, attempt)
            self.server.security = self.security_label
            try:
                self._load_rootdse()
            except Exception as exc:
                logger.debug('RootDSE query failed', exc_info=True)
                self._log('warn', 'RootDSE query failed: %s' % exc)
            return True

        self.result = {'description': '; '.join(errors) if errors else 'LDAP bind failed'}
        return False

    def _effective_label(self, ldap, attempt):
        label = attempt['label']
        if attempt['use_ssl'] or attempt['start_tls']:
            if not getattr(ldap, 'channel_binding_value', None):
                label = label.replace(' with channel binding', '')
                self._log('warn', 'TLS is up but channel binding was not negotiated')
        return label

    def _open_attempt(self, attempt, username, password, domain, lm_hash, nt_hash):
        try:
            from impacket.ldap.ldap import LDAPConnection, LDAPSessionError
        except ImportError as exc:
            raise RuntimeError(
                'LDAP support requires impacket (pip install impacket). %s' % exc
            ) from exc

        scheme = 'ldaps' if attempt['use_ssl'] else 'ldap'
        # impacket selects 389/636 from the URL scheme and does not parse :port.
        if attempt['port'] not in (389, 636):
            raise RuntimeError('TCP port %s is not supported by the LDAP client' % attempt['port'])
        url = '%s://%s' % (scheme, self.server.host)
        if attempt['start_tls']:
            probe = self._impacket_connect(LDAPConnection, url, signing=False)
            if not hasattr(probe, 'startTLS'):
                self._close_quiet(probe)
                raise RuntimeError('this impacket build has no StartTLS support')
        else:
            probe = None

        conn = None
        try:
            conn = probe or self._impacket_connect(
                LDAPConnection, url, signing=bool(attempt['signing'])
            )
            if attempt['start_tls']:
                conn.startTLS()
            try:
                conn.login(
                    username,
                    password,
                    domain,
                    lm_hash,
                    nt_hash,
                    authenticationChoice='sasl',
                )
            except LDAPSessionError as exc:
                if is_credential_rejection(exc):
                    rejected = _CredentialRejected(str(exc))
                    rejected.connection = conn
                    conn = None
                    raise rejected
                raise
            return conn
        except _CredentialRejected:
            raise
        except Exception:
            self._close_quiet(conn)
            raise

    def _impacket_connect(self, ldap_cls, url, signing):
        try:
            return ldap_cls(url, signing=signing, timeout=15)
        except TypeError:
            return ldap_cls(url, signing=signing)

    def _close_quiet(self, conn):
        if conn is None:
            return
        try:
            conn.close()
        except Exception:
            pass

    def _load_rootdse(self):
        from impacket.ldap.ldapasn1 import Scope
        answers = self._ldap.search(
            searchBase='',
            scope=Scope('baseObject'),
            searchFilter='(objectClass=*)',
            attributes=[
                'defaultNamingContext',
                'namingContexts',
                'configurationNamingContext',
                'schemaNamingContext',
                'rootDomainNamingContext',
                'dnsHostName',
            ],
        )
        values = {}
        for item in answers:
            parsed = self._parse_raw_attributes(item)
            for name, raw_values in parsed.items():
                values[name] = [decode_ldap_value(name, raw) for raw in raw_values]
        if not values:
            return

        def texts(name):
            raw = values.get(name) or []
            if not isinstance(raw, list):
                raw = [raw]
            return [str(item) for item in raw if item]

        default_nc = texts('defaultNamingContext')
        if default_nc:
            self.server.info.other['defaultNamingContext'] = default_nc
        naming = texts('namingContexts')
        if naming:
            self.server.info.other['namingContexts'] = naming
        for key in ('configurationNamingContext', 'schemaNamingContext', 'rootDomainNamingContext', 'dnsHostName'):
            found = texts(key)
            if found:
                self.server.info.other[key] = found

    def search(self, search_base: str, search_filter: str, attributes: List[str] = None, scope=None):
        if not self._bound:
            raise RuntimeError('Not bound to LDAP server')
        search_filter = rewrite_string_sid_filters(search_filter)
        attributes = list(resolve_ldap_attributes(attributes))
        for extra in ('distinguishedName', 'objectClass'):
            if extra not in attributes:
                attributes.append(extra)
        try:
            raw_items = self._paged_search(search_base, search_filter, attributes, scope=scope)
            self.entries = []
            for item in raw_items:
                entry = self._entry_from_item(item, attributes)
                if entry is not None:
                    self.entries.append(entry)
        except Exception as exc:
            logger.error('LDAP search failed: %s', exc)
            self.entries = []

    def _paged_search(self, search_base, search_filter, attributes, scope=None, paged_size=500):
        from impacket.ldap import ldapasn1
        controls = [ldapasn1.SimplePagedResultsControl(size=paged_size)]
        if any(attr.lower() in SD_ATTRIBUTES for attr in attributes):
            sd_control = getattr(ldapasn1, 'SDFlagsControl', None)
            if sd_control is not None:
                # Owner, group, and DACL. Matches the flags the ADWS pull uses.
                controls.append(sd_control(flags=0x07))
        kwargs = {
            'searchFilter': search_filter,
            'attributes': attributes,
            'searchControls': controls,
        }
        if search_base is not None:
            kwargs['searchBase'] = search_base
        if scope is not None:
            kwargs['scope'] = scope
        answers = self._ldap.search(**kwargs)
        entries = []
        for item in answers:
            if self._is_search_entry(item):
                entries.append(item)
        return entries

    def _is_search_entry(self, item):
        try:
            item['objectName']
            item['attributes']
            return True
        except Exception:
            return False

    def _parse_raw_attributes(self, item):
        parsed = {}
        try:
            attributes = item['attributes']
        except Exception:
            return parsed
        for attribute in attributes:
            try:
                name = str(attribute['type'])
            except Exception:
                continue
            values = []
            try:
                raw_vals = attribute['vals']
            except Exception:
                raw_vals = []
            for raw in raw_vals:
                if raw is None:
                    continue
                blob = ldap_octets(raw)
                if blob == b'':
                    continue
                values.append(blob)
            if values:
                parsed[name] = values
        return parsed

    def _expand_ranges(self, dn, parsed):
        """Follow member;range=0-1499 style results until the attribute is complete."""
        guard = 0
        while guard < 100:
            guard += 1
            ranged_name = None
            match = None
            for name in list(parsed):
                found = _RANGE_RE.match(name)
                if found and found.group('high') != '*':
                    ranged_name = name
                    match = found
                    break
            if match is None:
                break
            base = match.group('attr')
            start = int(match.group('high')) + 1
            existing = parsed.pop(ranged_name)
            parsed.setdefault(base, [])
            parsed[base].extend(existing)
            next_attr = '%s;range=%d-*' % (base, start)
            try:
                from impacket.ldap.ldapasn1 import Scope
                answers = self._ldap.search(
                    searchBase=dn,
                    scope=Scope('baseObject'),
                    searchFilter='(objectClass=*)',
                    attributes=[next_attr],
                )
            except Exception:
                logger.debug('Range retrieval failed for %s on %s', next_attr, dn, exc_info=True)
                break
            continued = False
            for item in answers:
                if not self._is_search_entry(item):
                    continue
                for name, values in self._parse_raw_attributes(item).items():
                    found = _RANGE_RE.match(name)
                    if not found or found.group('attr').lower() != base.lower():
                        continue
                    if found.group('high') == '*':
                        parsed[base].extend(values)
                    else:
                        parsed['%s;range=%s-%s' % (base, found.group('low'), found.group('high'))] = values
                        continued = True
            if not continued:
                break
        for name in list(parsed):
            found = _RANGE_RE.match(name)
            if not found:
                continue
            base = found.group('attr')
            parsed.setdefault(base, [])
            parsed[base].extend(parsed.pop(name))
        return parsed

    def _entry_from_item(self, item, requested):
        try:
            dn = str(item['objectName'])
        except Exception:
            return None
        parsed = self._expand_ranges(dn, self._parse_raw_attributes(item))
        if 'distinguishedName' not in parsed and dn:
            parsed['distinguishedName'] = [dn.encode('utf-8')]

        requested_by_lower = {name.lower(): name for name in requested}
        attributes = {}
        for name, raw_values in parsed.items():
            canonical = requested_by_lower.get(name.lower(), name.split(';')[0])
            decoded = [decode_ldap_value(canonical, raw) for raw in raw_values]
            if not decoded:
                continue
            stored = decoded[0] if len(decoded) == 1 else decoded
            attributes[canonical] = LDAPAttribute(canonical, stored)
        if 'distinguishedName' not in attributes and dn:
            attributes['distinguishedName'] = LDAPAttribute('distinguishedName', dn)
        if not attributes:
            return None
        return LDAPEntry(attributes)

    class ExtendStandard:
        def __init__(self, connection):
            self._connection = connection

        def paged_search(self, search_base, search_filter, attributes=None,
                         paged_size=500, generator=False):
            self._connection.search(search_base, search_filter, attributes)
            if generator:
                return iter(self._connection.entries)
            return self._connection.entries

    class Extend:
        def __init__(self, connection):
            self._connection = connection

        @property
        def standard(self):
            return LDAPConnection.ExtendStandard(self._connection)

    @property
    def extend(self):
        return LDAPConnection.Extend(self)


class _CredentialRejected(Exception):
    pass
