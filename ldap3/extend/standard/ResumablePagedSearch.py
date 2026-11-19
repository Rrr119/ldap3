"""
"""

import base64
import hashlib
import json
import os
import tempfile
from time import sleep

from ... import SUBTREE, DEREF_ALWAYS
from ...core.exceptions import LDAPCommunicationError, LDAPPagedSearchCursorError, \
    LDAPPagedSearchCursorMismatchError, LDAPPagedSearchResumeError, LDAPOperationResult
from ...utils.dn import safe_dn
from ...utils.log import log, log_enabled, BASIC, PROTOCOL


PAGED_SEARCH_CONTROL_OID = '1.2.840.113556.1.4.319'
PAGED_SEARCH_CURSOR_VERSION = 1


def _normalize_attributes(attributes):
    if attributes is None:
        return None
    if isinstance(attributes, str):
        attributes = [attributes]
    return sorted(set(str(attribute).lower() for attribute in attributes))


def _normalize_controls(controls):
    normalized = []
    for control in controls or []:
        try:
            oid = str(control[0])
            criticality = bool(control[1]) if len(control) > 1 else False
            value = repr(control[2]) if len(control) > 2 else None
        except (TypeError, IndexError):
            oid = str(control)
            criticality = False
            value = None
        normalized.append((oid, criticality, value))
    return sorted(normalized)


def _encode_cookie(cookie):
    if cookie is None:
        return None
    if isinstance(cookie, str):
        cookie = cookie.encode('utf-8')
    return base64.b64encode(bytes(cookie)).decode('ascii')


def _decode_cookie(cookie):
    if cookie is None:
        return None
    return base64.b64decode(cookie.encode('ascii'))


def _as_bytes_cookie(cookie):
    if cookie is None:
        return None
    if isinstance(cookie, str):
        return cookie.encode('utf-8')
    return bytes(cookie)


class PagedSearchCursor(object):
    """
    Persistent position of one RFC 2696 paged search.

    The cookie, not a page number, is the continuation token. A cursor is
    only advanced after a complete page has been received. Persist it with
    save() or on_cursor and resume with the same cursor after a reconnect.
    """

    def __init__(self,
                 search_base='',
                 search_filter='(objectClass=*)',
                 search_scope=SUBTREE,
                 dereference_aliases=DEREF_ALWAYS,
                 attributes=None,
                 size_limit=0,
                 time_limit=0,
                 types_only=False,
                 get_operational_attributes=False,
                 controls=None,
                 paged_size=100,
                 paged_criticality=False):
        self.search_base = safe_dn(search_base) if search_base else search_base
        self.search_filter = search_filter
        self.search_scope = search_scope
        self.dereference_aliases = dereference_aliases
        if attributes is None:
            self.attributes = None
        elif isinstance(attributes, str):
            self.attributes = [attributes]
        else:
            self.attributes = list(attributes)
        self.size_limit = size_limit
        self.time_limit = time_limit
        self.types_only = types_only
        self.get_operational_attributes = get_operational_attributes
        self.controls = _normalize_controls(controls)
        self.paged_size = paged_size
        self.paged_criticality = paged_criticality

        self.cookie = None
        self.pages = 0
        self.entries = 0
        self.completed = False
        self.fingerprint = self._calculate_fingerprint()

    def __repr__(self):
        return 'PagedSearchCursor(base={0.search_base!r}, filter={0.search_filter!r}, pages={0.pages}, ' \
               'entries={0.entries}, completed={0.completed!r})'.format(self)

    @property
    def has_more(self):
        return not self.completed

    def _calculate_fingerprint(self):
        definition = {
            'base': self.search_base,
            'filter': self.search_filter,
            'scope': self.search_scope,
            'dereference_aliases': self.dereference_aliases,
            'attributes': _normalize_attributes(self.attributes),
            'size_limit': self.size_limit,
            'time_limit': self.time_limit,
            'types_only': self.types_only,
            'get_operational_attributes': self.get_operational_attributes,
            'controls': self.controls,
            'paged_size': self.paged_size,
            'paged_criticality': self.paged_criticality
        }
        payload = json.dumps(definition, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(payload).hexdigest()

    def matches(self, cursor_definition):
        if self.fingerprint != cursor_definition._calculate_fingerprint():
            raise LDAPPagedSearchCursorMismatchError(
                'the cursor belongs to a different search definition')
        return True

    def to_dict(self):
        return {
            'version': PAGED_SEARCH_CURSOR_VERSION,
            'fingerprint': self.fingerprint,
            'cookie': _encode_cookie(self.cookie),
            'pages': self.pages,
            'entries': self.entries,
            'completed': self.completed,
            'search': {
                'base': self.search_base,
                'filter': self.search_filter,
                'scope': self.search_scope,
                'dereference_aliases': self.dereference_aliases,
                'attributes': self.attributes,
                'size_limit': self.size_limit,
                'time_limit': self.time_limit,
                'types_only': self.types_only,
                'get_operational_attributes': self.get_operational_attributes,
                'controls': self.controls,
                'paged_size': self.paged_size,
                'paged_criticality': self.paged_criticality
            }
        }

    @classmethod
    def from_dict(cls, data):
        version = data.get('version', PAGED_SEARCH_CURSOR_VERSION)
        if version != PAGED_SEARCH_CURSOR_VERSION:
            raise LDAPPagedSearchCursorError('unsupported paged search cursor version: ' + str(version))
        search = data.get('search', {})
        cursor = cls(search_base=search.get('base', ''),
                     search_filter=search.get('filter', '(objectClass=*)'),
                     search_scope=search.get('scope', SUBTREE),
                     dereference_aliases=search.get('dereference_aliases', DEREF_ALWAYS),
                     attributes=search.get('attributes'),
                     size_limit=search.get('size_limit', 0),
                     time_limit=search.get('time_limit', 0),
                     types_only=search.get('types_only', False),
                     get_operational_attributes=search.get('get_operational_attributes', False),
                     controls=search.get('controls'),
                     paged_size=search.get('paged_size', 100),
                     paged_criticality=search.get('paged_criticality', False))
        fingerprint = data.get('fingerprint')
        if fingerprint and fingerprint != cursor.fingerprint:
            raise LDAPPagedSearchCursorMismatchError('cursor fingerprint does not match its search definition')
        cursor.cookie = _decode_cookie(data.get('cookie'))
        cursor.pages = int(data.get('pages', 0))
        cursor.entries = int(data.get('entries', 0))
        cursor.completed = bool(data.get('completed', False)) or cursor.cookie == b''
        return cursor

    def copy(self):
        return self.from_dict(self.to_dict())

    def save(self, filename):
        """Atomically persist the cursor as JSON."""
        directory = os.path.dirname(os.path.abspath(filename))
        descriptor, temporary_filename = tempfile.mkstemp(prefix='.ldap3-cursor-', dir=directory)
        try:
            with os.fdopen(descriptor, 'w') as target:
                json.dump(self.to_dict(), target, sort_keys=True)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary_filename, filename)
        except Exception:
            try:
                os.unlink(temporary_filename)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, filename):
        with open(filename, 'r') as source:
            return cls.from_dict(json.load(source))


class PagedSearchCursorIterator(object):
    """Iterator exposing the live cursor used to continue a paged search."""

    def __init__(self, generator, cursor):
        self._generator = generator
        self.cursor = cursor

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._generator)

    def next(self):
        return self.__next__()

    def close(self):
        if self._generator is not None:
            self._generator.close()
            self._generator = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def _build_cursor(cursor,
                  search_base,
                  search_filter,
                  search_scope,
                  dereference_aliases,
                  attributes,
                  size_limit,
                  time_limit,
                  types_only,
                  get_operational_attributes,
                  controls,
                  paged_size,
                  paged_criticality):
    definition = PagedSearchCursor(search_base=search_base,
                                   search_filter=search_filter,
                                   search_scope=search_scope,
                                   dereference_aliases=dereference_aliases,
                                   attributes=attributes,
                                   size_limit=size_limit,
                                   time_limit=time_limit,
                                   types_only=types_only,
                                   get_operational_attributes=get_operational_attributes,
                                   controls=controls,
                                   paged_size=paged_size,
                                   paged_criticality=paged_criticality)
    if cursor is None:
        return definition
    if isinstance(cursor, dict):
        cursor = PagedSearchCursor.from_dict(cursor)
    if not isinstance(cursor, PagedSearchCursor):
        raise LDAPPagedSearchCursorError('cursor must be a PagedSearchCursor or a dictionary')
    cursor.matches(definition)
    return cursor


def _reconnect_connection(connection):
    try:
        if not connection.closed:
            try:
                connection.unbind()
            except (LDAPCommunicationError, OSError):
                pass
        connection.open(read_server_info=False)
        if not connection.bound and not connection.bind(read_server_info=False):
            raise LDAPCommunicationError('unable to bind the reconnected LDAP connection')
        return True
    except (LDAPCommunicationError, OSError):
        return False


def _execute_page(connection,
                  search_base,
                  search_filter,
                  search_scope,
                  dereference_aliases,
                  attributes,
                  size_limit,
                  time_limit,
                  types_only,
                  get_operational_attributes,
                  controls,
                  paged_size,
                  paged_criticality,
                  cookie):
    response = connection.search(search_base,
                                 search_filter,
                                 search_scope,
                                 dereference_aliases,
                                 list(attributes) if attributes is not None else None,
                                 size_limit,
                                 time_limit,
                                 types_only,
                                 get_operational_attributes,
                                 controls,
                                 paged_size,
                                 paged_criticality,
                                 cookie)
    if not connection.strategy.sync:
        response, result = connection.get_response(response)
    elif connection.strategy.thread_safe:
        _, result, response, _ = response
    else:
        response = connection.response
        result = connection.result
    return response or [], result


def _extract_cookie(result, has_continuation):
    try:
        cookie = result['controls'][PAGED_SEARCH_CONTROL_OID]['value']['cookie']
    except (KeyError, TypeError):
        if has_continuation:
            raise LDAPPagedSearchResumeError('server omitted the paged search cookie while resuming')
        return b''
    return _as_bytes_cookie(cookie) or b''


def _raise_operation_result(result):
    if not result:
        raise LDAPPagedSearchResumeError('server returned no paged search result')
    if result and result.get('result') != 0:
        raise LDAPOperationResult(result=result.get('result'),
                                  description=result.get('description'),
                                  dn=result.get('dn'),
                                  message=result.get('message'),
                                  response_type=result.get('type'))


def _resumable_paged_search_generator(connection,
                                      search_base,
                                      search_filter,
                                      search_scope,
                                      dereference_aliases,
                                      attributes,
                                      size_limit,
                                      time_limit,
                                      types_only,
                                      get_operational_attributes,
                                      controls,
                                      paged_size,
                                      paged_criticality,
                                      cursor,
                                      connection_pool,
                                      max_retries,
                                      retry_delay,
                                      max_retry_delay,
                                      on_cursor):
    pooled = connection_pool is not None
    leased_connection = None
    original_auto_referrals = {}

    try:
        while not cursor.completed:
            retry = 0
            while True:
                try:
                    if pooled:
                        if leased_connection is None:
                            leased_connection = connection_pool.acquire()
                        current_connection = leased_connection
                    else:
                        current_connection = connection
                        if current_connection.closed and not _reconnect_connection(current_connection):
                            raise LDAPCommunicationError('unable to reopen the LDAP connection')

                    if current_connection not in original_auto_referrals:
                        original_auto_referrals[current_connection] = current_connection.auto_referrals
                        current_connection.auto_referrals = False

                    response, result = _execute_page(current_connection,
                                                     cursor.search_base,
                                                     cursor.search_filter,
                                                     cursor.search_scope,
                                                     cursor.dereference_aliases,
                                                     cursor.attributes,
                                                     cursor.size_limit,
                                                     cursor.time_limit,
                                                     cursor.types_only,
                                                     cursor.get_operational_attributes,
                                                     controls,
                                                     cursor.paged_size,
                                                     cursor.paged_criticality,
                                                     cursor.cookie)
                    _raise_operation_result(result)
                    break
                except (LDAPCommunicationError, OSError) as error:
                    if retry >= max_retries:
                        raise LDAPPagedSearchResumeError(
                            'paged search could not resume after %d reconnect attempts: %s' % (max_retries, error))
                    if pooled:
                        connection_pool.release(leased_connection, invalid=True)
                        leased_connection = None
                    retry += 1
                    delay = min(max_retry_delay, retry_delay * (2 ** (retry - 1)))
                    if delay > 0:
                        sleep(delay)

            has_continuation = cursor.cookie not in (None, b'')
            next_cookie = _extract_cookie(result, has_continuation)
            if next_cookie and next_cookie == cursor.cookie:
                raise LDAPPagedSearchResumeError('server returned the same paged search cookie; cursor is stalled')

            cursor.cookie = next_cookie
            cursor.pages += 1
            cursor.entries += len(response)
            cursor.completed = not next_cookie
            if on_cursor is not None:
                on_cursor(cursor)

            if log_enabled(PROTOCOL):
                log(PROTOCOL, 'paged search cursor page %d received with %d entries', cursor.pages, len(response))

            for entry in response:
                yield entry
    finally:
        for current_connection, auto_referrals in original_auto_referrals.items():
            current_connection.auto_referrals = auto_referrals
        if pooled and leased_connection is not None:
            connection_pool.release(leased_connection)
        if log_enabled(BASIC):
            log(BASIC, 'paged search cursor stopped at page %d with %d entries', cursor.pages, cursor.entries)


def resumable_paged_search(connection,
                           search_base,
                           search_filter,
                           search_scope=SUBTREE,
                           dereference_aliases=DEREF_ALWAYS,
                           attributes=None,
                           size_limit=0,
                           time_limit=0,
                           types_only=False,
                           get_operational_attributes=False,
                           controls=None,
                           paged_size=100,
                           paged_criticality=False,
                           cursor=None,
                           connection_pool=None,
                           max_retries=3,
                           retry_delay=0.1,
                           max_retry_delay=5,
                           on_cursor=None):
    """
    Stream a paged search using a persistent RFC 2696 cookie cursor.

    The connection (or a connection leased from connection_pool) is reused
    for every page. If the connection is lost before a page is complete, the
    same cookie is retried on a healthy connection. A page is committed to the
    cursor before its entries are yielded.
    """
    if connection_pool is not None and (not hasattr(connection_pool, 'acquire') or not hasattr(connection_pool, 'release')):
        raise LDAPPagedSearchCursorError('connection_pool must be a ConnectionPool')
    if max_retries < 0:
        raise LDAPPagedSearchCursorError('max_retries cannot be negative')
    if paged_size is None or paged_size < 1:
        raise LDAPPagedSearchCursorError('paged_size must be greater than zero')

    if attributes is not None and not isinstance(attributes, str):
        attributes = list(attributes)
    if controls is not None:
        controls = list(controls)

    if connection is None:
        if connection_pool is None:
            raise LDAPPagedSearchCursorError('connection or connection_pool is required')
        with connection_pool.connection() as check_connection:
            check_names = check_connection.check_names
    else:
        check_names = connection.check_names

    normalized_base = safe_dn(search_base) if check_names and search_base else search_base
    active_cursor = _build_cursor(cursor,
                                  normalized_base,
                                  search_filter,
                                  search_scope,
                                  dereference_aliases,
                                  attributes,
                                  size_limit,
                                  time_limit,
                                  types_only,
                                  get_operational_attributes,
                                  controls,
                                  paged_size,
                                  paged_criticality)
    generator = _resumable_paged_search_generator(connection,
                                                  normalized_base,
                                                  search_filter,
                                                  search_scope,
                                                  dereference_aliases,
                                                  attributes,
                                                  size_limit,
                                                  time_limit,
                                                  types_only,
                                                  get_operational_attributes,
                                                  controls,
                                                  paged_size,
                                                  paged_criticality,
                                                  active_cursor,
                                                  connection_pool,
                                                  max_retries,
                                                  retry_delay,
                                                  max_retry_delay,
                                                  on_cursor)
    return PagedSearchCursorIterator(generator, active_cursor)


paged_search_resumable = resumable_paged_search
