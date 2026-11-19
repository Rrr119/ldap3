"""
"""

from collections import deque
from contextlib import contextmanager
from threading import Condition
from time import monotonic, sleep

from .. import ANONYMOUS, AUTO_BIND_NONE, BASE, NO_ATTRIBUTES
from .exceptions import LDAPConnectionPoolClosedError, LDAPConnectionPoolError, \
    LDAPConnectionPoolExhaustedError, LDAPExceptionError


class ConnectionPool(object):
    """
    A bounded pool of already configured LDAP connections.

    A connection is leased for the duration of an operation and returned with
    release(). Connections are checked before they are leased. A closed or
    unresponsive connection is reopened and rebound; if that fails it is
    discarded and replaced by a connection built by connection_factory.

    connection_factory is a callable returning a new Connection object. An
    iterable of existing connections can be supplied instead. The latter is
    useful for tests and for applications that need custom connection setup.
    """

    def __init__(self,
                 connection_factory,
                 size=5,
                 health_check=None,
                 health_check_interval=30,
                 health_check_timeout=2,
                 reconnect_attempts=2,
                 reconnect_delay=0.1):
        if callable(connection_factory):
            self._factory = connection_factory
            initial_connections = []
        else:
            try:
                initial_connections = list(connection_factory)
            except TypeError:
                if hasattr(connection_factory, 'search') and hasattr(connection_factory, 'unbind'):
                    initial_connections = [connection_factory]
                else:
                    raise LDAPConnectionPoolError('connection_factory must be callable, a connection, or an iterable of connections')
            if not initial_connections:
                raise LDAPConnectionPoolError('connection_factory cannot be an empty iterable')
            self._factory = None

        if size < 1:
            raise LDAPConnectionPoolError('pool size must be greater than zero')
        if len(initial_connections) > size:
            raise LDAPConnectionPoolError('initial connections exceed pool size')

        self.size = size
        self.health_check = health_check
        self.health_check_interval = health_check_interval
        self.health_check_timeout = health_check_timeout
        self.reconnect_attempts = reconnect_attempts
        self.reconnect_delay = reconnect_delay

        self._condition = Condition()
        self._all = set(initial_connections)
        self._available = deque(initial_connections)
        self._creating = 0
        self._closed = False
        self._last_health_check = {}
        self.connections_created = len(initial_connections)
        self.connections_discarded = 0
        self.health_checks = 0

    @classmethod
    def from_connection(cls, connection, size=5, **kwargs):
        """Build a pool that creates new connections with the same settings."""
        from .connection import Connection

        def factory():
            return Connection(server=connection.server_pool if connection.server_pool else connection.server,
                              user=connection.user,
                              password=connection.password,
                              auto_bind=AUTO_BIND_NONE,
                              version=connection.version,
                              authentication=connection.authentication,
                              client_strategy=connection.strategy_type,
                              auto_referrals=connection.auto_referrals,
                              auto_range=connection.auto_range,
                              sasl_mechanism=connection.sasl_mechanism,
                              sasl_credentials=connection.sasl_credentials,
                              check_names=connection.check_names,
                              collect_usage=connection.usage is not None,
                              read_only=connection.read_only,
                              raise_exceptions=connection.raise_exceptions,
                              fast_decoder=connection.fast_decoder,
                              receive_timeout=connection.receive_timeout,
                              return_empty_attributes=connection.empty_attributes,
                              auto_escape=connection.auto_escape,
                              auto_encode=connection.auto_encode,
                              source_address=connection.source_address,
                              source_port_list=connection.source_port_list)

        return cls(factory, size=size, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __len__(self):
        with self._condition:
            return len(self._all)

    @property
    def available(self):
        with self._condition:
            return len(self._available)

    @property
    def in_use(self):
        with self._condition:
            return len(self._all) - len(self._available)

    @property
    def closed(self):
        with self._condition:
            return self._closed

    def acquire(self, timeout=30):
        """
        Lease a healthy connection.

        The connection remains associated with the caller until release() or
        release(invalid=True) is called.
        """
        deadline = monotonic() + timeout if timeout is not None else None
        failed_attempts = 0
        max_failed_attempts = max(2, self.size + self.reconnect_attempts)

        while True:
            connection, create = self._take_connection(deadline)
            if create:
                try:
                    connection = self._new_connection()
                except Exception as error:
                    with self._condition:
                        self._creating -= 1
                        self._condition.notify_all()
                    failed_attempts += 1
                    if failed_attempts >= max_failed_attempts or self._deadline_expired(deadline):
                        raise LDAPConnectionPoolExhaustedError('unable to create a connection: ' + str(error))
                    self._wait_before_retry(failed_attempts, deadline)
                    continue
                with self._condition:
                    self._all.add(connection)
                    self._creating -= 1
                    self.connections_created += 1
                    self._condition.notify_all()

            if self._is_healthy(connection):
                return connection

            self.release(connection, invalid=True)
            failed_attempts += 1
            if failed_attempts >= max_failed_attempts or self._deadline_expired(deadline):
                raise LDAPConnectionPoolExhaustedError('no healthy connection available in pool')
            self._wait_before_retry(failed_attempts, deadline)

    def release(self, connection, invalid=False):
        """Return a leased connection to the pool."""
        close_connection = False
        with self._condition:
            if connection not in self._all:
                return
            if invalid or self._closed or connection.closed:
                self._all.discard(connection)
                try:
                    self._available.remove(connection)
                except ValueError:
                    pass
                self.connections_discarded += 1
                close_connection = True
            elif connection not in self._available:
                self._available.append(connection)
            self._condition.notify_all()

        if close_connection:
            self._close_connection(connection)

    @contextmanager
    def connection(self, timeout=30):
        """Lease a connection for a with-block."""
        connection = self.acquire(timeout)
        try:
            yield connection
        except Exception:
            self.release(connection, invalid=True)
            raise
        else:
            self.release(connection)

    def reconnect(self, connection):
        """Reopen and rebind a connection, or replace it if that is not possible."""
        if connection not in self._all:
            raise LDAPConnectionPoolError('connection does not belong to this pool')
        if self._reconnect_connection(connection):
            return connection

        self.release(connection, invalid=True)
        replacement = self._new_connection()
        with self._condition:
            self._all.add(replacement)
            self.connections_created += 1
            self._condition.notify_all()
        return replacement

    def is_healthy(self, connection):
        """Run the configured health check, reconnecting the connection if needed."""
        return self._is_healthy(connection)

    def close(self):
        with self._condition:
            if self._closed:
                return
            self._closed = True
            connections = list(self._all)
            self._all.clear()
            self._available.clear()
            self._condition.notify_all()

        for connection in connections:
            self._close_connection(connection)

    def _take_connection(self, deadline):
        with self._condition:
            while True:
                if self._closed:
                    raise LDAPConnectionPoolClosedError('connection pool is closed')
                if self._available:
                    return self._available.popleft(), False
                if len(self._all) + self._creating < self.size:
                    self._creating += 1
                    return None, True
                if self._deadline_expired(deadline):
                    raise LDAPConnectionPoolExhaustedError('timed out waiting for an available connection')
                remaining = None if deadline is None else max(0, deadline - monotonic())
                self._condition.wait(remaining)

    def _new_connection(self):
        if self._factory is None:
            raise LDAPConnectionPoolError('no connection factory configured and no connection available')
        connection = self._factory()
        if not self._activate_connection(connection):
            raise LDAPConnectionPoolError('unable to open or bind the new connection')
        self._last_health_check[connection] = monotonic()
        return connection

    def _activate_connection(self, connection):
        try:
            if connection.closed:
                connection.open(read_server_info=False)
            if not connection.bound and not connection.bind(read_server_info=False):
                return False
            return True
        except (LDAPExceptionError, OSError):
            return False

    def _reconnect_connection(self, connection):
        try:
            if not connection.closed:
                try:
                    connection.unbind()
                except (LDAPExceptionError, OSError):
                    pass
            return self._activate_connection(connection)
        except (LDAPExceptionError, OSError):
            return False

    def _is_healthy(self, connection):
        if connection.closed:
            return self._reconnect_with_retries(connection)
        if not self._passive_health_check(connection):
            return False
        if self.health_check is not None:
            self.health_checks += 1
            try:
                return bool(self.health_check(connection))
            except Exception:
                return False

        if not self.health_check_interval:
            return True

        now = monotonic()
        last_checked = self._last_health_check.get(connection, 0)
        if now - last_checked < self.health_check_interval:
            return True
        if getattr(connection.strategy, 'no_real_dsa', False):
            return True

        self.health_checks += 1
        try:
            if not connection.strategy.sync:
                return True
            connection.search('', '(objectClass=*)', BASE, attributes=[NO_ATTRIBUTES],
                              size_limit=1, time_limit=self.health_check_timeout)
            result = connection.result
            healthy = bool(result and result.get('result') in (0, 4))
        except Exception:
            healthy = False

        self._last_health_check[connection] = now
        return healthy or self._reconnect_with_retries(connection)

    def _passive_health_check(self, connection):
        if connection.closed:
            return False
        if not connection.bound and connection.authentication != ANONYMOUS:
            return self._reconnect_with_retries(connection)
        return True

    def _reconnect_with_retries(self, connection):
        for attempt in range(self.reconnect_attempts + 1):
            if self._reconnect_connection(connection):
                self._last_health_check[connection] = monotonic()
                return True
            if attempt < self.reconnect_attempts and self.reconnect_delay:
                sleep(self.reconnect_delay * (2 ** attempt))
        return False

    def _wait_before_retry(self, attempt, deadline):
        if self.reconnect_delay:
            delay = self.reconnect_delay * (2 ** min(attempt, 8))
            if deadline is not None:
                delay = min(delay, max(0, deadline - monotonic()))
            if delay:
                sleep(delay)

    @staticmethod
    def _deadline_expired(deadline):
        return deadline is not None and monotonic() >= deadline

    @staticmethod
    def _close_connection(connection):
        try:
            connection.unbind()
        except (LDAPExceptionError, OSError):
            try:
                connection.strategy.close()
            except Exception:
                pass


LDAPConnectionPool = ConnectionPool
