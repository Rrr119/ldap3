import os
import random
import tempfile
import unittest

from ldap3 import Connection, ConnectionPool, MOCK_SYNC, NONE, PagedSearchCursor, Server, resumable_paged_search
from ldap3.core.exceptions import LDAPPagedSearchCursorMismatchError, LDAPSocketOpenError


class TestResumablePagedSearch(unittest.TestCase):
    entry_count = 73
    page_size = 5
    search_base = 'o=lab'
    search_filter = '(objectClass=person)'

    def setUp(self):
        self.server = Server('mock-resumable-server', get_info=NONE)
        self.setup_connection = Connection(self.server, client_strategy=MOCK_SYNC)
        self.setup_connection.open()
        self.setup_connection.bind()
        self.expected_dns = set()
        for index in range(self.entry_count):
            dn = 'cn=user%04d,o=lab' % index
            self.expected_dns.add(dn)
            self.setup_connection.strategy.add_entry(dn,
                                                     {'objectClass': ['top', 'person'],
                                                      'cn': ['user%04d' % index],
                                                      'sn': ['sn%04d' % index]})
        self.pools = []
        self.connection_count = 0

    def tearDown(self):
        for pool in self.pools:
            pool.close()
        if not self.setup_connection.closed:
            self.setup_connection.unbind()

    def make_pool(self, health_check=None):
        def factory():
            self.connection_count += 1
            return Connection(self.server, client_strategy=MOCK_SYNC)

        pool = ConnectionPool(factory,
                              size=2,
                              health_check=health_check if health_check else (lambda connection: not connection.closed),
                              reconnect_delay=0)
        self.pools.append(pool)
        return pool

    def test_random_disconnects_resume_without_duplicates_or_gaps(self):
        disconnects = {'before': 0, 'after': 0}
        generator = random.Random(26906)

        def maybe_disconnect(stage):
            def callback(request, controls):
                if controls and generator.random() < 0.2:
                    disconnects[stage] += 1
                    return True
                return False
            return callback

        self.server.mock_disconnect = maybe_disconnect('before')
        self.server.mock_disconnect_after = maybe_disconnect('after')
        pool = self.make_pool()
        result = resumable_paged_search(self.setup_connection,
                                        self.search_base,
                                        self.search_filter,
                                        attributes=['cn'],
                                        paged_size=self.page_size,
                                        connection_pool=pool,
                                        max_retries=30,
                                        retry_delay=0)
        dns = [entry['dn'] for entry in result]

        self.assertGreater(disconnects['before'], 0)
        self.assertGreater(disconnects['after'], 0)
        self.assertGreater(self.connection_count, 1)
        self.assertEqual(len(dns), self.entry_count)
        self.assertEqual(set(dns), self.expected_dns)
        self.assertEqual(result.cursor.entries, self.entry_count)
        self.assertTrue(result.cursor.completed)

    def test_cursor_checkpoint_resumes_exactly_where_it_stopped(self):
        pool = self.make_pool()
        first_result = resumable_paged_search(self.setup_connection,
                                              self.search_base,
                                              self.search_filter,
                                              attributes=['cn'],
                                              paged_size=self.page_size,
                                              connection_pool=pool)
        first_dns = [next(first_result)['dn'] for _ in range(self.page_size * 3)]
        self.assertEqual(first_result.cursor.pages, 3)

        descriptor, filename = tempfile.mkstemp(prefix='ldap3-cursor-', suffix='.json')
        os.close(descriptor)
        try:
            first_result.cursor.save(filename)
            saved_cursor = PagedSearchCursor.load(filename)
        finally:
            os.unlink(filename)
        first_result.close()

        second_pool = self.make_pool()
        second_result = resumable_paged_search(self.setup_connection,
                                               self.search_base,
                                               self.search_filter,
                                               attributes=['cn'],
                                               paged_size=self.page_size,
                                               connection_pool=second_pool,
                                               cursor=saved_cursor)
        second_dns = [entry['dn'] for entry in second_result]

        self.assertEqual(len(first_dns) + len(second_dns), self.entry_count)
        self.assertEqual(set(first_dns), set(first_dns).intersection(self.expected_dns))
        self.assertEqual(set(second_dns), set(second_dns).intersection(self.expected_dns))
        self.assertEqual(set(first_dns + second_dns), self.expected_dns)
        self.assertEqual(len(set(first_dns + second_dns)), self.entry_count)
        self.assertTrue(second_result.cursor.completed)

    def test_lost_page_response_is_retried_without_skipping_the_page(self):
        page_requests = [0]

        def disconnect_after_second_page(request, controls):
            if controls:
                page_requests[0] += 1
                return page_requests[0] == 2
            return False

        self.server.mock_disconnect_after = disconnect_after_second_page
        pool = self.make_pool()
        result = resumable_paged_search(self.setup_connection,
                                        self.search_base,
                                        self.search_filter,
                                        attributes=['cn'],
                                        paged_size=self.page_size,
                                        connection_pool=pool,
                                        max_retries=5,
                                        retry_delay=0)
        dns = [entry['dn'] for entry in result]

        self.assertEqual(len(dns), self.entry_count)
        self.assertEqual(set(dns), self.expected_dns)

    def test_cursor_rejects_a_different_search(self):
        cursor = PagedSearchCursor(search_base=self.search_base,
                                   search_filter=self.search_filter,
                                   attributes=['cn'],
                                   paged_size=self.page_size)
        with self.assertRaises(LDAPPagedSearchCursorMismatchError):
            resumable_paged_search(self.setup_connection,
                                   self.search_base,
                                   '(objectClass=groupOfNames)',
                                   attributes=['cn'],
                                   paged_size=self.page_size,
                                   cursor=cursor)

    def test_pool_replaces_connection_that_cannot_be_reopened(self):
        health_checks = []
        pool = self.make_pool(health_check=lambda connection: health_checks.append(connection) or True)
        first_connection = pool.acquire()
        pool.release(first_connection)

        first_connection.closed = True

        def fail_to_open(*args, **kwargs):
            raise LDAPSocketOpenError('simulated dead endpoint')

        first_connection.open = fail_to_open
        second_connection = pool.acquire()
        self.assertIsNot(first_connection, second_connection)
        self.assertFalse(second_connection.closed)
        self.assertTrue(second_connection.bound)
        self.assertGreaterEqual(pool.connections_discarded, 1)
        self.assertTrue(health_checks)
