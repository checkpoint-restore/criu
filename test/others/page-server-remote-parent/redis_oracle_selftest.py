#!/usr/bin/env python3
"""Unprivileged tests for the Redis protocol client and external oracle."""
import contextlib
import socket
import threading
import unittest
from unittest import mock

from redis_oracle import OracleError, RedisClient, RedisError, RedisOracle


@contextlib.contextmanager
def scripted_client(reply, request=b'*1\r\n$4\r\nPING\r\n'):
    client_socket, server_socket = socket.socketpair()
    client_socket.settimeout(2)
    server_socket.settimeout(2)
    errors = []

    def serve():
        try:
            received = b''
            while len(received) < len(request):
                chunk = server_socket.recv(len(request) - len(received))
                if not chunk:
                    raise AssertionError('Client closed before sending command')
                received += chunk
            if received != request:
                raise AssertionError('Incorrect RESP request encoding')
            for offset in range(0, len(reply), 7):
                server_socket.sendall(reply[offset:offset + 7])
        except Exception as error:
            errors.append(error)
        finally:
            server_socket.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        with mock.patch('redis_oracle.socket.create_connection',
                        return_value=client_socket):
            with RedisClient('localhost', 0) as client:
                yield client
    finally:
        client_socket.close()
        worker.join(timeout=3)
        if worker.is_alive():
            raise AssertionError('Fake RESP server did not finish')
        if errors:
            raise errors[0]


class ProtocolTests(unittest.TestCase):
    def test_fragmented_binary_request_and_response(self):
        value = b'\x00\r\n\xff*123\r\n'
        request = (b'*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$%d\r\n' %
                   len(value)) + value + b'\r\n'
        reply = b'$%d\r\n' % len(value) + value + b'\r\n'
        with scripted_client(reply, request) as client:
            self.assertEqual(client.command('SET', b'key', value), value)

    def test_large_fragmented_bulk(self):
        value = bytes(range(256)) * 512
        reply = b'$%d\r\n' % len(value) + value + b'\r\n'
        with scripted_client(reply) as client:
            self.assertEqual(client.command('PING'), value)

    def test_reply_types(self):
        replies = [(b'+PONG\r\n', b'PONG'), (b':-42\r\n', -42),
                   (b'$0\r\n\r\n', b''), (b'$-1\r\n', None),
                   (b'*-1\r\n', None), (b'*0\r\n', []),
                   (b'*3\r\n$1\r\nx\r\n:2\r\n*1\r\n+OK\r\n',
                    [b'x', 2, [b'OK']])]
        for reply, expected in replies:
            with self.subTest(reply=reply), scripted_client(reply) as client:
                self.assertEqual(client.command('PING'), expected)

    def test_errors_and_malformed_replies(self):
        replies = [b'-ERR intentional\r\n', b'', b'+short',
                   b'$4\r\nab', b'$1\r\nx!!', b'$-2\r\n',
                   b'$67108865\r\n', b'*65537\r\n', b':not-an-int\r\n',
                   b'?unknown\r\n', b'*1\r\n' * 9]
        for reply in replies:
            with self.subTest(reply=reply), scripted_client(reply) as client:
                with self.assertRaises(RedisError):
                    client.command('PING')


class MemoryRedis:
    """An independent command model; it never reads oracle expectations."""

    def __init__(self):
        self.data = {}
        self.run_id = b'a' * 40
        self.commands = []

    def command(self, *arguments):
        args = [value if isinstance(value, bytes) else str(value).encode('utf-8')
                for value in arguments]
        command = args.pop(0).upper()
        self.commands.append(command)
        if command == b'INFO':
            return b'# Server\r\nrun_id:' + self.run_id + b'\r\n'
        if command == b'PING':
            return b'PONG'
        if command == b'DBSIZE':
            return len(self.data)
        if command == b'EXISTS':
            return sum(key in self.data for key in args)
        if command == b'DEL':
            removed = 0
            for key in args:
                if key in self.data:
                    del self.data[key]
                    removed += 1
            return removed
        key = args.pop(0)
        if command == b'SET':
            if len(args) == 2 and args[1] == b'NX' and key in self.data:
                return None
            self.data[key] = args[0]
            return b'OK'
        if command == b'GET':
            return self.data.get(key)
        if command in (b'INCR', b'INCRBY'):
            value = int(self.data.get(key, b'0'))
            value += 1 if command == b'INCR' else int(args[0])
            self.data[key] = str(value).encode('ascii')
            return value
        if command in (b'RPUSH', b'LPUSH'):
            values = self.data.setdefault(key, [])
            for value in args:
                if command == b'LPUSH':
                    values.insert(0, value)
                else:
                    values.append(value)
            return len(values)
        if command == b'RPOP':
            return self.data[key].pop()
        if command == b'LRANGE':
            if args != [b'0', b'-1']:
                raise AssertionError('Unsupported fake LRANGE arguments')
            return list(self.data[key])
        if command in (b'HSET', b'ZADD'):
            values = self.data.setdefault(key, {})
            field, value = args if command == b'HSET' else (args[1], int(args[0]))
            added = field not in values
            values[field] = value
            return int(added)
        if command in (b'HDEL', b'ZREM'):
            if args[0] in self.data[key]:
                del self.data[key][args[0]]
                return 1
            return 0
        if command == b'HGETALL':
            return [value for item in reversed(list(self.data[key].items()))
                    for value in item]
        if command == b'SADD':
            values = self.data.setdefault(key, set())
            added = len(set(args) - values)
            values.update(args)
            return added
        if command == b'SREM':
            values = self.data[key]
            removed = len(values.intersection(args))
            values.difference_update(args)
            return removed
        if command == b'SMEMBERS':
            return sorted(self.data[key], reverse=True)
        if command == b'ZRANGE':
            if args != [b'0', b'-1', b'WITHSCORES']:
                raise AssertionError('Unsupported fake ZRANGE arguments')
            items = sorted(self.data[key].items(), key=lambda item: (item[1], item[0]))
            return [value for member, score in items
                    for value in (member, str(score).encode('ascii'))]
        raise AssertionError(f'Unimplemented fake command {command!r}')


class SmallOracle(RedisOracle):
    STRING_COUNT = 64
    VALUE_SIZE = 128


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.client = MemoryRedis()
        self.oracle = SmallOracle()
        self.oracle.seed(self.client)

    def test_full_dataset_three_generations(self):
        client = MemoryRedis()
        oracle = RedisOracle()
        initial = oracle.seed(client)
        self.assertEqual(initial['dataset_bytes'], 32 << 20)
        self.assertEqual(initial['key_count'], 262)
        digests = {initial['sha256']}
        for generation in (1, 2, 3):
            result = oracle.mutate(client, generation)
            self.assertEqual(result['mutated_keys'], 16)
            self.assertEqual(result['mutated_bytes'], 2 << 20)
            self.assertEqual(result['key_count'], 262)
            digests.add(result['sha256'])
        self.assertEqual(len(digests), 4)
        # Check retained generations and the overlapping stripe independently.
        for index, generation in ((0, 3), (4, 1), (16, 2), (28, 3), (40, 0),
                                  (255, 0)):
            self.assertEqual(client.data[oracle.string_key(index)],
                             oracle.value(index, generation))
        result = oracle.verify(client)
        self.assertEqual(result['generation'], 3)
        self.assertEqual(client.data[oracle.COUNTER], b'46')
        self.assertIn(b'PING', client.commands)
        self.assertIn(b'INCR', client.commands)
        self.assertEqual(len(client.data), result['key_count'])

    def test_detects_last_byte_corruption(self):
        key = self.oracle.string_key(self.oracle.STRING_COUNT - 1)
        original = self.client.data[key]
        self.client.data[key] = original[:-1] + bytes([original[-1] ^ 1])
        with self.assertRaisesRegex(OracleError, 'GET'):
            self.oracle.verify(self.client)

    def test_detects_stale_generation(self):
        old = self.client.data[self.oracle.string_key(0)]
        self.oracle.mutate(self.client, 1)
        self.oracle.mutate(self.client, 2)
        self.client.data[self.oracle.string_key(0)] = old
        with self.assertRaisesRegex(OracleError, 'GET'):
            self.oracle.verify(self.client)

    def test_detects_replacement_server_with_identical_data(self):
        self.client.run_id = b'b' * 40
        with self.assertRaisesRegex(OracleError, 'replacement server'):
            self.oracle.verify(self.client)

    def test_detects_unexpected_key(self):
        self.client.data[b'unexpected'] = b'value'
        with self.assertRaisesRegex(OracleError, 'key count'):
            self.oracle.verify(self.client)

    def test_detects_same_count_key_substitution(self):
        del self.client.data[self.oracle.string_key(0)]
        self.client.data[b'unexpected'] = b'value'
        with self.assertRaisesRegex(OracleError, 'GET'):
            self.oracle.verify(self.client)

    def test_detects_collection_corruption(self):
        changes = [(self.oracle.LIST, lambda value: value.reverse()),
                   (self.oracle.HASH, lambda value: value.update({b'field:00': b'bad'})),
                   (self.oracle.SET, lambda value: value.add(b'extra')),
                   (self.oracle.ZSET, lambda value: value.update({b'zset:00\x00\r\n': 100}))]
        for key, change in changes:
            with self.subTest(key=key):
                original = self.client.data[key].copy()
                change(self.client.data[key])
                with self.assertRaises(OracleError):
                    self.oracle.verify(self.client)
                self.client.data[key] = original

    def test_detects_broken_service(self):
        original = self.client.command

        def broken(*args):
            if args[0] == 'INCR':
                return 41
            return original(*args)

        with mock.patch.object(self.client, 'command', side_effect=broken):
            with self.assertRaisesRegex(OracleError, 'Service INCR'):
                self.oracle.verify(self.client)

    def test_requires_ordered_generations_and_empty_database(self):
        with self.assertRaises(OracleError):
            self.oracle.mutate(self.client, 2)
        with self.assertRaises(OracleError):
            self.oracle.seed(self.client)
        with self.assertRaisesRegex(OracleError, 'not empty'):
            SmallOracle().seed(self.client)
        for generation in (1, 2, 3):
            self.oracle.mutate(self.client, generation)
        with self.assertRaises(OracleError):
            self.oracle.mutate(self.client, 4)


if __name__ == '__main__':
    unittest.main()
