#!/usr/bin/env python3
"""External data and service oracle for a checkpointed Redis server.

The controller owns all expected bytes. Keep this object outside the container,
and close RedisClient connections before checkpointing. Verification reconnects
after restore; this does not test established TCP sessions or key expiration.
"""
import hashlib
import socket


class RedisError(RuntimeError):
    pass


class OracleError(RuntimeError):
    pass


class RedisClient:
    """Small binary-safe RESP2 client with bounded reads and socket timeouts."""

    def __init__(self, host, port, timeout=5):
        self.socket = socket.create_connection((host, port), timeout=timeout)
        self.reader = self.socket.makefile('rb')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        try:
            self.reader.close()
        finally:
            self.socket.close()

    def _read_exact(self, size):
        data = self.reader.read(size)
        if len(data) != size:
            raise RedisError('Truncated RESP reply')
        return data

    def _read_reply(self, depth=0):
        if depth > 8:
            raise RedisError('RESP nesting limit exceeded')
        line = self.reader.readline(65537)
        if len(line) > 65536 or not line.endswith(b'\r\n'):
            raise RedisError('Truncated or oversized RESP header')
        kind, value = line[:1], line[1:-2]
        if kind == b'+':
            return value
        if kind == b'-':
            raise RedisError(value.decode('utf-8', errors='replace'))
        if kind not in (b':', b'$', b'*'):
            raise RedisError('Unknown RESP reply type')
        try:
            size = int(value)
        except ValueError as error:
            raise RedisError('Invalid RESP integer') from error
        if kind == b':':
            return size
        if size == -1:
            return None
        if size < 0:
            raise RedisError('Invalid RESP length')
        if kind == b'$':
            if size > 64 << 20:
                raise RedisError('RESP bulk reply limit exceeded')
            data = self._read_exact(size)
            if self._read_exact(2) != b'\r\n':
                raise RedisError('Invalid RESP bulk terminator')
            return data
        if size > 65536:
            raise RedisError('RESP array limit exceeded')
        return [self._read_reply(depth + 1) for _ in range(size)]

    def command(self, *arguments):
        if not arguments:
            raise ValueError('Redis command requires arguments')
        parts = [b'*%d\r\n' % len(arguments)]
        for argument in arguments:
            if isinstance(argument, (str, int)):
                argument = str(argument).encode('utf-8')
            if not isinstance(argument, bytes):
                raise TypeError('Redis arguments must be bytes, str, or int')
            parts.extend((b'$%d\r\n' % len(argument), argument, b'\r\n'))
        self.socket.sendall(b''.join(parts))
        return self._read_reply()


def require_equal(actual, expected, description):
    if actual != expected:
        raise OracleError(f'{description}: Redis value differs from controller')


def server_run_id(client):
    info = client.command('INFO', 'server')
    if not isinstance(info, bytes):
        raise OracleError('INFO server did not return bytes')
    fields = dict(line.split(b':', 1) for line in info.splitlines()
                  if b':' in line and not line.startswith(b'#'))
    run_id = fields.get(b'run_id', b'')
    if len(run_id) != 40 or any(c not in b'0123456789abcdef' for c in run_id):
        raise OracleError('INFO server lacks a valid run_id')
    return run_id.decode('ascii')


class RedisOracle:
    STRING_COUNT = 256
    VALUE_SIZE = 128 << 10
    PREFIX = b'criu:oracle:'
    LIST = PREFIX + b'list'
    HASH = PREFIX + b'hash'
    SET = PREFIX + b'set'
    ZSET = PREFIX + b'zset'
    COUNTER = PREFIX + b'counter'

    def __init__(self):
        self.run_id = None
        self.generation = -1
        self.strings = {}
        self.list_values = []
        self.hash_values = {}
        self.set_values = set()
        self.zset_values = {}
        self.deleted_keys = []

    @classmethod
    def string_key(cls, index):
        return cls.PREFIX + b'string:%04d' % index

    @classmethod
    def value(cls, index, generation):
        # High-entropy, reproducible binary payloads cover every value byte.
        seed = b'criu-redis-value:%d:%d' % (index, generation)
        return hashlib.shake_256(seed).digest(cls.VALUE_SIZE)

    @classmethod
    def marker_key(cls, generation):
        return cls.PREFIX + b'marker:%d' % generation

    def _check_server(self, client):
        if self.run_id is None:
            raise OracleError('Redis oracle has not been seeded')
        require_equal(server_run_id(client), self.run_id,
                      'Server run_id changed (replacement server)')

    def _set_string(self, client, key, value):
        require_equal(client.command('SET', key, value), b'OK', f'SET {key!r}')
        self.strings[key] = value

    def seed(self, client):
        if self.generation != -1 or self.run_id is not None:
            raise OracleError('Redis oracle may only be seeded once')
        require_equal(client.command('DBSIZE'), 0, 'Initial database not empty')
        self.run_id = server_run_id(client)
        for index in range(self.STRING_COUNT):
            self._set_string(client, self.string_key(index), self.value(index, 0))
        self._set_string(client, self.COUNTER, b'40')
        self._set_string(client, self.marker_key(0), b'generation:0\x00\r\n')

        self.list_values = [b'list:%02d\x00\r\n' % i for i in range(32)]
        require_equal(client.command('RPUSH', self.LIST, *self.list_values),
                      len(self.list_values), 'Seed list length')
        self.hash_values = {b'field:%02d' % i: b'hash:%02d\x00\r\n' % i
                            for i in range(16)}
        for field, value in self.hash_values.items():
            require_equal(client.command('HSET', self.HASH, field, value), 1,
                          'Seed hash field')
        self.set_values = {b'set:%02d\x00\r\n' % i for i in range(16)}
        require_equal(client.command('SADD', self.SET, *sorted(self.set_values)),
                      len(self.set_values), 'Seed set members')
        self.zset_values = {b'zset:%02d\x00\r\n' % i: i for i in range(16)}
        for member, score in self.zset_values.items():
            require_equal(client.command('ZADD', self.ZSET, score, member), 1,
                          'Seed sorted set member')
        self.generation = 0
        return self.verify(client)

    def mutate(self, client, generation):
        """Change 2 MiB per round, retaining bytes from older generations."""
        if generation not in (1, 2, 3) or generation != self.generation + 1:
            raise OracleError('Mutation generations must be 1, 2, then 3')
        self._check_server(client)
        changed = 0
        indices = list(range(4)) + list(range(4 + (generation - 1) * 12,
                                            4 + generation * 12))
        for index in indices:
            # Four values are rewritten every round. The other twelve
            # retain this generation through subsequent checkpoints.
            self._set_string(client, self.string_key(index),
                             self.value(index, generation))
            changed += 1

        old_marker = self.marker_key(generation - 1)
        require_equal(client.command('DEL', old_marker), 1, 'Delete old marker')
        del self.strings[old_marker]
        self.deleted_keys.append(old_marker)
        self._set_string(client, self.marker_key(generation),
                         b'generation:%d\x00\r\n' % generation)
        counter = int(self.strings[self.COUNTER]) + generation
        require_equal(client.command('INCRBY', self.COUNTER, generation),
                      counter, 'Mutate counter')
        self.strings[self.COUNTER] = str(counter).encode('ascii')

        head = b'list:generation:%d\x00\r\n' % generation
        require_equal(client.command('LPUSH', self.LIST, head),
                      len(self.list_values) + 1, 'Mutate list length')
        require_equal(client.command('RPOP', self.LIST), self.list_values[-1],
                      'Mutate list tail')
        self.list_values = [head] + self.list_values[:-1]
        field = b'field:%02d' % generation
        require_equal(client.command('HDEL', self.HASH, field), 1,
                      'Delete hash field')
        del self.hash_values[field]
        field = b'new-field:%d' % generation
        value = b'hash:generation:%d\x00\r\n' % generation
        require_equal(client.command('HSET', self.HASH, field, value), 1,
                      'Add hash field')
        self.hash_values[field] = value
        require_equal(client.command('HSET', self.HASH, b'field:00', value), 0,
                      'Update hash field')
        self.hash_values[b'field:00'] = value
        member = b'set:%02d\x00\r\n' % generation
        require_equal(client.command('SREM', self.SET, member), 1,
                      'Delete set member')
        self.set_values.remove(member)
        member = b'set:generation:%d\x00\r\n' % generation
        require_equal(client.command('SADD', self.SET, member), 1,
                      'Add set member')
        self.set_values.add(member)
        member = b'zset:%02d\x00\r\n' % generation
        require_equal(client.command('ZREM', self.ZSET, member), 1,
                      'Delete sorted set member')
        del self.zset_values[member]
        member = b'zset:generation:%d\x00\r\n' % generation
        require_equal(client.command('ZADD', self.ZSET, 100 + generation,
                                     member), 1, 'Add sorted set member')
        self.zset_values[member] = 100 + generation
        member = b'zset:00\x00\r\n'
        require_equal(client.command('ZADD', self.ZSET, -generation, member),
                      0, 'Update sorted set score')
        self.zset_values[member] = -generation
        self.generation = generation
        result = self.verify(client)
        result.update(mutated_keys=changed,
                      mutated_bytes=changed * self.VALUE_SIZE)
        return result

    def _service_check(self, client):
        require_equal(client.command('PING'), b'PONG', 'PING')
        write_key = self.PREFIX + b'service:write'
        count_key = self.PREFIX + b'service:counter'
        value = b'post-restore-write\x00\r\n\xff'
        require_equal(client.command('SET', write_key, value, 'NX'), b'OK',
                      'New service write')
        try:
            require_equal(client.command('GET', write_key), value,
                          'Read new service write')
            require_equal(client.command('SET', count_key, 41, 'NX'), b'OK',
                          'New service counter')
            require_equal(client.command('INCR', count_key), 42, 'Service INCR')
            require_equal(client.command('GET', count_key), b'42',
                          'Read incremented service counter')
        finally:
            client.command('DEL', write_key, count_key)

    def verify(self, client):
        """Compare every expected value byte, then exercise fresh commands."""
        self._check_server(client)
        key_count = len(self.strings) + 4
        require_equal(client.command('DBSIZE'), key_count, 'Database key count')
        digest = hashlib.sha256()

        def record(*values):
            for value in values:
                digest.update(len(value).to_bytes(8, 'big'))
                digest.update(value)

        for key, expected in sorted(self.strings.items()):
            actual = client.command('GET', key)
            require_equal(actual, expected, f'GET {key!r}')
            record(key, actual)
        for key in self.deleted_keys:
            require_equal(client.command('EXISTS', key), 0,
                          f'Deleted key reappeared: {key!r}')
        actual = client.command('LRANGE', self.LIST, 0, -1)
        require_equal(actual, self.list_values, 'List contents/order')
        record(self.LIST, *actual)
        actual = client.command('HGETALL', self.HASH)
        if not isinstance(actual, list) or len(actual) != 2 * len(self.hash_values):
            raise OracleError('Hash field/value count mismatch')
        require_equal(dict(zip(actual[::2], actual[1::2])), self.hash_values,
                      'Hash fields/values')
        record(self.HASH)
        for field, value in sorted(self.hash_values.items()):
            record(field, value)
        actual = client.command('SMEMBERS', self.SET)
        if not isinstance(actual, list) or len(actual) != len(self.set_values):
            raise OracleError('Set member count mismatch')
        require_equal(set(actual), self.set_values, 'Set members')
        record(self.SET, *sorted(actual))
        expected = []
        for member, score in sorted(self.zset_values.items(),
                                    key=lambda item: (item[1], item[0])):
            expected.extend((member, str(score).encode('ascii')))
        actual = client.command('ZRANGE', self.ZSET, 0, -1, 'WITHSCORES')
        require_equal(actual, expected, 'Sorted set members/scores/order')
        record(self.ZSET, *actual)
        self._service_check(client)
        require_equal(client.command('DBSIZE'), key_count,
                      'Key count after service commands')
        self._check_server(client)
        return {'generation': self.generation, 'run_id': self.run_id,
                'key_count': key_count,
                'string_bytes': sum(map(len, self.strings.values())),
                'dataset_bytes': self.STRING_COUNT * self.VALUE_SIZE,
                'sha256': digest.hexdigest()}
