#!/usr/bin/env python3
"""Unit tests for runc regression cleanup without running a container."""
import contextlib
import io
import subprocess
import unittest
from unittest.mock import Mock

from runc_redis_regression import cleanup_containers


class CleanupTests(unittest.TestCase):
    runtimes = ((['runc', '--root', 'target'], 'target-cleanup'),
                (['runc', '--root', 'source'], 'source-cleanup'))

    def run_cleanup(self, outcomes, failed=False):
        self.commands = Mock()
        self.commands.run.side_effect = outcomes
        cleanup_containers(self.commands, self.runtimes, 'redis', failed)

    def check_calls(self):
        self.assertEqual(self.commands.run.call_count, 2)
        for call, (runtime, label) in zip(self.commands.run.call_args_list, self.runtimes):
            self.assertEqual(call.args, (runtime + ['delete', '--force', 'redis'], label))
            self.assertEqual(call.kwargs, {'timeout': 30, 'check': False})

    def test_success(self):
        self.run_cleanup([None, None])
        self.check_calls()

    def test_target_timeout_still_cleans_source(self):
        timeout = subprocess.TimeoutExpired(['runc', 'delete'], 30)
        with self.assertRaisesRegex(RuntimeError, 'target-cleanup'):
            self.run_cleanup([timeout, None])
        self.check_calls()

    def test_both_cleanup_errors_are_reported(self):
        with self.assertRaisesRegex(RuntimeError, 'target-cleanup.*source-cleanup'):
            self.run_cleanup([OSError('target failed'), OSError('source failed')])
        self.check_calls()

    def test_source_error_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, 'source-cleanup'):
            self.run_cleanup([None, OSError('source failed')])
        self.check_calls()

    def test_primary_failure_is_preserved(self):
        original = ValueError('checkpoint failed')
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            with self.assertRaises(ValueError) as caught:
                try:
                    raise original
                finally:
                    self.run_cleanup([OSError('target failed'),
                                      subprocess.TimeoutExpired(['runc', 'delete'], 30)], failed=True)
        self.assertIs(caught.exception, original)
        self.check_calls()
        self.assertIn('target-cleanup', output.getvalue())
        self.assertIn('source-cleanup', output.getvalue())

    def test_nonzero_exit_is_tolerated(self):
        self.run_cleanup([subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 1)])
        self.check_calls()


if __name__ == '__main__':
    unittest.main()
