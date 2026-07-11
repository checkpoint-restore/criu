#!/usr/bin/env python3
"""Crash and race scenarios for CRIT's transactional image replacement.

crit compress/decompress rewrite pages-*.img, pagemap-*.img, and
inventory.img as one transaction (_commit_staged() and friends in
crit.__main__): replacements are staged next to the originals, the
originals are retained through hard links, and any failure or
termination signal before the whole set is durable must put every
original image back. Each test sabotages one step of that commit and
asserts the directory ends in one of the two legal states: the complete
old image set or the complete new one.

Faults are injected with intercept(), which wraps a function in the os
module for the duration of a test. crit resolves os functions at call
time through the same module object this test imports, so the wrapper
sees exactly the calls made by the code under test -- and also this
module's own os calls inside the window, which is why it must always
forward to the real function saved before patching.
"""

import errno
import glob
import io
import os
import shutil
import signal
import stat
import tempfile
import unittest
import unittest.mock as mock
from contextlib import contextmanager, redirect_stderr

from crit import __main__ as crit_main

# Transaction files created next to the images: staged replacements
# (".NAME.crit-XXXX") and rollback hard links (".NAME.crit-rollback-XXXX").
# The name patterns come from _staged_file() and _make_rollback_link().
TRANSACTION_GLOB = ".*.crit-*"
ROLLBACK_GLOB = ".*.crit-rollback-*"

TERMINATION_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def write(path, data):
    with open(path, "wb") as output:
        output.write(data)


def read(path):
    with open(path, "rb") as source:
        return source.read()


@contextmanager
def intercept(name, when, before=None, after=None):
    """Wrap os.<name> so faults fire on calls matching when(*args).

    For a matching call, before(*args) runs first (raise from it to
    suppress the real call), then the real function, then after(*args).
    Calls not matching when() pass straight through.
    """
    real = getattr(os, name)

    def wrapper(*args, **kwargs):
        if not when(*args, **kwargs):
            return real(*args, **kwargs)
        if before is not None:
            before(*args, **kwargs)
        result = real(*args, **kwargs)
        if after is not None:
            after(*args, **kwargs)
        return result

    with mock.patch.object(crit_main.os, name, new=wrapper):
        yield


def raise_(exc):
    """intercept() hook: fail the matching call with exc."""
    def effect(*args, **kwargs):
        raise exc
    return effect


def send_signal(signum):
    """intercept() hook: deliver signum to this process."""
    def effect(*args, **kwargs):
        os.kill(os.getpid(), signum)
    return effect


class TransactionTestCase(unittest.TestCase):
    """Shared fixture: a directory of original images and staged updates."""

    def make_images(self, count=1):
        """Create count originals ("old-N") with staged updates ("new-N").

        Returns (directory, staged) where staged is the [(path, tmp_path)]
        list _commit_staged() consumes.
        """
        directory = tempfile.mkdtemp(dir=".")
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        staged = []
        for index in range(count):
            path = os.path.join(directory, "image-%d" % index)
            staged_path = path + ".new"
            write(path, b"old-%d" % index)
            write(staged_path, b"new-%d" % index)
            staged.append((path, staged_path))
        return directory, staged

    def assertOriginalsIntact(self, staged):
        for index, (path, _) in enumerate(staged):
            self.assertEqual(read(path), b"old-%d" % index)

    def assertCommitted(self, staged):
        for index, (path, _) in enumerate(staged):
            self.assertEqual(read(path), b"new-%d" % index)

    def assertNoTransactionFiles(self, directory):
        self.assertEqual(glob.glob(os.path.join(directory,
                                                TRANSACTION_GLOB)), [])


class CommitRollbackTests(TransactionTestCase):
    """A failed commit must restore the complete original image set."""

    def test_failed_rename_restores_originals(self):
        """A rename failure on a later image rolls back earlier renames."""
        directory, staged = self.make_images(count=2)
        second_staged = staged[1][1]

        with intercept("replace",
                       when=lambda src, dst: src == second_staged,
                       before=raise_(OSError(
                           "injected second-image rename failure"))):
            with self.assertRaisesRegex(crit_main.CritTransformError,
                                        "original images were restored"):
                crit_main._commit_staged(staged, True)

        self.assertOriginalsIntact(staged)
        self.assertNoTransactionFiles(directory)

    def test_termination_signal_rolls_back(self):
        """A signal between renames rolls back and is named in the error."""
        for signum in TERMINATION_SIGNALS:
            if signal.getsignal(signum) == signal.SIG_IGN:
                # _commit_staged() leaves ignored signals ignored, so an
                # injected kill would not interrupt anything.
                continue
            with self.subTest(signal=signal.Signals(signum).name):
                directory, staged = self.make_images(count=2)
                second_staged = staged[1][1]

                with intercept("replace",
                               when=lambda src, dst, marker=second_staged:
                                   src == marker,
                               after=send_signal(signum)):
                    with self.assertRaisesRegex(
                            crit_main.CritTransformError,
                            signal.Signals(signum).name):
                        crit_main._commit_staged(staged, True)

                self.assertOriginalsIntact(staged)
                self.assertNoTransactionFiles(directory)

    def test_failed_rollback_preserves_recovery_link(self):
        """If rollback also fails, the original bytes survive in a named
        recovery link and the error reports the double failure."""
        directory, staged = self.make_images(count=1)
        staged_path = staged[0][1]

        with intercept("replace",
                       when=lambda src, dst: "crit-rollback" in src,
                       before=raise_(OSError("injected rollback failure"))), \
             intercept("replace",
                       when=lambda src, dst: src == staged_path,
                       after=raise_(OSError("injected failure after rename"))):
            with self.assertRaisesRegex(crit_main.CritTransformError,
                                        "rollback also failed"):
                crit_main._commit_staged(staged, True)

        recovery = glob.glob(os.path.join(directory, ROLLBACK_GLOB))
        self.assertEqual(len(recovery), 1)
        self.assertEqual(read(recovery[0]), b"old-0")


class ConcurrentReplacementTests(TransactionTestCase):
    """A transform must not overwrite an image replaced after staging."""

    def test_replaced_source_is_preserved(self):
        for in_place in (False, True):
            with self.subTest(in_place=in_place):
                directory, staged = self.make_images(count=1)
                path, staged_path = staged[0]
                image_metadata = {
                    path: crit_main._capture_file_metadata(path),
                }
                replacement = path + ".concurrent"
                write(replacement, b"concurrent")
                os.replace(replacement, path)

                with self.assertRaisesRegex(
                        crit_main.CritTransformError,
                        "image changed while preparing to replace"):
                    crit_main._commit_staged(
                        staged, in_place, image_metadata=image_metadata)

                self.assertEqual(read(path), b"concurrent")
                self.assertFalse(os.path.exists(staged_path))
                self.assertFalse(os.path.exists(path + ".bak"))
                self.assertNoTransactionFiles(directory)

    def test_replacement_while_commit_links_original_is_preserved(self):
        for in_place in (False, True):
            with self.subTest(in_place=in_place):
                directory, staged = self.make_images(count=1)
                path, staged_path = staged[0]
                image_metadata = {
                    path: crit_main._capture_file_metadata(path),
                }

                def replace_source(_source, _link):
                    replacement = path + ".concurrent"
                    write(replacement, b"concurrent")
                    os.replace(replacement, path)

                with intercept(
                        "link", when=lambda src, _dst: src == path,
                        after=replace_source):
                    with self.assertRaisesRegex(
                            crit_main.CritTransformError,
                            "image changed while preparing to replace"):
                        crit_main._commit_staged(
                            staged, in_place,
                            image_metadata=image_metadata)

                self.assertEqual(read(path), b"concurrent")
                self.assertFalse(os.path.exists(staged_path))
                self.assertFalse(os.path.exists(path + ".bak"))
                self.assertNoTransactionFiles(directory)

    def test_later_replacement_rolls_back_only_earlier_images(self):
        for in_place in (False, True):
            with self.subTest(in_place=in_place):
                directory, staged = self.make_images(count=2)
                first_path, first_staged = staged[0]
                second_path, second_staged = staged[1]
                image_metadata = {
                    path: crit_main._capture_file_metadata(path)
                    for path, _ in staged
                }

                def replace_second(_source, _destination):
                    replacement = second_path + ".concurrent"
                    write(replacement, b"concurrent")
                    os.replace(replacement, second_path)

                with intercept(
                        "replace",
                        when=lambda src, _dst: src == first_staged,
                        after=replace_second):
                    with self.assertRaisesRegex(
                            crit_main.CritTransformError,
                            "image changed while preparing to replace"):
                        crit_main._commit_staged(
                            staged, in_place,
                            image_metadata=image_metadata)

                self.assertEqual(read(first_path), b"old-0")
                self.assertEqual(read(second_path), b"concurrent")
                self.assertFalse(os.path.exists(first_staged))
                self.assertFalse(os.path.exists(second_staged))
                self.assertFalse(os.path.exists(first_path + ".bak"))
                self.assertFalse(os.path.exists(second_path + ".bak"))
                self.assertNoTransactionFiles(directory)


@unittest.skipIf(signal.getsignal(signal.SIGTERM) == signal.SIG_IGN,
                 "SIGTERM is ignored in this environment")
class SignalHandlingTests(TransactionTestCase):
    """Termination signals must never leave a half-replaced image set."""

    def test_repeated_signal_does_not_interrupt_cleanup(self):
        """The first signal raises for rollback; a repeat during that
        unwinding is swallowed so cleanup can finish."""
        with crit_main._commit_signal_handlers():
            with self.assertRaisesRegex(crit_main.CritTransformError,
                                        "SIGTERM"):
                os.kill(os.getpid(), signal.SIGTERM)
            # Unwinding has started; a second signal must not raise again.
            os.kill(os.getpid(), signal.SIGTERM)

    def test_signal_after_commit_is_ignored(self):
        """Once the replacement set is durable, a late signal must not
        make a committed command look failed."""
        _, staged = self.make_images(count=1)

        with crit_main._commit_signal_handlers() as signal_state:
            crit_main._commit_staged(staged, True, signal_state)
            self.assertTrue(signal_state["committed"])
            os.kill(os.getpid(), signal.SIGTERM)

        self.assertCommitted(staged)

    def test_signal_during_post_commit_cleanup(self):
        """A signal while removing the now-unneeded rollback links stays
        deferred: it is too late to roll back, so the command succeeds
        with the new image set installed and no leftover links."""
        directory, staged = self.make_images(count=1)

        with crit_main._commit_signal_handlers() as signal_state:
            def during_rollback_cleanup(target):
                return (signal_state["committed"] and
                        "crit-rollback" in target)

            with intercept("unlink", when=during_rollback_cleanup,
                           after=send_signal(signal.SIGTERM)):
                crit_main._commit_staged(staged, True, signal_state)

        self.assertCommitted(staged)
        self.assertNoTransactionFiles(directory)


class MetadataTests(TransactionTestCase):
    """Replacing an image's inode must not lose its metadata."""

    def test_replacement_preserves_mode_owner_and_times(self):
        """The replacement keeps the original's complete Unix ownership
        and permission tuple, including when CRIT runs as root on an
        unprivileged user's checkpoint."""
        directory, _ = self.make_images(count=0)
        path = os.path.join(directory, "owned")
        write(path, b"old")
        # Owner-only, but distinct from mkstemp's 0600 default so a
        # replacement whose mode was never restored cannot pass.
        os.chmod(path, 0o400)
        os.utime(path, ns=(946684800123456789, 978307200987654321))
        if os.geteuid() == 0:
            os.chown(path, 65534, 65534)
        # Compare against a stat snapshot rather than the raw utime values
        # so filesystems with coarser timestamp granularity still pass.
        before = os.stat(path)

        with crit_main._staged_file(path) as (output, staged_path):
            output.write(b"new")
        crit_main._commit_staged([(path, staged_path)], True)

        after = os.stat(path)
        self.assertEqual(stat.S_IMODE(after.st_mode),
                         stat.S_IMODE(before.st_mode))
        self.assertEqual((after.st_uid, after.st_gid),
                         (before.st_uid, before.st_gid))
        self.assertEqual((after.st_atime_ns, after.st_mtime_ns),
                         (before.st_atime_ns, before.st_mtime_ns))

    def test_replacement_preserves_xattrs(self):
        """Replacement keeps ACL/security metadata carried as xattrs."""
        directory, _ = self.make_images(count=0)
        path = os.path.join(directory, "labelled")
        write(path, b"old")
        # user.* is available to unprivileged users on the filesystems
        # normally used by the test; skip only when unsupported.
        try:
            os.setxattr(path, b"user.crit-test", b"preserved")
        except OSError as exc:
            if exc.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP):
                raise
            self.skipTest("filesystem does not support user xattrs")

        with crit_main._staged_file(path) as (output, staged_path):
            output.write(b"new")
        crit_main._commit_staged([(path, staged_path)], True)

        self.assertEqual(os.getxattr(path, b"user.crit-test"), b"preserved")

    def test_metadata_capture_without_xattr_support(self):
        """Filesystems without xattr support must still permit a transform
        when there is no extended metadata to preserve."""
        directory, _ = self.make_images(count=0)
        path = os.path.join(directory, "no-xattrs")
        write(path, b"contents")

        unsupported = OSError(errno.ENOTSUP, "xattrs unsupported")
        with mock.patch.object(crit_main.os, "listxattr",
                               side_effect=unsupported):
            metadata, xattrs = crit_main._capture_file_metadata(path)

        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(xattrs, [])

    def test_noatime_denied_fallback_restores_atime(self):
        """O_NOATIME can be denied when the caller may read but does not
        own an image; the fallback read restores the captured atime."""
        directory, _ = self.make_images(count=0)
        path = os.path.join(directory, "source")
        write(path, b"contents")
        os.utime(path, ns=(946684800123456789, 978307200987654321))
        source_metadata = crit_main._capture_file_metadata(path)
        before = os.stat(path)
        noatime = getattr(os, "O_NOATIME", 0)

        with intercept("open",
                       when=lambda target, flags, *args, **kwargs:
                           flags & noatime,
                       before=raise_(OSError(errno.EPERM,
                                             "injected O_NOATIME denial"))):
            with crit_main._source_file(path, source_metadata) as source:
                self.assertEqual(source.read(), b"contents")

        after = os.stat(path)
        self.assertEqual((after.st_atime_ns, after.st_mtime_ns),
                         (before.st_atime_ns, before.st_mtime_ns))


class CleanupDiagnosticsTests(TransactionTestCase):
    """Cleanup failures must not mask the error that triggered cleanup."""

    def test_cleanup_failure_does_not_mask_primary_error(self):
        directory, staged = self.make_images(count=1)

        stderr = io.StringIO()
        with redirect_stderr(stderr), mock.patch.object(
                crit_main, "_remove_file",
                side_effect=OSError(errno.EIO, "injected cleanup failure")):
            result = crit_main._command_failed(
                "compress",
                ValueError("primary transformation failure"),
                staged)

        self.assertEqual(result, 1)
        diagnostic = stderr.getvalue()
        self.assertIn("primary transformation failure", diagnostic)
        self.assertIn("injected cleanup failure", diagnostic)


class BackupCollisionTests(TransactionTestCase):
    """A prior .bak file is user data and must never be overwritten."""

    def test_existing_backup_is_preserved(self):
        """The complete operation is refused before the first rename."""
        directory, staged = self.make_images(count=1)
        path, staged_path = staged[0]
        backup = path + ".bak"
        write(backup, b"existing backup")

        with self.assertRaisesRegex(crit_main.CritTransformError,
                                    "existing backup"):
            crit_main._commit_staged(staged, False)

        self.assertOriginalsIntact(staged)
        self.assertEqual(read(backup), b"existing backup")
        self.assertFalse(os.path.exists(staged_path))
        self.assertNoTransactionFiles(directory)

    def test_concurrent_backup_creation_wins(self):
        """A backup created by another process after this transaction
        starts must win atomically (link() failing with EEXIST)."""
        directory, staged = self.make_images(count=1)
        path, staged_path = staged[0]
        backup = path + ".bak"

        def racer(source, destination):
            write(destination, b"concurrent backup")

        with intercept("link",
                       when=lambda src, dst: dst.endswith(".bak"),
                       before=racer):
            with self.assertRaisesRegex(crit_main.CritTransformError,
                                        "existing backup"):
                crit_main._commit_staged(staged, False)

        self.assertOriginalsIntact(staged)
        self.assertEqual(read(backup), b"concurrent backup")
        self.assertFalse(os.path.exists(staged_path))
        self.assertNoTransactionFiles(directory)


if __name__ == "__main__":
    unittest.main()
