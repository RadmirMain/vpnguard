#!/usr/bin/env python3
"""
Tests for fail-safe Wi-Fi pause timer helpers and state cleanup in vpnguard.py.
"""
import argparse
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

import vpnguard


class TestPauseResume(unittest.TestCase):
    def test_read_pause_until_missing_and_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pfile = os.path.join(tmpdir, "pause_until")
            self.assertIsNone(vpnguard._read_pause_until(pfile))

            with open(pfile, "w", encoding="utf-8") as f:
                f.write("not-a-number\n")
            self.assertIsNone(vpnguard._read_pause_until(pfile))

            target = int(time.time()) + 300
            with open(pfile, "w", encoding="utf-8") as f:
                f.write(f"{target}\n")
            self.assertEqual(vpnguard._read_pause_until(pfile), target)

    def test_clear_pause_state_removes_files_without_killing_unrelated_pid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pfile = os.path.join(tmpdir, "pause_until")
            pidfile = os.path.join(tmpdir, "pause_watcher.pid")
            with open(pfile, "w", encoding="utf-8") as f:
                f.write("1999999999\n")
            with open(pidfile, "w", encoding="utf-8") as f:
                f.write(f"{os.getpid()}\n")

            vpnguard._clear_pause_state(run_dir=tmpdir, kill_watcher=True)
            self.assertFalse(os.path.exists(pfile))
            self.assertFalse(os.path.exists(pidfile))

    def test_cmd_pause_reuses_alive_watcher_without_spawning_duplicate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pfile = os.path.join(tmpdir, "pause_until")
            pidfile = os.path.join(tmpdir, "pause_watcher.pid")
            with mock.patch.object(vpnguard, "RUN_DIR", tmpdir), \
                 mock.patch.object(vpnguard, "PAUSE_UNTIL_FILE", pfile), \
                 mock.patch.object(vpnguard, "PAUSE_WATCHER_PID_FILE", pidfile), \
                 mock.patch("os.geteuid", return_value=0), \
                 mock.patch.object(vpnguard, "_disable_protection_core"), \
                 mock.patch.object(vpnguard, "_is_pause_watcher_alive", return_value=42424), \
                 mock.patch("subprocess.Popen") as popen_mock:
                rc = vpnguard.cmd_pause(argparse.Namespace(seconds=300))

            self.assertEqual(rc, 0)
            popen_mock.assert_not_called()
            saved_ts = vpnguard._read_pause_until(pfile)
            self.assertIsNotNone(saved_ts)
            self.assertGreater(saved_ts, int(time.time()) + 250)

    def test_cmd_pause_spawns_single_watcher_when_none_alive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pfile = os.path.join(tmpdir, "pause_until")
            pidfile = os.path.join(tmpdir, "pause_watcher.pid")
            fake_proc = mock.MagicMock()
            fake_proc.pid = 51515
            with mock.patch.object(vpnguard, "RUN_DIR", tmpdir), \
                 mock.patch.object(vpnguard, "PAUSE_UNTIL_FILE", pfile), \
                 mock.patch.object(vpnguard, "PAUSE_WATCHER_PID_FILE", pidfile), \
                 mock.patch("os.geteuid", return_value=0), \
                 mock.patch.object(vpnguard, "_disable_protection_core"), \
                 mock.patch.object(vpnguard, "_is_pause_watcher_alive", return_value=None), \
                 mock.patch("subprocess.Popen", return_value=fake_proc) as popen_mock:
                rc = vpnguard.cmd_pause(argparse.Namespace(seconds=300))

            self.assertEqual(rc, 0)
            popen_mock.assert_called_once()
            with open(pidfile, "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "51515")

    def test_cmd_resume_if_expired_only_arms_when_expired(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pfile = os.path.join(tmpdir, "pause_until")
            pidfile = os.path.join(tmpdir, "pause_watcher.pid")
            with open(pfile, "w", encoding="utf-8") as f:
                f.write(f"{int(time.time()) + 120}\n")

            with mock.patch.object(vpnguard, "RUN_DIR", tmpdir), \
                 mock.patch.object(vpnguard, "PAUSE_UNTIL_FILE", pfile), \
                 mock.patch.object(vpnguard, "PAUSE_WATCHER_PID_FILE", pidfile), \
                 mock.patch("os.geteuid", return_value=0), \
                 mock.patch.object(vpnguard, "cmd_on", return_value=0) as cmd_on_mock:
                rc = vpnguard.cmd_resume_if_expired(argparse.Namespace())
                self.assertEqual(rc, 0)
                cmd_on_mock.assert_not_called()

                # Now expire timestamp
                with open(pfile, "w", encoding="utf-8") as f:
                    f.write(f"{int(time.time()) - 5}\n")
                with mock.patch.object(vpnguard, "notify"):
                    rc = vpnguard.cmd_resume_if_expired(argparse.Namespace())
                self.assertEqual(rc, 0)
                cmd_on_mock.assert_called_once()

    def test_acquire_state_lock_is_reentrant_and_nonblocking_on_contention(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = os.path.join(tmpdir, "state.lock")
            with mock.patch.object(vpnguard, "RUN_DIR", tmpdir), \
                 mock.patch.object(vpnguard, "STATE_LOCK_PATH", lock_path), \
                 mock.patch.object(vpnguard, "_STATE_LOCK_DEPTH", 0), \
                 mock.patch.object(vpnguard, "_STATE_LOCK_FD", None):
                with vpnguard.acquire_state_lock(timeout=1.0):
                    self.assertEqual(vpnguard._STATE_LOCK_DEPTH, 1)
                    # Nested re-entrant acquisition must succeed without deadlock
                    with vpnguard.acquire_state_lock(timeout=0.1):
                        self.assertEqual(vpnguard._STATE_LOCK_DEPTH, 2)
                    self.assertEqual(vpnguard._STATE_LOCK_DEPTH, 1)
                self.assertEqual(vpnguard._STATE_LOCK_DEPTH, 0)
                self.assertIsNone(vpnguard._STATE_LOCK_FD)

                # External LOCK_EX must trigger TimeoutError cleanly
                ext_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
                try:
                    fcntl.flock(ext_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(TimeoutError):
                        with vpnguard.acquire_state_lock(timeout=0.15):
                            pass
                finally:
                    fcntl.flock(ext_fd, fcntl.LOCK_UN)
                    os.close(ext_fd)

                # Lock is acquirable again after contention clears
                with vpnguard.acquire_state_lock(timeout=0.5):
                    self.assertEqual(vpnguard._STATE_LOCK_DEPTH, 1)


if __name__ == "__main__":
    unittest.main()
