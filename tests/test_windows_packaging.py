"""Windows installer packaging: static guarantees + (opt-in) built-artefact checks.

Static checks run everywhere. Set HM_WIN_INSTALLER_CONTENTS to the
``*.contents.sha256`` written by packaging/windows/build-windows.sh to also
check a built installer's file list (the CI packaging job does this).
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WIN = ROOT / "packaging" / "windows"


class StaticPackagingTests(unittest.TestCase):
    def test_inputs_are_pinned_by_sha256(self):
        rows = [l.split() for l in (WIN / "inputs.sha256").read_text().splitlines()
                if l.strip() and not l.startswith("#")]
        self.assertGreaterEqual(len(rows), 8)
        for digest, name in rows:
            self.assertRegex(digest, r"^[0-9a-f]{64}$", name)
        names = {n for _, n in rows}
        script = (WIN / "build-windows.sh").read_text()
        for whl in re.findall(r"[\w.-]+\.whl", script):
            self.assertIn(whl, names, f"{whl} used by the build but not pinned")
        self.assertIn("holochain-x86_64-pc-windows-msvc.exe", names)
        self.assertIn("pinned \"$src\"", script)
        self.assertIn("pinned \"$HM_WIN_PYTHON\"", script)

    def test_holochain_version_is_the_linux_one(self):
        # Same conductor release as the .deb; no silent upgrade.
        notes = (WIN / "inputs.sha256").read_text()
        self.assertIn("holochain-0.7.0", notes)
        self.assertIn("Holochain 0.7.0", notes)
        self.assertIn('holo_hash = "=0.7.0"', (ROOT / "music-e2e" / "Cargo.toml").read_text())

    def test_firewall_rules_are_private_profile_program_rules_only(self):
        nsi = (WIN / "installer.nsi").read_text()
        adds = re.findall(r"netsh advfirewall firewall add rule[^\n']*", nsi)
        self.assertTrue(adds)
        for rule in adds:
            self.assertIn("profile=private", rule)
            self.assertIn('program="$INSTDIR\\bin\\', rule)
            self.assertNotRegex(rule, r"profile=(any|public|domain)")
        self.assertNotRegex(nsi.lower(), r"set\s+(allprofiles|currentprofile)\s+state\s+off")
        self.assertNotRegex(nsi.lower(), r"smartscreen|disableantispyware|realtimeprotection")

    def test_uninstall_and_upgrade_never_touch_user_data(self):
        nsi = (WIN / "installer.nsi").read_text()
        for line in nsi.splitlines():
            if re.search(r"\b(RMDir|Delete)\b", line):
                self.assertNotIn("LOCALAPPDATA", line.upper().replace("$", ""), line)
                self.assertNotIn("APPDATA", line.upper(), line)
                self.assertNotIn("$PROFILE", line, line)
                if "RMDir /r" in line:
                    self.assertRegex(line, r'RMDir /r "\$INSTDIR\\(runtime|python|bin|docs|licenses)"', line)
        self.assertIn("NOT deleted", nsi)

    def test_installer_is_marked_unsigned_and_private(self):
        nsi = (WIN / "installer.nsi").read_text()
        self.assertIn("unsigned development build", nsi)
        notice = (WIN / "PRIVATE-TEST-NOTICE.txt").read_text()
        self.assertIn("UNSIGNED PRIVATE TEST BUILD", notice)
        self.assertIn("Do not turn off SmartScreen", notice)

    def test_launcher_runs_isolated_utf8_bundled_interpreter(self):
        c = (WIN / "launcher.c").read_text()
        self.assertIn('-I -X utf8 -m holochain_music', c)
        self.assertIn("runtime\\\\%ls", c)
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", c)
        self.assertNotIn("cmd.exe", c)
        self.assertNotIn("ShellExecute", c)

    def test_asio_portaudio_and_lair_are_not_shipped(self):
        script = (WIN / "build-windows.sh").read_text()
        self.assertIn("! -name libportaudio64bit.dll", script)
        self.assertNotIn("lair-keystore", script)
        third = (WIN / "THIRD-PARTY.txt").read_text()
        self.assertIn("CAL-1.0", third)
        self.assertIn("licensing review incomplete", third)

    def test_icon_is_a_valid_multi_size_ico(self):
        out = Path(tempfile.mkdtemp()) / "x.ico"
        subprocess.run([sys.executable, str(WIN / "make_icon.py"), str(out)], check=True)
        data = out.read_bytes()
        reserved, kind, count = struct.unpack("<HHH", data[:6])
        self.assertEqual((reserved, kind, count), (0, 1, 6))
        for i in range(count):
            w, h, _, _, planes, bpp, size, offset = struct.unpack("<BBBBHHII", data[6 + 16 * i: 22 + 16 * i])
            self.assertEqual(data[offset:offset + 8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(bpp, 32)
        again = Path(tempfile.mkdtemp()) / "y.ico"
        subprocess.run([sys.executable, str(WIN / "make_icon.py"), str(again)], check=True)
        self.assertEqual(data, again.read_bytes(), "icon generation must be deterministic")


@unittest.skipUnless(os.environ.get("HM_WIN_INSTALLER_CONTENTS"), "set HM_WIN_INSTALLER_CONTENTS")
class BuiltInstallerTests(unittest.TestCase):
    def setUp(self):
        rows = Path(os.environ["HM_WIN_INSTALLER_CONTENTS"]).read_text().splitlines()
        self.files = {r.split("  ", 1)[1] for r in rows if r.strip()}

    def test_required_components(self):
        for f in ("HolochainMusic.exe", "holochain-music.exe", "holochain_music.happ",
                  "bin/holochain.exe", "bin/hc.exe", "bin/kitsune2-bootstrap-srv.exe",
                  "bin/holochain-music-moq.exe", "bin/music_app_bridge.exe", "bin/vcruntime140.dll",
                  "runtime/pythonw.exe", "runtime/python.exe", "runtime/python314._pth",
                  "runtime/Lib/site-packages/_sounddevice_data/portaudio-binaries/libportaudio64bit.dll",
                  "python/holochain_music/cli.py", "python/holochain_storage/portable.py",
                  "python/music_catalogue/audio_output.py", "python/holochain_music/ui/index.html",
                  "licenses/holochain-CAL-1.0.txt", "licenses/THIRD-PARTY.txt", "PRIVATE-TEST-NOTICE.txt",
                  "docs/windows-installation.md", "docs/windows-lan-test-plan.md"):
            self.assertIn(f, self.files)

    def test_nothing_unreviewed(self):
        self.assertFalse([f for f in self.files if "asio" in f.lower()])
        self.assertFalse([f for f in self.files if "lair-keystore" in f])
        self.assertFalse([f for f in self.files if f.endswith((".pem", ".key", ".passphrase"))])
        self.assertFalse([f for f in self.files if "__pycache__" in f or "/tests/" in f])


if __name__ == "__main__":
    unittest.main()
