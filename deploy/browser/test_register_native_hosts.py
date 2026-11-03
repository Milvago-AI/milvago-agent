"""Run only as root in an owned offline sandbox with SETUID/SETGID test capabilities."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("registration", Path(__file__).with_name("register_native_hosts.py"))
registration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registration)


class NativeHosts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/scratch", prefix="native-hosts-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        image = self.root / "opt/milvago-commercial/milvago-commercial-bridge"
        image.parent.mkdir(parents=True, mode=0o755)
        for parent in [self.root / "opt", image.parent]:
            parent.chmod(0o755)
        image.write_bytes(b"owned non-executable test input\n")
        image.chmod(0o755)
        self.image = image
        self.chromium = "a" * 32
        self.firefox = "browser-enterprise@milvago.app"
        self.old_umask = os.umask(0o077)

    def tearDown(self):
        os.umask(self.old_umask)
        self.temporary.cleanup()

    def register(self):
        registration.register(self.chromium, self.firefox, "/opt/milvago-commercial/milvago-commercial-bridge", root=self.root)

    def _verify_standard_user_access(self, paths):
        """Assertions run after dropping privileges; the caller reports failure to the parent."""
        for path in paths:
            document = json.loads(path.read_text())
            assert document["path"] == "/opt/milvago-commercial/milvago-commercial-bridge"
            assert document.get("allowed_extensions", document.get("allowed_origins")) in [
                [self.firefox], ["chrome-extension://" + self.chromium + "/"],
            ]
            try:
                with path.open("wb"):
                    pass
            except PermissionError:
                pass
            else:
                raise AssertionError("Standard user could replace the manifest")
        for folder in registration.MANAGED:
            path = self.root / folder / (self.firefox + ".json")
            value = json.loads(path.read_text())
            assert value["name"] == self.firefox and value["type"] == "storage" and value["data"] == {}
            try:
                with path.open("wb"):
                    pass
            except PermissionError:
                pass
            else:
                raise AssertionError("Standard user could change managed authority")

    def test_standard_user_can_read_but_not_change_the_installed_manifests(self):
        self.register()
        paths = [self.root / folder / registration.NAME for folder in registration.CHROMIUM + registration.FIREFOX]
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            try:
                os.setgroups([])
                os.setgid(1001)
                os.setuid(1001)
                self._verify_standard_user_access(paths)
                os.write(write, b"passed")
                os._exit(0)
            except BaseException:
                os.write(write, b"failed")
                os._exit(1)
        os.close(write)
        result = os.read(read, 16)
        os.close(read)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(status, 0, "A real UID1001 must read the public manifests without write access")
        self.assertEqual(result, b"passed")
        for path in paths:
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o755)

    def test_registration_repeats_without_handles_or_identity_drift(self):
        self.register()
        paths = [self.root / folder / registration.NAME for folder in registration.CHROMIUM + registration.FIREFOX]
        before = [path.read_bytes() for path in paths]
        handles = len(os.listdir("/proc/self/fd"))
        for _ in range(50):
            self.register()
        self.assertEqual(len(os.listdir("/proc/self/fd")), handles)
        self.assertEqual([path.read_bytes() for path in paths], before)
        for path in paths:
            path.chmod(0o600)
        self.register()
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in paths))

    def test_firefox_managed_configuration_preserves_administrator_authority(self):
        self.register()
        for folder in registration.MANAGED:
            path = self.root / folder / (self.firefox + ".json")
            value = json.loads(path.read_text())
            value["data"] = {"milvago_pin": "administrator-defined-authority"}
            data = json.dumps(value, indent=2).encode("ascii")
            path.write_bytes(data)
            inode = path.stat().st_ino
            for _ in range(10):
                self.register()
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_ino, inode)

    def test_firefox_managed_redirects_unsafe_files_and_malformed_data_are_refused(self):
        self.register()
        path = self.root / registration.MANAGED[0] / (self.firefox + ".json")
        original = path.read_bytes()
        marker = self.root / "managed-marker"
        marker.write_bytes(b"unchanged")
        for kind in ["symlink", "hardlink", "fifo", "writable", "private", "invalid", "oversized", "wrong_identity", "wrong_storage", "wrong_data", "bad_description"]:
            path.unlink()
            if kind == "symlink":
                path.symlink_to(marker)
            elif kind == "hardlink":
                os.link(marker, path)
            elif kind == "fifo":
                os.mkfifo(path)
            else:
                data = b"[]" if kind == "invalid" else b" " * 65537 if kind == "oversized" else original
                if kind in ["wrong_identity", "wrong_storage", "wrong_data", "bad_description"]:
                    value = json.loads(original)
                    key, replacement = {"wrong_identity": ("name", "other@milvago.app"), "wrong_storage": ("type", "stdio"), "wrong_data": ("data", []), "bad_description": ("description", {"image": "invalid"})}[kind]
                    value[key] = replacement
                    data = json.dumps(value).encode("ascii")
                path.write_bytes(data)
                path.chmod(0o666 if kind == "writable" else 0o600 if kind == "private" else 0o644)
            with self.assertRaises((PermissionError, OSError, ValueError)):
                self.register()
            self.assertEqual(marker.read_bytes(), b"unchanged")

    def test_concurrent_administrator_configuration_is_not_replaced(self):
        configured = {"name": self.firefox, "description": "Administrator configuration", "type": "storage",
                      "data": {"milvago_pin": "concurrent-administrator-authority"}}
        encoded = json.dumps(configured, indent=2).encode("ascii")

        def administrator_wins(source, destination, *, src_dir_fd, dst_dir_fd, follow_symlinks):
            self.assertEqual(src_dir_fd, dst_dir_fd)
            self.assertFalse(follow_symlinks)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=dst_dir_fd)
            with os.fdopen(fd, "wb") as output:
                output.write(encoded)
                os.fchmod(output.fileno(), 0o644)
            raise FileExistsError("concurrent trusted administrator")

        with patch.object(registration.os, "link", side_effect=administrator_wins):
            self.register()
        for folder in registration.MANAGED:
            directory = self.root / folder
            self.assertEqual((directory / (self.firefox + ".json")).read_bytes(), encoded)
            self.assertEqual(list(directory.glob(".milvago-managed-*")), [])

    def test_existing_private_shared_managed_directory_is_never_opened_to_other_users(self):
        self.register()
        directory = self.root / registration.MANAGED[0]
        other = directory / "another-extension.json"
        other.write_bytes(b"administrator-private-configuration")
        other.chmod(0o644)
        directory.chmod(0o700)
        with self.assertRaises(PermissionError):
            self.register()
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(other.read_bytes(), b"administrator-private-configuration")

    def test_existing_private_native_host_directory_preserves_other_administrator_files(self):
        self.register()
        for relative in registration.CHROMIUM + registration.FIREFOX:
            directory = self.root / relative
            other = directory / "another-application.json"
            other.write_bytes(b"administrator-private-configuration")
            other.chmod(0o644)
            directory.chmod(0o700)
            with self.assertRaises(PermissionError):
                self.register()
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(other.read_bytes(), b"administrator-private-configuration")
            directory.chmod(0o755)

    def test_untrusted_manifest_entries_are_refused_without_overwriting_them(self):
        self.register()
        path = self.root / registration.CHROMIUM[0] / registration.NAME
        original = path.read_bytes()
        marker = self.root / "unrelated.txt"
        marker.write_bytes(b"unchanged")
        for kind in ["symlink", "hardlink", "fifo", "writable"]:
            path.unlink()
            if kind == "symlink":
                path.symlink_to(marker)
            elif kind == "hardlink":
                os.link(marker, path)
            elif kind == "fifo":
                os.mkfifo(path)
            else:
                path.write_bytes(original)
                path.chmod(0o666)
            with self.assertRaises((PermissionError, OSError)):
                self.register()
            self.assertEqual(marker.read_bytes(), b"unchanged")
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o644)

    def test_untrusted_ancestors_and_images_are_refused(self):
        self.image.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.register()
        self.image.chmod(0o755)
        image_content = self.image.read_bytes()
        self.image.unlink()
        marker = self.root / "image-marker"
        marker.write_bytes(image_content)
        self.image.symlink_to(marker)
        with self.assertRaises(OSError):
            self.register()
        self.image.unlink()
        self.image.write_bytes(image_content)
        self.image.chmod(0o755)
        (self.root / "etc").mkdir(mode=0o777)
        (self.root / "etc").chmod(0o777)
        with self.assertRaises(PermissionError):
            self.register()
        (self.root / "etc").chmod(0o700)
        with self.assertRaises(PermissionError):
            self.register()

    def test_invalid_inputs_never_select_a_program_or_an_extension(self):
        for chromium, firefox, binary in [
            ("image", self.firefox, str(self.image)),
            (self.chromium, "../extension", str(self.image)),
            (self.chromium, self.firefox, "/bin/sh"),
            (self.chromium, self.firefox, "/opt/milvago-commercial/../malicious"),
            ({"image": "invalid"}, self.firefox, str(self.image)),
            (self.chromium, {"image": "invalid"}, str(self.image)),
        ]:
            with self.assertRaises(ValueError):
                registration.register(chromium, firefox, binary, root=self.root)


if __name__ == "__main__":
    assert os.geteuid() == 0 and Path("/scratch").is_dir()
    unittest.main(verbosity=2)
