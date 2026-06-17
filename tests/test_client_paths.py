import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from client import client


class ClientPathTests(unittest.TestCase):
    def test_safe_filename_removes_path_traversal(self):
        self.assertEqual(client.safe_filename("../../secret.pem"), "secret.pem")
        self.assertEqual(client.safe_filename("..\\..\\secret.pem"), "secret.pem")

    def test_receive_path_stays_under_media_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            media_root = Path(tmpdir).resolve()
            with mock.patch.object(client, "MEDIA_ROOT", media_root):
                save_path = client.build_receive_path(
                    "alice/../../", "../bob", "../../secret.pem")

            self.assertTrue(save_path.is_relative_to(media_root))
            self.assertEqual(save_path.name, "secret.pem")
            self.assertNotIn("..", os.fspath(save_path.relative_to(media_root)))


if __name__ == "__main__":
    unittest.main()
