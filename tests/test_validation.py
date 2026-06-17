import unittest

from common import encryption, validation


class ValidationTests(unittest.TestCase):
    def test_usernames_are_restricted(self):
        self.assertTrue(validation.is_safe_username("alice_1"))
        self.assertFalse(validation.is_safe_username("../alice"))
        self.assertFalse(validation.is_safe_username("alice/bob"))

    def test_transfer_filename_blocks_dangerous_extensions(self):
        self.assertFalse(validation.is_safe_transfer_filename("payload.exe"))
        self.assertFalse(validation.is_safe_transfer_filename("script.ps1"))
        self.assertTrue(validation.is_safe_transfer_filename("notes.txt"))

    def test_transfer_filename_rejects_paths(self):
        self.assertFalse(validation.is_safe_transfer_filename("../../notes.txt"))
        self.assertFalse(validation.is_safe_transfer_filename(r"subdir\notes.txt"))

    def test_frame_size_allows_configured_file_payloads(self):
        self.assertGreater(encryption.MAX_FRAME_SIZE, encryption.MAX_FILE_SIZE)
        self.assertLessEqual(encryption.MAX_FRAME_SIZE, 8 * 1024**2)


if __name__ == "__main__":
    unittest.main()
