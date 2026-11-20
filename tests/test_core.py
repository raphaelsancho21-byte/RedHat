import tempfile
import unittest
from pathlib import Path
from redhat.core import sha256, inspect

class SecurityTests(unittest.TestCase):
    def test_hash(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'hello.txt'; f.write_bytes(b'hello')
            self.assertEqual(sha256(f), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    def test_double_extension(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'photo.jpg.exe'; f.write_bytes(b'test')
            r=inspect(f)
            self.assertEqual(r['score'],80)
            self.assertEqual(r['classification'],'suspeito')
    def test_normal(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'photo.jpg'; f.write_bytes(b'test')
            self.assertEqual(inspect(f)['score'],0)

if __name__ == '__main__': unittest.main()
