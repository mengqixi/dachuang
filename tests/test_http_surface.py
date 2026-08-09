import unittest

from app import app


class HttpSurfaceTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_index_is_served(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<!DOCTYPE html>", response.data)
        response.close()

    def test_repository_files_are_not_public_static_assets(self):
        for path in (
            "/.env.example",
            "/.git/HEAD",
            "/app.py",
            "/config/security.yaml",
            "/data/system.db",
            "/src/main.py",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)
                response.close()


if __name__ == "__main__":
    unittest.main()
