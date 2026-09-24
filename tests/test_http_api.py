import http.client
import io
import json
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from forgetting_evidence.__main__ import main
from forgetting_evidence.requests import RequestStore
from forgetting_evidence.server import create_server


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.server = create_server("127.0.0.1", 0, self.store)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)
        self._tmp.cleanup()

    # -- low level helpers ------------------------------------------------

    def _raw_request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            data = response.read()
            return response.status, data, {k.lower(): v for k, v in response.getheaders()}
        finally:
            conn.close()

    def _json_request(
        self,
        method: str,
        path: str,
        payload: object | None,
        headers: dict[str, str] | None = None,
        *,
        raw: bytes | None = None,
    ) -> tuple[int, object, bytes]:
        sent_headers = {"Content-Type": "application/json"}
        if headers:
            sent_headers.update(headers)
        body = raw if raw is not None else json.dumps(payload).encode("utf-8")
        status, data, _ = self._raw_request(method, path, body, sent_headers)
        try:
            return status, json.loads(data.decode("utf-8")), data
        except ValueError:
            return status, None, data

    def _submit(self, payload=None, headers=None):
        if payload is None:
            payload = {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "scopes": ["email", "profile"],
                "idempotency_key": "key-1",
            }
        return self._json_request("POST", "/requests", payload, headers)

    def _get(self, request_id: str, tenant: str = "tenant-a", via: str = "header"):
        if via == "header":
            return self._json_request(
                "GET", f"/requests/{request_id}", None, {"X-Tenant-ID": tenant}
            )
        return self._json_request(
            "GET", f"/requests/{request_id}?tenant_id={tenant}", None
        )

    # -- acceptance --------------------------------------------------------

    def test_accept_returns_single_line_receipt_in_order_with_newline(self):
        status, parsed, raw = self._submit()
        self.assertEqual(status, 200)
        self.assertTrue(raw.endswith(b"\n"), raw)
        self.assertEqual(raw.count(b"\n"), 1)
        # Exactly one JSON object on the line; keys must appear in
        # contract order.
        text = raw.decode("utf-8").rstrip("\n")
        self.assertEqual(list(json.loads(text)), ["request_id", "status", "created_at"])
        self.assertEqual(set(parsed), {"request_id", "status", "created_at"})
        self.assertEqual(parsed["status"], "accepted")
        uuid.UUID(parsed["request_id"])
        stamp = _parse_utc(parsed["created_at"])
        self.assertEqual(stamp.utcoffset().total_seconds(), 0)

    def test_get_returns_identical_receipt_header_and_query(self):
        _, first, _ = self._submit()
        for via in ("header", "query"):
            status, fetched, raw = self._get(first["request_id"], via=via)
            self.assertEqual(status, 200)
            self.assertEqual(fetched, first)
            self.assertTrue(raw.endswith(b"\n"))

    def test_receipt_persists_across_server_rebuild(self):
        _, first, _ = self._submit()
        self.server.shutdown()
        self.server.server_close()
        rebuilt_store = RequestStore(self.db_path)
        rebuilt = create_server("127.0.0.1", 0, rebuilt_store)
        thread = threading.Thread(target=rebuilt.serve_forever, daemon=True)
        thread.start()
        try:
            old_port = self.port
            self.port = rebuilt.server_address[1]
            try:
                status, fetched, _ = self._get(first["request_id"])
                self.assertEqual(status, 200)
                self.assertEqual(fetched, first)
            finally:
                self.port = old_port
        finally:
            rebuilt.shutdown()
            rebuilt.server_close()
            thread.join(timeout=5)

    def test_scope_order_does_not_change_idempotency(self):
        one = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "scopes": ["email", "profile"],
            "idempotency_key": "key-1",
        }
        two = dict(one, scopes=["profile", "email"])
        status_a, first, _ = self._submit(one)
        status_b, second, _ = self._submit(two)
        self.assertEqual((status_a, status_b), (200, 200))
        self.assertEqual(first, second)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT count(*) FROM requests").fetchone()[0]
        self.assertEqual(count, 1)

    def test_conflict_different_subject_or_scopes(self):
        base = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "scopes": ["email"],
            "idempotency_key": "key-1",
        }
        self.assertEqual(self._submit(base)[0], 200)
        different_subject = dict(base, subject_id="subject-2")
        status, body, raw = self._submit(different_subject)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "idempotency_conflict"})
        self.assertEqual(set(json.loads(raw)), {"error"})

        different_scopes = dict(base, scopes=["email", "billing"])
        status, body, _ = self._submit(different_scopes)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "idempotency_conflict"})

    def test_same_key_distinct_tenants_are_independent(self):
        a = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "scopes": ["email"],
            "idempotency_key": "shared",
        }
        b = dict(a, tenant_id="tenant-b")
        _, first, _ = self._submit(a)
        _, second, _ = self._submit(b)
        self.assertNotEqual(first["request_id"], second["request_id"])

    # -- 400 invalid request ----------------------------------------------

    def test_malformed_json_is_400(self):
        for raw in (b"", b"   ", b"{not json", b"[]", b'"string"', b"null", b"{}garbage"):
            with self.subTest(raw=raw):
                status, body, _ = self._json_request(
                    "POST", "/requests", None, raw=raw
                )
                self.assertEqual(status, 400)
                self.assertEqual(body, {"error": "invalid_request"})

    def test_null_non_string_or_missing_fields_are_400(self):
        good = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "scopes": ["email"],
            "idempotency_key": "key-1",
        }
        bad_bodies = [
            dict(good, tenant_id=""),
            dict(good, tenant_id=None),
            dict(good, tenant_id=7),
            dict(good, tenant_id=["a"]),
            dict(good, subject_id=""),
            dict(good, subject_id=None),
            dict(good, idempotency_key=""),
            dict(good, idempotency_key=False),
            {"subject_id": "s", "scopes": ["email"], "idempotency_key": "k"},
            {"tenant_id": "t", "scopes": ["email"], "idempotency_key": "k"},
            {"tenant_id": "t", "subject_id": "s", "idempotency_key": "k"},
            {"tenant_id": "t", "subject_id": "s", "scopes": ["email"]},
        ]
        for body in bad_bodies:
            with self.subTest(body=body):
                status, parsed, raw = self._submit(body)
                self.assertEqual(status, 400)
                self.assertEqual(parsed, {"error": "invalid_request"})
                self.assertEqual(set(json.loads(raw)), {"error"})
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM requests").fetchone()[0], 0)

    def test_bad_scopes_are_400(self):
        good = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "idempotency_key": "key-1",
        }
        for scopes in ([], ["email", "email"], [""], [7], "email", None, {"a": 1}):
            with self.subTest(scopes=scopes):
                status, body, _ = self._submit(dict(good, scopes=scopes))
                self.assertEqual(status, 400)
                self.assertEqual(body, {"error": "invalid_request"})

    def test_body_tenant_must_match_tenant_header(self):
        status, body, _ = self._submit(
            headers={"X-Tenant-ID": "tenant-other"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid_request"})

    # -- 404 not found -----------------------------------------------------

    def test_missing_malformed_and_cross_tenant_lookups_are_404(self):
        _, first, _ = self._submit()
        missing_status, missing_body, raw = self._get(str(uuid.uuid4()))
        self.assertEqual(missing_status, 404)
        self.assertEqual(missing_body, {"error": "not_found"})
        self.assertEqual(set(json.loads(raw)), {"error"})

        for bad_id in ("not-a-uuid", "", "12345", "%2e%2e"):
            status, body, _ = self._json_request(
                "GET", f"/requests/{bad_id}", None, {"X-Tenant-ID": "tenant-a"}
            )
            self.assertEqual(status, 404, bad_id)
            self.assertEqual(body, {"error": "not_found"})

        status, body, _ = self._get(first["request_id"], tenant="tenant-b")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "not_found"})

    def test_get_without_tenant_scope_is_400(self):
        _, first, _ = self._submit()
        status, body, _ = self._json_request(
            "GET", f"/requests/{first['request_id']}", None
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid_request"})

    def test_conflicting_tenant_scopes_are_400(self):
        _, first, _ = self._submit()
        status, body, _ = self._json_request(
            "GET",
            f"/requests/{first['request_id']}?tenant_id=tenant-b",
            None,
            {"X-Tenant-ID": "tenant-a"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid_request"})

    def test_unknown_paths_are_404(self):
        for method, path, has_body in (
            ("GET", "/", False),
            ("GET", "/healthz", False),
            ("GET", "/requests/", False),
            ("POST", "/other", True),
            ("GET", "/requests/a/b", False),
        ):
            body = b"{}" if has_body else None
            status, parsed, raw = self._json_request(
                method, path, {} if has_body else None, raw=body
            )
            self.assertEqual(status, 404, (method, path))
            self.assertEqual(parsed, {"error": "not_found"})

        # A malformed item token is a not-found once a tenant is in scope.
        status, data, _ = self._raw_request(
            "GET", "/requests/..", headers={"X-Tenant-ID": "tenant-a"}
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(data), {"error": "not_found"})

    # -- 405 method not allowed -------------------------------------------

    def test_unsupported_methods_are_405(self):
        for method, path in (
            ("GET", "/requests"),
            ("PUT", "/requests"),
            ("DELETE", "/requests"),
            ("PUT", f"/requests/{uuid.uuid4()}"),
            ("POST", f"/requests/{uuid.uuid4()}"),
            ("DELETE", f"/requests/{uuid.uuid4()}"),
        ):
            status, parsed, raw = self._json_request(method, path, {})
            self.assertEqual(status, 405, (method, path))
            self.assertEqual(parsed, {"error": "method_not_allowed"})
            self.assertEqual(set(json.loads(raw)), {"error"})

    # -- 503 storage unavailable ------------------------------------------

    def test_corrupted_database_is_503_without_leak(self):
        _, first, _ = self._submit()
        # Simulate on-disk corruption: subsequent calls open fresh
        # connections against the file-backed store.
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database" * 32)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.server")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.WARNING)
        try:
            status, body, raw = self._submit()
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "storage_unavailable"})
        self.assertEqual(set(json.loads(raw)), {"error"})
        for secret in ("subject-1", "email", "profile", "key-1", self.db_path):
            self.assertNotIn(secret, raw.decode())
            self.assertNotIn(secret, stream.getvalue())
        status, body, _ = self._get(first["request_id"])
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "storage_unavailable"})

    # -- concurrency -------------------------------------------------------

    def test_concurrent_same_key_single_record(self):
        payload = json.dumps(
            {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "scopes": ["email", "billing"],
                "idempotency_key": "hot-key",
            }
        ).encode("utf-8")

        def post() -> tuple[int, object]:
            status, parsed, _ = self._json_request(
                "POST", "/requests", None, raw=payload
            )
            return status, parsed

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: post(), range(32)))
        statuses = {status for status, _ in results}
        self.assertEqual(statuses, {200})
        request_ids = {parsed["request_id"] for _, parsed in results}
        self.assertEqual(len(request_ids), 1)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests "
                "WHERE tenant_id = 'tenant-a' AND idempotency_key = 'hot-key'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_concurrent_same_key_different_payloads_one_wins(self):
        def post(subject: str) -> int:
            payload = json.dumps(
                {
                    "tenant_id": "tenant-a",
                    "subject_id": subject,
                    "scopes": ["email"],
                    "idempotency_key": "race-key",
                }
            ).encode("utf-8")
            status, _, raw = self._json_request(
                "POST", "/requests", None, raw=payload
            )
            for secret in (subject, "race-key"):
                self.assertNotIn(secret, raw.decode())
            return status

        with ThreadPoolExecutor(max_workers=16) as pool:
            statuses = list(pool.map(post, ["s1"] * 16 + ["s2"] * 16))
        self.assertIn(200, statuses)
        self.assertTrue(all(status in (200, 409) for status in statuses))
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests "
                "WHERE tenant_id = 'tenant-a' AND idempotency_key = 'race-key'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    # -- leakage -----------------------------------------------------------

    def test_error_bodies_and_logs_do_not_leak_payload(self):
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        secret_key = "key-SECRET"
        first = {
            "tenant_id": "tenant-a",
            "subject_id": secret_subject,
            "scopes": [secret_scope, "email"],
            "idempotency_key": secret_key,
        }
        self.assertEqual(self._submit(first)[0], 200)

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.server")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            status, _, raw = self._submit(dict(first, subject_id="other"))
            self.assertEqual(status, 409)
            self._get(str(uuid.uuid4()))
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        emitted = stream.getvalue()
        for secret in (secret_subject, secret_scope, secret_key, self.db_path):
            self.assertNotIn(secret, raw.decode())
            self.assertNotIn(secret, emitted)


class CliTests(unittest.TestCase):
    def test_health_output_and_exit_unchanged(self):
        output = io.StringIO()
        from contextlib import redirect_stdout

        with redirect_stdout(output):
            code = main(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"service": "forgetting-evidence", "status": "ok"},
        )

    def test_serve_starts_and_serves_over_real_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "evidence.db")
            port = _free_port()
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "forgetting_evidence",
                    "serve",
                    "--db",
                    db_path,
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                payload = json.dumps(
                    {
                        "tenant_id": "tenant-a",
                        "subject_id": "subject-1",
                        "scopes": ["email"],
                        "idempotency_key": "key-1",
                    }
                )
                last_error = None
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                        conn.request(
                            "POST",
                            "/requests",
                            body=payload,
                            headers={"Content-Type": "application/json"},
                        )
                        response = conn.getresponse()
                        data = response.read()
                        conn.close()
                        self.assertEqual(response.status, 200)
                        receipt = json.loads(data)
                        self.assertEqual(
                            set(receipt), {"request_id", "status", "created_at"}
                        )
                        break
                    except (ConnectionError, OSError, http.client.HTTPException) as exc:
                        last_error = exc
                        time.sleep(0.1)
                else:
                    self.fail(f"server never accepted connections: {last_error}")

                # Persistence after the live process served the request.
                self.assertTrue(os.path.exists(db_path))
                store = RequestStore(db_path)
                fetched = store.get("tenant-a", receipt["request_id"])
                self.assertEqual(fetched, receipt)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
                stderr = proc.stderr.read().decode() if proc.stderr else ""
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()
        # No payload or path leakage on stderr.
        self.assertNotIn("subject-1", stderr)
        self.assertNotIn("key-1", stderr)

    def test_serve_with_uncreateable_database_reports_storage_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "a-file")
            with open(blocker, "wb") as handle:
                handle.write(b"x")
            bad_db = os.path.join(blocker, "evidence.db")
            stderr = io.StringIO()
            from contextlib import redirect_stderr

            with redirect_stderr(stderr):
                code = main(
                    ["serve", "--db", bad_db, "--host", "127.0.0.1", "--port", "0"]
                )
            self.assertEqual(code, 1)
            emitted = stderr.getvalue()
            self.assertIn("storage_unavailable", emitted)
            # The unusable path itself must not be printed.
            self.assertNotIn(bad_db, emitted)


if __name__ == "__main__":
    unittest.main()
