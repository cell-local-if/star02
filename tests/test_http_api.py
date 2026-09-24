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
import unittest
import uuid
from contextlib import redirect_stderr
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence import httpapi
from forgetting_evidence.httpapi import build_server, make_handler
from forgetting_evidence.requests import RequestStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")


def _parse_utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ServerFixture:
    def __init__(self, store, host="127.0.0.1", port=0):
        self.server = build_server(store, host, port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class HttpAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self._fixture = ServerFixture(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    # -- helpers -------------------------------------------------------

    def _request(self, method, path, body=None, headers=None, raw_body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            kwargs = {}
            if raw_body is not None:
                kwargs["body"] = raw_body
            elif body is not None:
                kwargs["body"] = json.dumps(body)
            conn.request(method, path, headers=headers or {}, **kwargs)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def _submit(self, payload=None, tenant="tenant-a"):
        payload = payload or {
            "tenant_id": tenant,
            "subject_id": "subject-1",
            "idempotency_key": "key-1",
            "scopes": ["email", "profile"],
        }
        return self._request("POST", "/requests", body=payload)

    # -- acceptance ----------------------------------------------------

    def test_submit_success_single_line_receipt(self):
        status, headers, data = self._submit()
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        # Field order is fixed as request_id, status, created_at.
        self.assertTrue(
            data.startswith(b'{"request_id":"'), data
        )
        receipt = json.loads(data)
        self.assertEqual(
            list(receipt), ["request_id", "status", "created_at"]
        )
        self.assertEqual(set(receipt), {"request_id", "status", "created_at"})
        self.assertEqual(receipt["status"], "accepted")
        uuid.UUID(receipt["request_id"])
        parsed = _parse_utc(receipt["created_at"])
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_get_returns_byte_identical_receipt(self):
        post_status, _, post_data = self._submit()
        self.assertEqual(post_status, 200)
        status, headers, data = self._request(
            "GET",
            f"/requests/{json.loads(post_data)['request_id']}",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, post_data)
        # Query parameter is accepted too and yields the same bytes.
        request_id = json.loads(post_data)["request_id"]
        status2, _, data2 = self._request(
            "GET", f"/requests/{request_id}?tenant_id=tenant-a"
        )
        self.assertEqual(status2, 200)
        self.assertEqual(data2, post_data)
        # Upper-case UUID spelling canonicalises to the stored row.
        status3, _, data3 = self._request(
            "GET",
            f"/requests/{request_id.upper()}",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status3, 200)
        self.assertEqual(data3, post_data)

    def test_get_remains_frozen_after_storage_layer_transition(self):
        # Advancing state happens only on the storage layer; the HTTP
        # lookup must keep serving the byte-identical accepted receipt and
        # no status endpoint must appear.
        _, _, post_data = self._submit()
        receipt = json.loads(post_data)
        self.store.transition(
            "tenant-a", receipt["request_id"], "processing"
        )
        self.store.transition(
            "tenant-a", receipt["request_id"], "completed"
        )
        # Storage layer sees the terminal state...
        self.assertEqual(
            self.store.get_status(
                "tenant-a", receipt["request_id"]
            )["status"],
            "completed",
        )
        # ...but the HTTP query is unchanged from acceptance.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, post_data)
        self.assertEqual(json.loads(data)["status"], "accepted")
        # Idempotent POST replay is likewise the frozen accepted receipt.
        replay_status, _, replay_data = self._submit(
            {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "idempotency_key": "key-1",
                "scopes": ["profile", "email"],
            }
        )
        self.assertEqual(replay_status, 200)
        self.assertEqual(replay_data, post_data)
        # No status route is exposed: a status sub-resource is 404.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}/status",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')
        # PATCH/PUT to advance state over HTTP stay 405.
        for method in ("PATCH", "PUT"):
            status, _, _ = self._request(
                method,
                f"/requests/{receipt['request_id']}",
                body=json.dumps({"status": "processing"}),
                headers={"X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 405)


    def test_receipt_byte_stable_across_server_rebuild(self):
        _, _, first_data = self._submit()
        receipt = json.loads(first_data)
        self._fixture.__exit__(None, None, None)
        rebuilt_store = RequestStore(self.db_path)
        with ServerFixture(rebuilt_store) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "GET",
                    f"/requests/{receipt['request_id']}",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                data = conn.getresponse().read()
            finally:
                conn.close()
        self.assertEqual(data, first_data)

    # -- idempotency ---------------------------------------------------

    def test_scope_order_does_not_change_idempotent_replay(self):
        _, _, first = self._submit()
        status, _, second = self._submit(
            {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "idempotency_key": "key-1",
                "scopes": ["profile", "email"],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests "
                "WHERE tenant_id = 'tenant-a' AND idempotency_key = 'key-1'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_conflict_on_different_subject_or_scopes(self):
        self._submit()
        for payload in (
            {
                "tenant_id": "tenant-a",
                "subject_id": "subject-2",
                "idempotency_key": "key-1",
                "scopes": ["email", "profile"],
            },
            {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "idempotency_key": "key-1",
                "scopes": ["email"],
            },
        ):
            with self.subTest(payload=payload):
                status, _, data = self._submit(payload)
                self.assertEqual(status, 409)
                self.assertEqual(data, b'{"error":"idempotency_conflict"}\n')
                self.assertEqual(set(json.loads(data)), {"error"})

    def test_same_key_distinct_tenants_are_independent(self):
        status_a, _, data_a = self._submit(
            {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "idempotency_key": "shared",
                "scopes": ["email"],
            }
        )
        status_b, _, data_b = self._submit(
            {
                "tenant_id": "tenant-b",
                "subject_id": "subject-1",
                "idempotency_key": "shared",
                "scopes": ["email"],
            }
        )
        self.assertEqual((status_a, status_b), (200, 200))
        self.assertNotEqual(json.loads(data_a)["request_id"],
                            json.loads(data_b)["request_id"])

    def test_concurrent_same_key_persists_one_record(self):
        payload = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "idempotency_key": "hot-key",
            "scopes": ["email", "billing"],
        }

        def post():
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
            try:
                conn.request("POST", "/requests", body=json.dumps(payload))
                resp = conn.getresponse()
                return resp.status, resp.read()
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: post(), range(32)))
        self.assertTrue(all(status == 200 for status, _ in results))
        bodies = {data for _, data in results}
        self.assertEqual(len(bodies), 1)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests "
                "WHERE tenant_id = 'tenant-a' AND idempotency_key = 'hot-key'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    # -- 400 invalid request -------------------------------------------

    def test_malformed_json_is_400(self):
        for raw in (b"{not json", b"", b"[1,2,3]", b'"a string"', b"null", b"12"):
            with self.subTest(raw=raw):
                status, _, data = self._request(
                    "POST",
                    "/requests",
                    raw_body=raw,
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(status, 400)
                self.assertEqual(data, b'{"error":"invalid_request"}\n')
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM requests").fetchone()[0], 0)

    def test_invalid_field_types_are_400(self):
        base = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "idempotency_key": "key-1",
            "scopes": ["email"],
        }
        bad_bodies = []
        for field in ("tenant_id", "subject_id", "idempotency_key"):
            for value in (None, "", 7, True, ["x"], {"x": 1}):
                body = dict(base)
                body[field] = value
                bad_bodies.append(body)
        for body in bad_bodies:
            with self.subTest(body=body):
                status, _, data = self._submit(body)
                self.assertEqual(status, 400)
                self.assertEqual(data, b'{"error":"invalid_request"}\n')
        for field in ("tenant_id", "subject_id", "idempotency_key", "scopes"):
            body = dict(base)
            del body[field]
            with self.subTest(missing=field):
                status, _, data = self._submit(body)
                self.assertEqual(status, 400)
                self.assertEqual(data, b'{"error":"invalid_request"}\n')
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM requests").fetchone()[0], 0)

    def test_invalid_scopes_are_400(self):
        base = {
            "tenant_id": "tenant-a",
            "subject_id": "subject-1",
            "idempotency_key": "key-1",
        }
        for scopes in (
            [],
            ["email", "email"],
            ["email", 7],
            [None],
            [""],
            "email",
            {"email": 1},
            None,
            123,
        ):
            with self.subTest(scopes=scopes):
                status, _, data = self._submit({**base, "scopes": scopes})
                self.assertEqual(status, 400)
                self.assertEqual(data, b'{"error":"invalid_request"}\n')
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM requests").fetchone()[0], 0)

    def test_missing_tenant_on_get_is_400(self):
        _, _, post_data = self._submit()
        request_id = json.loads(post_data)["request_id"]
        status, _, data = self._request("GET", f"/requests/{request_id}")
        self.assertEqual(status, 400)
        self.assertEqual(data, b'{"error":"invalid_request"}\n')

    # -- 404 not found --------------------------------------------------

    def test_missing_malformed_and_cross_tenant_ids_are_404(self):
        _, _, post_data = self._submit()
        request_id = json.loads(post_data)["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        paths_and_headers = [
            (f"/requests/{unknown}", {"X-Tenant-Id": "tenant-a"}),
            (f"/requests/{request_id}", {"X-Tenant-Id": "tenant-b"}),
            (f"/requests/{request_id}?tenant_id=tenant-b", {}),
            ("/requests/not-a-uuid", {"X-Tenant-Id": "tenant-a"}),
            ("/requests/123", {"X-Tenant-Id": "tenant-a"}),
            ("/requests/", {"X-Tenant-Id": "tenant-a"}),
            ("/requests", {"X-Tenant-Id": "tenant-a"}),  # GET on collection is 405, skip
        ]
        for index, (path, headers) in enumerate(paths_and_headers[:-1]):
            with self.subTest(index=index, path=path):
                status, _, data = self._request("GET", path, headers=headers)
                self.assertEqual(status, 404)
                self.assertEqual(data, b'{"error":"not_found"}\n')
                self.assertEqual(set(json.loads(data)), {"error"})

    def test_unknown_paths_are_404(self):
        for method in ("GET", "POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, _, data = self._request(method, "/nothing/here")
                self.assertEqual(status, 404)
                self.assertEqual(data, b'{"error":"not_found"}\n')

    # -- 405 method not allowed ----------------------------------------

    def test_unsupported_methods_on_known_paths_are_405(self):
        _, _, post_data = self._submit()
        request_id = json.loads(post_data)["request_id"]
        cases = [
            ("GET", "/requests"),
            ("PUT", "/requests"),
            ("DELETE", "/requests"),
            ("PATCH", "/requests"),
            ("OPTIONS", "/requests"),
            ("POST", f"/requests/{request_id}"),
            ("PUT", f"/requests/{request_id}"),
        ]
        for method, path in cases:
            with self.subTest(method=method, path=path):
                status, headers, data = self._request(method, path)
                self.assertEqual(status, 405)
                self.assertEqual(data, b'{"error":"method_not_allowed"}\n')
                self.assertEqual(set(json.loads(data)), {"error"})

    def test_head_has_no_body_but_sets_length(self):
        status, headers, data = self._request("HEAD", "/requests")
        self.assertEqual(status, 405)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("Content-Length"),
                         str(len(b'{"error":"method_not_allowed"}\n')))
        status, headers, data = self._request("HEAD", "/unknown")
        self.assertEqual(status, 404)
        self.assertEqual(data, b"")

    def test_unknown_verb_honours_path_routing(self):
        for path, expected in (("/requests", 405), ("/nope", 404)):
            with self.subTest(path=path):
                with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
                    sock.sendall(
                        f"FROBNICATE {path} HTTP/1.1\r\nHost: x\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    raw = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                status_line = raw.split(b"\r\n", 1)[0].decode()
                self.assertIn(str(expected), status_line)
                self.assertIn(b'"error"', raw)

    # -- 503 storage unavailable ---------------------------------------

    def test_corrupt_database_returns_503(self):
        _, _, post_data = self._submit()
        request_id = json.loads(post_data)["request_id"]
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is definitely not a sqlite database")
        status, _, data = self._request(
            "GET",
            f"/requests/{request_id}",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 503)
        self.assertEqual(data, b'{"error":"storage_unavailable"}\n')
        status, _, data = self._submit(
            {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "idempotency_key": "key-2",
                "scopes": ["email"],
            }
        )
        self.assertEqual(status, 503)
        self.assertEqual(data, b'{"error":"storage_unavailable"}\n')

    def test_store_exception_becomes_503_without_leak(self):
        secret_sql = "database is locked SECRET-SQL-DETAIL"

        class BrokenStore:
            def submit(self, *a, **k):
                raise sqlite3.OperationalError(secret_sql)

            def get(self, *a, **k):
                raise RuntimeError(secret_sql + "-PATH")

        handler = make_handler(BrokenStore())

        class _Server(threading.Thread):
            def __init__(self):
                super().__init__(daemon=True)
                from http.server import ThreadingHTTPServer

                self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
                self.httpd.daemon_threads = True
                self.port = self.httpd.server_address[1]

            def run(self):
                self.httpd.serve_forever()

        server = _Server()
        server.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
            conn.request(
                "POST",
                "/requests",
                body=json.dumps(
                    {
                        "tenant_id": "tenant-a",
                        "subject_id": "subject-1",
                        "idempotency_key": "key-1",
                        "scopes": ["email"],
                    }
                ),
            )
            resp = conn.getresponse()
            post_data = resp.read()
            self.assertEqual(resp.status, 503)
            self.assertNotIn(b"SECRET", post_data)
            conn.request(
                "GET",
                "/requests/00000000-0000-4000-8000-000000000000",
                headers={"X-Tenant-Id": "tenant-a"},
            )
            resp = conn.getresponse()
            get_data = resp.read()
            self.assertEqual(resp.status, 503)
            self.assertNotIn(b"SECRET", get_data)
            conn.close()
        finally:
            server.httpd.shutdown()
            server.httpd.server_close()

    # -- no-leak / headers ----------------------------------------------

    def test_responses_and_logs_do_not_leak_payload(self):
        secret_subject = "subject-SECRETXYZ"
        secret_scope = "scope-SECRETXYZ"
        secret_key = "key-SECRETXYZ"
        good = {
            "tenant_id": "tenant-a",
            "subject_id": secret_subject,
            "idempotency_key": secret_key,
            "scopes": [secret_scope, "email"],
        }
        _, _, post_data = self._submit(good)
        self.assertNotIn(secret_subject.encode(), post_data)
        self.assertNotIn(secret_scope.encode(), post_data)
        self.assertNotIn(secret_key.encode(), post_data)

        bad = dict(good)
        bad["subject_id"] = "other-subject"
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.WARNING)
        stderr = io.StringIO()
        try:
            with redirect_stderr(stderr):
                # Trigger a 409.
                self._submit(bad)
                # Trigger a 503 by corrupting the database.
                with open(self.db_path, "wb") as handle:
                    handle.write(b"garbage")
                self._request(
                    "GET",
                    f"/requests/{json.loads(post_data)['request_id']}",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        emitted = stream.getvalue() + stderr.getvalue()
        self.assertNotIn(secret_subject, emitted)
        self.assertNotIn(secret_scope, emitted)
        self.assertNotIn(secret_key, emitted)
        self.assertNotIn(self.db_path, emitted)

    def test_keepalive_connection_frames_multiple_requests(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            # Submit, replay, error and lookup over one reused connection.
            payload = {
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "idempotency_key": "keep-alive-key",
                "scopes": ["email"],
            }
            bodies = []
            for _ in range(2):
                conn.request("POST", "/requests", body=json.dumps(payload))
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                bodies.append(resp.read())
            self.assertEqual(bodies[0], bodies[1])
            request_id = json.loads(bodies[0])["request_id"]
            conn.request(
                "GET",
                f"/requests/{request_id}",
                headers={"X-Tenant-Id": "tenant-a"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), bodies[0])
            conn.request("GET", "/requests/not-a-uuid",
                         headers={"X-Tenant-Id": "tenant-a"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 404)
            self.assertEqual(resp.read(), b'{"error":"not_found"}\n')
        finally:
            conn.close()

    def test_server_header_is_fixed(self):
        status, headers, _ = self._request(
            "GET",
            "/requests/00000000-0000-4000-8000-000000000000",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 404)
        self.assertTrue(headers.get("Server", "").startswith("forgetting-evidence/"))
        self.assertNotIn("Python", headers.get("Server", ""))


class ServeCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self._procs = []

    def tearDown(self):
        for proc in self._procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            # Drain and close the captured pipes so no fd is leaked.
            try:
                proc.communicate(timeout=5)
            except (subprocess.TimeoutExpired, ValueError):
                pass
        self._tmp.cleanup()

    def _start_serve(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.Popen(
            [sys.executable, "-m", "forgetting_evidence", "serve", *args],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._procs.append(proc)
        return proc

    def _wait_for_port(self, port, timeout=10.0):
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        self.fail("server did not open the listening port in time")

    def _free_port(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def test_health_command_unchanged(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-m", "forgetting_evidence", "health"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(
            json.loads(proc.stdout),
            {"service": "forgetting-evidence", "status": "ok"},
        )
        self.assertTrue(proc.stdout.endswith("\n"))

    def test_bad_usage_exits_2(self):
        from forgetting_evidence.__main__ import main

        self.assertEqual(main([]), 2)
        self.assertEqual(main(["bogus"]), 2)
        self.assertEqual(main(["serve"]), 2)
        self.assertEqual(main(["serve", self.db_path, "127.0.0.1"]), 2)
        self.assertEqual(main(["serve", self.db_path, "127.0.0.1", "notaport"]), 2)
        self.assertEqual(main(["serve", self.db_path, "127.0.0.1", "70000"]), 2)
        self.assertEqual(main(["health", "extra"]), 2)

    def test_serve_end_to_end_and_persistence_across_restart(self):
        port = self._free_port()
        proc = self._start_serve(self.db_path, "127.0.0.1", str(port))
        self._wait_for_port(port)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request(
                "POST",
                "/requests",
                body=json.dumps(
                    {
                        "tenant_id": "tenant-a",
                        "subject_id": "subject-1",
                        "idempotency_key": "key-1",
                        "scopes": ["email", "profile"],
                    }
                ),
            )
            resp = conn.getresponse()
            first = resp.read()
            self.assertEqual(resp.status, 200)
            receipt = json.loads(first)
            conn.close()
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            proc.communicate()
        self.assertEqual(proc.returncode, 0)

        # Restart against the same database file: lookup is unchanged and
        # an idempotent replay returns the identical receipt.
        proc2 = self._start_serve(
            "--db", self.db_path, "--host", "127.0.0.1", "--port", str(port)
        )
        self._wait_for_port(port)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request(
                "GET",
                f"/requests/{receipt['request_id']}",
                headers={"X-Tenant-Id": "tenant-a"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), first)
            conn.request(
                "POST",
                "/requests",
                body=json.dumps(
                    {
                        "tenant_id": "tenant-a",
                        "subject_id": "subject-1",
                        "idempotency_key": "key-1",
                        "scopes": ["profile", "email"],
                    }
                ),
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), first)
            conn.close()
        finally:
            proc2.terminate()
            proc2.wait(timeout=5)
            proc2.communicate()
        self.assertEqual(proc2.returncode, 0)

    def test_serve_uncreatable_database_still_serves_503(self):
        # An existing regular file cannot be a directory, so the nested db
        # path beneath it cannot be created. The service must still bind;
        # business requests answer 503 with the stable code only.
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        port = self._free_port()
        proc = self._start_serve(impossible, "127.0.0.1", str(port))
        self._wait_for_port(port)
        try:
            status, _, data = self._post_json(
                port,
                "/requests",
                {
                    "tenant_id": "tenant-a",
                    "subject_id": "subject-1",
                    "idempotency_key": "key-1",
                    "scopes": ["email"],
                },
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, b'{"error":"storage_unavailable"}\n')
            status, _, data = self._raw_request(
                port,
                "GET",
                "/requests/00000000-0000-4000-8000-000000000000",
                headers={"X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, b'{"error":"storage_unavailable"}\n')
            # Routing and validation still work without a database.
            status, _, data = self._raw_request(port, "GET", "/unknown")
            self.assertEqual(status, 404)
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            out, err = proc.communicate()
        # No payload, SQL text or filesystem path in logs.
        self.assertNotIn(impossible.encode(), err)
        self.assertNotIn(b"Traceback", err)

    @staticmethod
    def _post_json(port, path, payload):
        return ServeCliTests._raw_request(port, "POST", path, body=json.dumps(payload))

    @staticmethod
    def _raw_request(port, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_serve_port_in_use_exits_1(self):
        port = self._free_port()
        first = self._start_serve(self.db_path, "127.0.0.1", str(port))
        self._wait_for_port(port)
        second_db = os.path.join(self._tmp.name, "other.db")
        second = self._start_serve(second_db, "127.0.0.1", str(port))
        try:
            out, err = second.communicate(timeout=5)
            self.assertEqual(second.returncode, 1)
            self.assertEqual(err.decode().strip(), "address_in_use")
        finally:
            first.terminate()
            first.wait(timeout=5)


class DeferredStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_unavailable_path_then_self_heals(self):
        blocker = os.path.join(self._tmp.name, "blocker")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        # Startup swallowed the failure; every call reports unavailable.
        with self.assertRaises(httpapi._StorageUnavailable):
            store.submit("tenant-a", "subject-1", ["email"], "key-1")
        with self.assertRaises(httpapi._StorageUnavailable):
            store.get("tenant-a", "00000000-0000-4000-8000-000000000000")

        # Once the storage path is repaired at runtime, the next request
        # initializes the store without needing a restart.
        os.remove(blocker)
        os.makedirs(os.path.dirname(impossible))
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(receipt["status"], "accepted")
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"]), receipt
        )

    def test_healthy_path_initializes_and_persists(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"]), receipt
        )

    def test_storage_layer_transition_and_status_are_proxied(self):
        # The HTTP layer never routes these, but the deferred wrapper must
        # forward them like the underlying store.
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        moved = store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(moved["status"], "processing")
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        # The acceptance query stays frozen even through the wrapper.
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"]), receipt
        )


if __name__ == "__main__":
    unittest.main()
