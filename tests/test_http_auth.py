import http.client
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
import io

from forgetting_evidence import httpapi
from forgetting_evidence.auth import AuthConfigError, load_auth_config
from forgetting_evidence.httpapi import build_server
from forgetting_evidence.requests import RequestStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")

TOKEN_A_SUBMIT = "token-a-submit-SECRET"
TOKEN_A_READ = "token-a-read-SECRET"
TOKEN_A_BOTH = "token-a-both-SECRET"
TOKEN_B_BOTH = "token-b-both-SECRET"


def _auth_file(tmpdir, principals, name="auth.json", raw=None):
    path = os.path.join(tmpdir, name)
    with open(path, "wb") as handle:
        if raw is not None:
            handle.write(raw)
        else:
            handle.write(
                json.dumps({"principals": principals}).encode("utf-8")
            )
    return path


def _principal(token, tenant="tenant-a", roles=None):
    return {"token": token, "tenant_id": tenant, "roles": roles or []}


def _standard_config_path(tmpdir):
    return _auth_file(
        tmpdir,
        [
            _principal(TOKEN_A_SUBMIT, "tenant-a", ["request:submit"]),
            _principal(TOKEN_A_READ, "tenant-a", ["request:read"]),
            _principal(
                TOKEN_A_BOTH,
                "tenant-a",
                ["request:submit", "request:read"],
            ),
            _principal(
                TOKEN_B_BOTH,
                "tenant-b",
                ["request:submit", "request:read"],
            ),
        ],
    )


class AuthConfigLoaderTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_config_loads_and_resolves(self):
        path = _standard_config_path(self._tmp.name)
        config = load_auth_config(path)
        principal = config.principal(f"Bearer {TOKEN_A_BOTH}")
        self.assertIsNotNone(principal)
        self.assertEqual(principal.tenant_id, "tenant-a")
        self.assertEqual(principal.roles, {"request:submit", "request:read"})

    def test_missing_file_is_invalid(self):
        with self.assertRaises(AuthConfigError) as caught:
            load_auth_config(os.path.join(self._tmp.name, "missing.json"))
        self.assertEqual(str(caught.exception), "auth_config_invalid")

    def test_invalid_configs_are_rejected_with_fixed_text(self):
        invalid_documents = [
            b"",
            b"{not json",
            b"[]",
            b'{"principals": [] }EXTRA',
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x",
                     "roles": ["request:submit"]}],
                 "extra": 1}
            ).encode(),
            json.dumps({"principals": {}}).encode(),
            json.dumps(
                {"principals": [
                    {"token": "", "tenant_id": "x",
                     "roles": ["request:submit"]}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": 7, "tenant_id": "x",
                     "roles": ["request:submit"]}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "",
                     "roles": ["request:submit"]}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x", "roles": []}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x",
                     "roles": ["request:submit", "request:submit"]}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x",
                     "roles": ["request:admin"]}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x",
                     "roles": "request:submit"}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x",
                     "roles": ["request:submit"]},
                    {"token": "t", "tenant_id": "y",
                     "roles": ["request:read"]}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x",
                     "roles": ["request:submit"], "extra": 1}]}
            ).encode(),
            json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "x"}]}
            ).encode(),
        ]
        for index, raw in enumerate(invalid_documents):
            path = _auth_file(
                self._tmp.name, [], name=f"bad-{index}.json", raw=raw
            )
            with self.subTest(index=index):
                with self.assertRaises(AuthConfigError) as caught:
                    load_auth_config(path)
                self.assertEqual(str(caught.exception), "auth_config_invalid")

    def test_non_utf8_file_is_invalid(self):
        path = _auth_file(
            self._tmp.name, [], raw=b'{"principals": []}\xff\xfe'
        )
        with self.assertRaises(AuthConfigError) as caught:
            load_auth_config(path)
        self.assertEqual(str(caught.exception), "auth_config_invalid")

    def test_empty_principals_is_valid_but_denies_all(self):
        path = _auth_file(self._tmp.name, [])
        config = load_auth_config(path)
        self.assertIsNone(config.principal("Bearer anything"))

    def test_authorization_header_shapes(self):
        config = load_auth_config(_standard_config_path(self._tmp.name))
        self.assertIsNone(config.principal(None))
        self.assertIsNone(config.principal(""))
        self.assertIsNone(config.principal("Basic abc"))
        self.assertIsNone(config.principal("Bearer"))
        self.assertIsNone(config.principal("Bearer "))
        self.assertIsNone(config.principal("Bearer unknown-token"))
        self.assertIsNone(config.principal(f"bearer {TOKEN_A_BOTH}"))
        self.assertIsNone(config.principal(f"Bearer  {TOKEN_A_BOTH}"))
        # Exact token match: no whitespace trimming.
        self.assertIsNone(config.principal(f"Bearer {TOKEN_A_BOTH} "))
        self.assertIsNotNone(config.principal(f"Bearer {TOKEN_A_BOTH}"))


class AuthedServerFixture:
    def __init__(self, store, auth, host="127.0.0.1", port=0):
        self.server = build_server(store, host, port, auth=auth)
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


class HttpAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = load_auth_config(_standard_config_path(self._tmp.name))
        self._fixture = AuthedServerFixture(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

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

    def _submit(self, token=None, tenant="tenant-a", key="key-1"):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return self._request(
            "POST",
            "/requests",
            body={
                "tenant_id": tenant,
                "subject_id": "subject-1",
                "idempotency_key": key,
                "scopes": ["email", "profile"],
            },
            headers=headers,
        )

    # -- 401 ------------------------------------------------------------

    def test_post_requires_authorization(self):
        for headers in (
            {},
            {"Authorization": "Basic x"},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer unknown-token"},
            {"Authorization": f"bearer {TOKEN_A_SUBMIT}"},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "POST", "/requests", body={"x": 1}, headers=headers
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, b'{"error":"unauthorized"}\n')
                self.assertEqual(data.count(b"\n"), 1)

    def test_get_requires_authorization(self):
        # Seed a request directly through the store.
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        for headers in (
            {},
            {"Authorization": "Bearer unknown-token"},
            {"X-Tenant-Id": "tenant-a"},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET",
                    f"/requests/{receipt['request_id']}",
                    headers=headers,
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, b'{"error":"unauthorized"}\n')

    # -- 403 RBAC -------------------------------------------------------

    def test_post_requires_submit_role_even_for_malformed_body(self):
        # A read-only token is rejected with 403 before the body is
        # parsed: even malformed payloads never reach validation.
        status, _, data = self._request(
            "POST",
            "/requests",
            raw_body=b"{not json",
            headers={"Authorization": f"Bearer {TOKEN_A_READ}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_auth_precedes_path_segment_validation_on_get(self):
        # A malformed request id would be 404 after validation, but a
        # missing or insufficient credential is answered first.
        path = "/requests/not-a-uuid"
        status, _, data = self._request("GET", path)
        self.assertEqual(status, 401)
        status, _, data = self._request(
            "GET",
            path,
            headers={
                "Authorization": f"Bearer {TOKEN_A_SUBMIT}",
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 403)
        # Role present, target tenant foreign to the principal: the
        # scope decision precedes the id-shape 404 as well.
        status, _, data = self._request(
            "GET",
            path,
            headers={
                "Authorization": f"Bearer {TOKEN_A_READ}",
                "X-Tenant-Id": "tenant-b",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')
        # Role present, own tenant: path validation then yields 404.
        status, _, data = self._request(
            "GET",
            path,
            headers={
                "Authorization": f"Bearer {TOKEN_A_READ}",
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_post_scope_check_uses_only_tenant_field(self):
        # A foreign, well-formed tenant_id fails the scope check even
        # when the rest of the payload is absent or invalid; the
        # tenant field alone establishes the target.
        status, _, data = self._request(
            "POST",
            "/requests",
            body={"tenant_id": "tenant-b"},
            headers={"Authorization": f"Bearer {TOKEN_A_BOTH}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')
        # A non-string/empty tenant cannot establish a target: the
        # ordinary payload validation outcome is preserved.
        for tenant in ("", 7, None):
            status, _, _ = self._request(
                "POST",
                "/requests",
                body={"tenant_id": tenant},
                headers={"Authorization": f"Bearer {TOKEN_A_BOTH}"},
            )
            self.assertEqual(status, 400)

    def test_get_requires_read_role(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        # submit-only token cannot read, even with the right tenant and
        # a perfectly valid target id.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={
                "Authorization": f"Bearer {TOKEN_A_SUBMIT}",
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_post_rejects_other_tenant_body(self):
        # A valid submit token for tenant-a cannot submit for tenant-b.
        status, _, data = self._submit(TOKEN_A_SUBMIT, tenant="tenant-b")
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_get_rejects_other_tenant_targets(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        # Header-based target.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={
                "Authorization": f"Bearer {TOKEN_A_BOTH}",
                "X-Tenant-Id": "tenant-b",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')
        # Query-parameter-based target.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}?tenant_id=tenant-b",
            headers={"Authorization": f"Bearer {TOKEN_A_BOTH}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')
        # A tenant-b principal explicitly naming tenant-a as the target
        # fails the scope check even though the request exists.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={
                "Authorization": f"Bearer {TOKEN_B_BOTH}",
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')
        # A tenant-b principal naming tenant-b as the target for an id
        # that actually belongs to tenant-a passes the scope check but
        # is the existing indistinguishable cross-tenant store miss.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={
                "Authorization": f"Bearer {TOKEN_B_BOTH}",
                "X-Tenant-Id": "tenant-b",
            },
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_get_header_tenant_takes_precedence_over_query(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        # Header says tenant-a (the principal's tenant) while the query
        # says tenant-b: header precedence yields 200.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}?tenant_id=tenant-b",
            headers={
                "Authorization": f"Bearer {TOKEN_A_BOTH}",
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], receipt["request_id"])

    def test_get_without_any_tenant_is_400_after_role_check(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        # Read role present, but no target tenant at all: the existing
        # validation outcome (400) is preserved.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={"Authorization": f"Bearer {TOKEN_A_READ}"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, b'{"error":"invalid_request"}\n')
        # Role failure (submit-only) still masks the missing tenant as
        # 403 because RBAC precedes payload validation.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={"Authorization": f"Bearer {TOKEN_A_SUBMIT}"},
        )
        self.assertEqual(status, 403)

    # -- routing stays ahead of auth -----------------------------------

    def test_unknown_path_is_404_without_challenge(self):
        for method in ("GET", "POST"):
            status, _, data = self._request(method, "/nothing/here")
            self.assertEqual(status, 404)
            self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_unsupported_method_is_405_without_challenge(self):
        status, _, data = self._request("GET", "/requests")
        self.assertEqual(status, 405)
        self.assertEqual(data, b'{"error":"method_not_allowed"}\n')
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        status, _, data = self._request(
            "PUT",
            f"/requests/{receipt['request_id']}",
            headers={"Authorization": f"Bearer {TOKEN_A_BOTH}"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, b'{"error":"method_not_allowed"}\n')

    # -- success semantics unchanged ------------------------------------

    def test_authenticated_submit_and_byte_identical_replay(self):
        status, _, first = self._submit(TOKEN_A_SUBMIT)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(first)["status"], "accepted")
        status, _, second = self._submit(TOKEN_A_SUBMIT)
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        receipt = json.loads(first)
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={
                "Authorization": f"Bearer {TOKEN_A_READ}",
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, first)
        # Query-param tenant works with auth too.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}?tenant_id=tenant-a",
            headers={"Authorization": f"Bearer {TOKEN_A_BOTH}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, first)

    def test_conflict_and_not_found_codes_unchanged(self):
        status, _, _ = self._submit(TOKEN_A_SUBMIT)
        self.assertEqual(status, 200)
        # Same key, different subject: 409 after auth succeeds.
        status, _, data = self._request(
            "POST",
            "/requests",
            body={
                "tenant_id": "tenant-a",
                "subject_id": "subject-2",
                "idempotency_key": "key-1",
                "scopes": ["email"],
            },
            headers={"Authorization": f"Bearer {TOKEN_A_SUBMIT}"},
        )
        self.assertEqual(status, 409)
        self.assertEqual(data, b'{"error":"idempotency_conflict"}\n')
        # Unknown id, own tenant: 404.
        status, _, data = self._request(
            "GET",
            "/requests/00000000-0000-4000-8000-000000000000",
            headers={
                "Authorization": f"Bearer {TOKEN_A_READ}",
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_unauthorized_post_writes_nothing(self):
        self._submit(None)
        self._submit("unknown-token")
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT count(*) FROM requests").fetchone()[0]
        self.assertEqual(count, 0)

    def test_token_never_persisted_or_logged(self):
        secret = TOKEN_A_BOTH
        status, _, post_data = self._submit(secret, key="key-auth")
        self.assertEqual(status, 200)
        receipt = self.store.submit("tenant-b", "s", ["x"], "other")
        self._request(
            "GET",
            f"/requests/{receipt['request_id']}",
            headers={
                "Authorization": f"Bearer {secret}",
                "X-Tenant-Id": "tenant-b",
            },
        )
        # Token material is absent from the database file.
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(secret.encode(), db_bytes)
        self.assertNotIn(b"request:submit", db_bytes)
        self.assertNotIn(secret.encode(), post_data)
        # Failed authz is not logged with the token.
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.WARNING)
        stderr = io.StringIO()
        try:
            with redirect_stderr(stderr):
                self._request(
                    "GET",
                    f"/requests/{json.loads(post_data)['request_id']}",
                    headers={
                        "Authorization": f"Bearer {secret}",
                        "X-Tenant-Id": "tenant-b",
                    },
                )
                self._request(
                    "POST",
                    "/requests",
                    body={},
                    headers={"Authorization": f"Bearer {secret}"},
                )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        emitted = stream.getvalue() + stderr.getvalue()
        self.assertNotIn(secret, emitted)

    def test_rejected_keeps_connection_usable(self):
        # The unread body on a 401 must not desync later requests even
        # when the client reuses the connection object.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                "POST",
                "/requests",
                body=json.dumps(
                    {
                        "tenant_id": "tenant-a",
                        "subject_id": "subject-1",
                        "idempotency_key": "key-keep",
                        "scopes": ["email"],
                    }
                ),
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            self.assertEqual(resp.read(), b'{"error":"unauthorized"}\n')
            conn.request(
                "POST",
                "/requests",
                body=json.dumps(
                    {
                        "tenant_id": "tenant-a",
                        "subject_id": "subject-1",
                        "idempotency_key": "key-keep",
                        "scopes": ["email"],
                    }
                ),
                headers={"Authorization": f"Bearer {TOKEN_A_SUBMIT}"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = resp.read()
            self.assertEqual(json.loads(body)["status"], "accepted")
        finally:
            conn.close()


class ServeAuthCliTests(unittest.TestCase):
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

    def test_invalid_auth_file_exits_2_without_binding(self):
        port = self._free_port()
        bad_cases = [
            os.path.join(self._tmp.name, "does-not-exist.json"),
            _auth_file(self._tmp.name, [], name="empty.json", raw=b""),
            _auth_file(
                self._tmp.name,
                [
                    _principal("dup", "tenant-a", ["request:submit"]),
                    _principal("dup", "tenant-a", ["request:read"]),
                ],
                name="dup.json",
            ),
            _auth_file(
                self._tmp.name,
                [_principal("t", "tenant-a", ["request:bogus"])],
                name="badrole.json",
            ),
        ]
        for index, auth_path in enumerate(bad_cases):
            with self.subTest(index=index):
                proc = self._start_serve(
                    self.db_path,
                    "127.0.0.1",
                    str(port),
                    "--auth-file",
                    auth_path,
                )
                out, err = proc.communicate(timeout=5)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(err.decode().strip(), "auth_config_invalid")
                self.assertNotIn(b"dup", err)
                self.assertNotIn(b"bogus", err)
                # No port was ever bound.
                with self.assertRaises(OSError):
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=0.5
                    ):
                        pass

    def test_serve_with_auth_file_end_to_end(self):
        auth_path = _standard_config_path(self._tmp.name)
        port = self._free_port()
        proc = self._start_serve(
            "--db",
            self.db_path,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--auth-file",
            auth_path,
        )
        self._wait_for_port(port)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            # Unauthenticated request rejected.
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
            self.assertEqual(resp.status, 401)
            self.assertEqual(resp.read(), b'{"error":"unauthorized"}\n')
            # Authenticated submission succeeds.
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
                headers={"Authorization": f"Bearer {TOKEN_A_SUBMIT}"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            first = resp.read()
            receipt = json.loads(first)
            conn.close()
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            out, err = proc.communicate()
        self.assertNotIn(TOKEN_A_SUBMIT.encode(), err)
        self.assertEqual(proc.returncode, 0)

        # Restart with the same config: identical authz outcomes and
        # byte-identical receipt; authorization is fully determined by
        # the restarted configuration, nothing persisted.
        proc2 = self._start_serve(
            self.db_path,
            "127.0.0.1",
            str(port),
            "--auth-file",
            auth_path,
        )
        self._wait_for_port(port)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request(
                "GET",
                f"/requests/{receipt['request_id']}",
                headers={
                    "Authorization": f"Bearer {TOKEN_A_READ}",
                    "X-Tenant-Id": "tenant-a",
                },
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), first)
            # A token absent from this (same) config would be 401.
            conn.request(
                "GET",
                f"/requests/{receipt['request_id']}",
                headers={
                    "Authorization": "Bearer not-in-config",
                    "X-Tenant-Id": "tenant-a",
                },
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            conn.close()
        finally:
            proc2.terminate()
            proc2.wait(timeout=5)
            proc2.communicate()

    def test_serve_without_auth_file_keeps_open_contract(self):
        port = self._free_port()
        proc = self._start_serve(
            "--db", self.db_path, "--host", "127.0.0.1", "--port", str(port)
        )
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
                        "scopes": ["email"],
                    }
                ),
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            resp.read()
            conn.close()
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            proc.communicate()

    def test_auth_file_flag_combines_with_positional_args(self):
        auth_path = _standard_config_path(self._tmp.name)
        port = self._free_port()
        proc = self._start_serve(
            self.db_path,
            "127.0.0.1",
            str(port),
            "--auth-file",
            auth_path,
        )
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
                        "scopes": ["email"],
                    }
                ),
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            resp.read()
            conn.close()
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            proc.communicate()

    def test_bad_serve_invocation_still_reports_usage(self):
        from forgetting_evidence.__main__ import main

        good = _standard_config_path(self._tmp.name)
        # Duplicate --auth-file, mixed named/positional required fields,
        # and an unknown flag are parse errors -- not auth errors.
        cases = [
            [
                "--db", self.db_path, "--host", "127.0.0.1",
                "--port", "1", "--auth-file", good, "--auth-file", good,
            ],
            [
                self.db_path, "127.0.0.1", "1", "--db", self.db_path,
            ],
            [
                "--db", self.db_path, "--host", "127.0.0.1",
                "--port", "1", "--bogus",
            ],
            [
                self.db_path, "127.0.0.1", "1", "extra-positional",
            ],
        ]
        for case in cases:
            with self.subTest(case=case):
                err = io.StringIO()
                with redirect_stderr(err):
                    code = main(["serve", *case])
                self.assertEqual(code, 2)
                self.assertIn("usage:", err.getvalue())
                self.assertNotIn("auth_config_invalid", err.getvalue())


if __name__ == "__main__":
    unittest.main()
