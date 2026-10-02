import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import (
    AuthConfig,
    AuthConfigError,
    build_server,
    load_auth_config,
)
from forgetting_evidence.requests import RequestStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")


def _auth_config(principals):
    return AuthConfig(principals)


class _Server:
    def __init__(self, store, auth=None, host="127.0.0.1", port=0):
        self.server = build_server(store, host, port, auth)
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


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
BOTH_A = {"token": "tok-both-a", "tenant_id": "tenant-a",
          "roles": ["request:submit", "request:read"]}
SUBMIT_B = {"token": "tok-submit-b", "tenant_id": "tenant-b",
            "roles": ["request:submit"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}

UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'


class AuthConfigLoaderTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, content, raw=False):
        path = os.path.join(self._tmp.name, "auth.json")
        mode = "wb" if raw else "w"
        with open(path, mode, encoding=None if raw else "utf-8") as handle:
            handle.write(content)
        return path

    def _valid_json(self):
        return json.dumps({"principals": [SUBMIT_A, READ_A, SUBMIT_B, READ_B]})

    def test_valid_config_loads_and_authenticates(self):
        config = load_auth_config(self._write(self._valid_json()))
        self.assertEqual(config.authenticate("tok-submit-a"),
                         ("tenant-a", frozenset({"request:submit"})))
        self.assertEqual(config.authenticate("tok-read-b"),
                         ("tenant-b", frozenset({"request:read"})))
        self.assertIsNone(config.authenticate("unknown-token"))

    def test_role_order_and_single_role_accepted(self):
        doc = {"principals": [
            {"token": "t1", "tenant_id": "tn",
             "roles": ["request:read", "request:submit"]},
            {"token": "t2", "tenant_id": "tn", "roles": ["request:read"]},
        ]}
        config = load_auth_config(self._write(json.dumps(doc)))
        self.assertEqual(
            config.authenticate("t1")[1],
            frozenset({"request:submit", "request:read"}),
        )

    def test_missing_file_is_invalid(self):
        missing = os.path.join(self._tmp.name, "does-not-exist.json")
        with self.assertRaises(AuthConfigError) as ctx:
            load_auth_config(missing)
        self.assertEqual(str(ctx.exception), "auth_config_invalid")

    def test_malformed_or_non_utf8_is_invalid(self):
        for content, raw in (
            (b"{not json", True),
            (b"", True),
            (b"\xff\xfe not json", True),
            (b'{"principals":}', True),
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(AuthConfigError):
                    load_auth_config(self._write(content, raw=True))

    def test_shape_violations_are_invalid(self):
        bad_docs = [
            [],
            "string",
            None,
            123,
            {},
            {"principals": "x"},
            {"principals": {}},
            {"principals": None},
        ]
        for doc in bad_docs:
            with self.subTest(doc=doc):
                with self.assertRaises(AuthConfigError):
                    load_auth_config(self._write(json.dumps(doc)))

    def test_extra_keys_are_ignored(self):
        # Mirrors the HTTP layer's permissive handling of unknown fields:
        # only the specified keys/domains are enforced.
        doc = {"principals": [
            {"token": "t", "tenant_id": "tn",
             "roles": ["request:submit"], "extra": 1}],
            "version": 2}
        config = load_auth_config(self._write(json.dumps(doc)))
        self.assertEqual(
            config.authenticate("t"),
            ("tn", frozenset({"request:submit"})),
        )

    def test_principal_field_violations_are_invalid(self):
        base = {"token": "t", "tenant_id": "tn",
                "roles": ["request:submit"]}
        bad_principals = []
        # Missing required fields.
        for key in ("token", "tenant_id", "roles"):
            entry = dict(base)
            del entry[key]
            bad_principals.append(entry)
        bad_principals.append(["not", "an", "object"])
        # Empty / non-string token and tenant.
        for field in ("token", "tenant_id"):
            for value in ("", 7, True, None, ["x"], {"x": 1}):
                entry = dict(base)
                entry[field] = value
                bad_principals.append(entry)
        # Bad roles.
        for roles in (
            [],
            "request:submit",
            None,
            123,
            ["request:submit", "request:submit"],
            ["unknown:role"],
            ["request:submit", "unknown:role"],
            [7],
            [None],
            [""],
        ):
            entry = dict(base)
            entry["roles"] = roles
            bad_principals.append(entry)
        for principal in bad_principals:
            with self.subTest(principal=principal):
                doc = {"principals": [principal]}
                with self.assertRaises(AuthConfigError):
                    load_auth_config(self._write(json.dumps(doc)))

    def test_duplicate_token_is_invalid(self):
        doc = {"principals": [
            {"token": "same", "tenant_id": "tenant-a",
             "roles": ["request:submit"]},
            {"token": "same", "tenant_id": "tenant-b",
             "roles": ["request:read"]},
        ]}
        with self.assertRaises(AuthConfigError):
            load_auth_config(self._write(json.dumps(doc)))

    def test_distinct_same_tenant_tokens_are_valid(self):
        doc = {"principals": [SUBMIT_A, READ_A, BOTH_A]}
        config = load_auth_config(self._write(json.dumps(doc)))
        self.assertIsNotNone(config.authenticate("tok-both-a"))


class HttpAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = _auth_config([SUBMIT_A, READ_A, BOTH_A, SUBMIT_B, READ_B])
        self._fixture = _Server(self.store, self.auth)
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
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def _post_payload(self, tenant="tenant-a", key="key-1", subject="subject-1"):
        return {
            "tenant_id": tenant,
            "subject_id": subject,
            "idempotency_key": key,
            "scopes": ["email", "profile"],
        }

    # -- 401 ------------------------------------------------------------

    def test_post_requires_authorization(self):
        for headers in (
            {},
            {"Authorization": ""},
            {"Authorization": "Basic tok-submit-a"},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer "},
            {"Authorization": "bearer tok-submit-a"},
            {"Authorization": "Bearer unknown-token"},
            {"Authorization": "tok-submit-a"},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "POST", "/requests", body=self._post_payload(),
                    headers=headers,
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, UNAUTHORIZED)

    def test_get_requires_authorization(self):
        # Seed a request directly through the store.
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        for headers in (
            {},
            {"Authorization": "Bearer unknown"},
            {"Authorization": "Bearer ", "X-Tenant-Id": "tenant-a"},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET", f"/requests/{receipt['request_id']}",
                    headers=headers,
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, UNAUTHORIZED)

    # -- 403 ------------------------------------------------------------

    def test_post_without_submit_role_is_forbidden(self):
        # A read-only principal cannot submit, even with a valid token and
        # matching tenant; role check precedes body validation.
        status, _, data = self._request(
            "POST", "/requests", body=self._post_payload(),
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_post_for_other_tenant_is_forbidden(self):
        status, _, data = self._request(
            "POST", "/requests", body=self._post_payload(tenant="tenant-b"),
            headers=self._bearer("tok-submit-a"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_get_without_read_role_is_forbidden(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        status, _, data = self._request(
            "GET", f"/requests/{receipt['request_id']}",
            headers={**self._bearer("tok-submit-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_get_for_other_tenant_is_forbidden(self):
        # A request belonging to tenant-b, queried while authenticating as
        # tenant-a, is forbidden before any storage access -- the foreign
        # id cannot even be probed.
        receipt_b = self.store.submit(
            "tenant-b", "subject-1", ["email"], "key-b"
        )
        status, _, data = self._request(
            "GET", f"/requests/{receipt_b['request_id']}",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # Same via query parameter.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt_b['request_id']}?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # A malformed foreign id is still 403, never 404: tenant
        # authorization precedes request-id validation.
        status, _, data = self._request(
            "GET", "/requests/not-a-uuid",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_header_tenant_takes_precedence_in_authorization(self):
        receipt_b = self.store.submit(
            "tenant-b", "subject-1", ["email"], "key-b"
        )
        # Header tenant-b matches the read-b principal even though the
        # query says tenant-a; the existing header-precedence rule governs
        # the authorization target.
        status, _, _ = self._request(
            "GET",
            f"/requests/{receipt_b['request_id']}?tenant_id=tenant-a",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 200)
        # Header for a different tenant forbids regardless of query.
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt_b['request_id']}?tenant_id=tenant-b",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    # -- authorized success --------------------------------------------

    def test_authorized_submit_and_read_byte_identical(self):
        status, _, post_data = self._request(
            "POST", "/requests", body=self._post_payload(),
            headers=self._bearer("tok-submit-a"),
        )
        self.assertEqual(status, 200)
        receipt = json.loads(post_data)
        request_id = receipt["request_id"]
        # The submit-only principal cannot read back.
        status, _, data = self._request(
            "GET", f"/requests/{request_id}",
            headers={**self._bearer("tok-submit-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # The read principal gets the byte-identical receipt.
        status, _, data = self._request(
            "GET", f"/requests/{request_id}",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, post_data)
        # Query parameter tenant works too.
        status, _, data = self._request(
            "GET", f"/requests/{request_id}?tenant_id=tenant-a",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, post_data)
        # A dual-role principal can both submit and read.
        status, _, data = self._request(
            "POST", "/requests", body=self._post_payload(key="key-2"),
            headers=self._bearer("tok-both-a"),
        )
        self.assertEqual(status, 200)

    def test_idempotent_replay_and_conflict_under_auth(self):
        payload = self._post_payload()
        status, _, first = self._request(
            "POST", "/requests", body=payload,
            headers=self._bearer("tok-submit-a"),
        )
        self.assertEqual(status, 200)
        # Same key/subject/scopes replays the identical receipt.
        status, _, replay = self._request(
            "POST", "/requests",
            body=self._post_payload(key="key-1", subject="subject-1"),
            headers=self._bearer("tok-submit-a"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        # Same key, different subject -> 409 (authorized, matching tenant).
        status, _, data = self._request(
            "POST", "/requests",
            body=self._post_payload(key="key-1", subject="other-subject"),
            headers=self._bearer("tok-submit-a"),
        )
        self.assertEqual(status, 409)
        self.assertEqual(data, b'{"error":"idempotency_conflict"}\n')

    def test_cross_tenant_same_key_is_independent(self):
        status_a, _, data_a = self._request(
            "POST", "/requests", body=self._post_payload(
                tenant="tenant-a", key="shared"),
            headers=self._bearer("tok-submit-a"),
        )
        status_b, _, data_b = self._request(
            "POST", "/requests", body=self._post_payload(
                tenant="tenant-b", key="shared"),
            headers=self._bearer("tok-submit-b"),
        )
        self.assertEqual((status_a, status_b), (200, 200))
        self.assertNotEqual(json.loads(data_a)["request_id"],
                            json.loads(data_b)["request_id"])

    def test_missing_request_remains_404_when_authorized(self):
        unknown = "00000000-0000-4000-8000-000000000000"
        status, _, data = self._request(
            "GET", f"/requests/{unknown}",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)
        # Own-tenant lookup of another tenant's record is not found.
        receipt_b = self.store.submit(
            "tenant-b", "subject-1", ["email"], "key-b"
        )
        status, _, data = self._request(
            "GET", f"/requests/{receipt_b['request_id']}",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    # -- ordering: routing/auth/validation ------------------------------

    def test_unknown_path_stays_404_without_and_with_token(self):
        for headers in ({}, self._bearer("tok-both-a")):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET", "/nothing/here", headers=headers
                )
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)

    def test_unsupported_method_stays_405_even_without_token(self):
        # Routing/method checks precede authentication.
        status, _, data = self._request("PUT", "/requests")
        self.assertEqual(status, 405)
        self.assertEqual(data, METHOD_NOT_ALLOWED)
        status, _, data = self._request(
            "POST", "/requests/00000000-0000-4000-8000-000000000000"
        )
        self.assertEqual(status, 405)

    def test_role_check_precedes_payload_validation(self):
        # A read-only principal sending garbage still gets 403, not 400.
        status, _, data = self._request(
            "POST", "/requests", raw_body=b"{not json",
            headers={**self._bearer("tok-read-a"),
                     "Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # An authenticated submitter sending garbage gets 400.
        status, _, data = self._request(
            "POST", "/requests", raw_body=b"{not json",
            headers={**self._bearer("tok-submit-a"),
                     "Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_get_missing_tenant_with_valid_token_is_400(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        status, _, data = self._request(
            "GET", f"/requests/{receipt['request_id']}",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    # -- no leakage ------------------------------------------------------

    def test_token_is_not_persisted(self):
        token = "tok-submit-a"
        status, _, _ = self._request(
            "POST", "/requests", body=self._post_payload(),
            headers=self._bearer(token),
        )
        self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(token.encode(), db_bytes)
        self.assertNotIn(b"request:submit", db_bytes)
        self.assertNotIn(b"request:read", db_bytes)


class UnauthenticatedServerContractTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self._fixture = _Server(self.store, None)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            kwargs = {}
            if body is not None:
                kwargs["body"] = json.dumps(body)
            conn.request(method, path, headers=headers or {}, **kwargs)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_no_auth_config_keeps_open_contract(self):
        # No Authorization header at all: acceptance and lookup work.
        status, post_data = self._request(
            "POST", "/requests",
            body={
                "tenant_id": "tenant-a", "subject_id": "subject-1",
                "idempotency_key": "key-1", "scopes": ["email"],
            },
        )
        self.assertEqual(status, 200)
        request_id = json.loads(post_data)["request_id"]
        status, data = self._request(
            "GET", f"/requests/{request_id}",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, post_data)
        # An Authorization header is simply ignored without auth config.
        status, data = self._request(
            "GET", f"/requests/{request_id}",
            headers={"X-Tenant-Id": "tenant-a",
                     "Authorization": "Bearer anything"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, post_data)


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
            cwd=REPO_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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

    def _write_auth(self, content):
        path = os.path.join(self._tmp.name, "auth.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def _raw_request(self, port, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_invalid_auth_file_refuses_to_bind_exit_2(self):
        port = self._free_port()
        bad_cases = [
            ("missing", None),
            ("malformed", "{not json"),
            ("not-object", json.dumps(["x"])),
            ("empty-principals-roles", json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "tn", "roles": []}]} )),
            ("duplicate-token", json.dumps(
                {"principals": [
                    {"token": "same", "tenant_id": "a",
                     "roles": ["request:submit"]},
                    {"token": "same", "tenant_id": "b",
                     "roles": ["request:read"]}]} )),
            ("bad-role", json.dumps(
                {"principals": [
                    {"token": "t", "tenant_id": "tn",
                     "roles": ["request:delete"]}]} )),
        ]
        for label, content in bad_cases:
            with self.subTest(label=label):
                if content is None:
                    auth_path = os.path.join(self._tmp.name, "nope.json")
                else:
                    auth_path = self._write_auth(content)
                proc = self._start_serve(
                    "--db", self.db_path + label,
                    "--host", "127.0.0.1", "--port", str(port),
                    "--auth-file", auth_path,
                )
                out, err = proc.communicate(timeout=5)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(err.decode().strip(), "auth_config_invalid")
                # The port must not have been bound.
                with socket.socket() as probe:
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        probe.bind(("127.0.0.1", port))
                    except OSError:
                        self.fail("invalid config still bound the port")

    def test_auth_file_end_to_end(self):
        auth_path = self._write_auth(json.dumps(
            {"principals": [
                {"token": "cli-token-a", "tenant_id": "tenant-a",
                 "roles": ["request:submit", "request:read"]}]}
        ))
        port = self._free_port()
        proc = self._start_serve(
            "--db", self.db_path, "--host", "127.0.0.1", "--port", str(port),
            "--auth-file", auth_path,
        )
        self._wait_for_port(port)
        try:
            payload = json.dumps({
                "tenant_id": "tenant-a", "subject_id": "subject-1",
                "idempotency_key": "key-1", "scopes": ["email", "profile"],
            })
            # Without a token: 401.
            status, _, data = self._raw_request(
                port, "POST", "/requests", body=payload)
            self.assertEqual(status, 401)
            self.assertEqual(data, UNAUTHORIZED)
            # With the configured token: accepted.
            status, _, post_data = self._raw_request(
                port, "POST", "/requests", body=payload,
                headers={"Authorization": "Bearer cli-token-a"})
            self.assertEqual(status, 200)
            request_id = json.loads(post_data)["request_id"]
            # Cross-tenant submit: 403.
            other = json.dumps({
                "tenant_id": "tenant-b", "subject_id": "subject-1",
                "idempotency_key": "key-2", "scopes": ["email"],
            })
            status, _, data = self._raw_request(
                port, "POST", "/requests", body=other,
                headers={"Authorization": "Bearer cli-token-a"})
            self.assertEqual(status, 403)
            self.assertEqual(data, FORBIDDEN)
            # Authorized lookup returns the byte-identical receipt.
            status, _, data = self._raw_request(
                port, "GET", f"/requests/{request_id}",
                headers={"Authorization": "Bearer cli-token-a",
                         "X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(data, post_data)
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            out, err = proc.communicate()
        # Token and roles never appear in process logs.
        self.assertNotIn(b"cli-token-a", err)
        self.assertNotIn(b"request:submit", err)
        self.assertNotIn(b"request:read", err)


if __name__ == "__main__":
    unittest.main()
