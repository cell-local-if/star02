import io
import json
import unittest
from contextlib import redirect_stdout

from forgetting_evidence.__main__ import main


class HealthTests(unittest.TestCase):
    def test_health_is_machine_readable(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["health"]), 0)
        self.assertEqual(json.loads(output.getvalue()), {
            "service": "forgetting-evidence",
            "status": "ok",
        })


if __name__ == "__main__":
    unittest.main()
