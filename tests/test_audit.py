import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit  # noqa: E402

HARDENED = {
    "image": "nginx:1.27",
    "user": "101",
    "read_only": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "healthcheck": {"test": ["CMD", "true"]},
    "deploy": {"resources": {"limits": {"memory": "64M"}}},
}


def rules(service: dict) -> set[str]:
    return {f.rule for f in audit.audit({"services": {"svc": service}})}


class AuditTest(unittest.TestCase):
    def test_hardened_service_is_clean(self):
        self.assertEqual(rules(HARDENED), set())

    def test_image_pinning(self):
        self.assertIn("CH001", rules({**HARDENED, "image": "nginx"}))
        self.assertIn("CH001", rules({**HARDENED, "image": "nginx:latest"}))
        self.assertNotIn("CH001", rules({**HARDENED, "image": "nginx@sha256:abc"}))

    def test_registry_port_is_not_a_tag(self):
        self.assertIn("CH001", rules({**HARDENED, "image": "localhost:5000/app"}))

    def test_build_only_service_skips_image_rule(self):
        svc = {k: v for k, v in HARDENED.items() if k != "image"}
        self.assertNotIn("CH001", rules({**svc, "build": "."}))

    def test_root_user_variants(self):
        for user in ("0", "root", "0:0"):
            self.assertIn("CH002", rules({**HARDENED, "user": user}))
        self.assertIn("CH002", rules({k: v for k, v in HARDENED.items() if k != "user"}))

    def test_each_missing_control_maps_to_its_rule(self):
        cases = {
            "read_only": "CH003",
            "cap_drop": "CH004",
            "healthcheck": "CH006",
            "deploy": "CH007",
            "security_opt": "CH008",
        }
        for key, rule in cases.items():
            svc = {k: v for k, v in HARDENED.items() if k != key}
            self.assertEqual(rules(svc), {rule}, key)

    def test_privileged(self):
        self.assertEqual(rules({**HARDENED, "privileged": True}), {"CH005"})

    def test_disabled_healthcheck_is_flagged(self):
        self.assertEqual(rules({**HARDENED, "healthcheck": {"disable": True}}), {"CH006"})

    def test_mem_limit_shorthand_is_accepted(self):
        svc = {k: v for k, v in HARDENED.items() if k != "deploy"}
        self.assertEqual(rules({**svc, "mem_limit": "64m"}), set())


if __name__ == "__main__":
    unittest.main()
