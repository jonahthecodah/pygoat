from django.apps import apps
from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from challenge.models import Lab


@override_settings(LAB_DOMAIN="lvh.me")
class TraefikAuthVerifyTests(TestCase):
    url = "/auth/verify/"

    def setUp(self):
        Lab.objects.create(name="xss_lab", build_location="x", port=5000, is_custom=False)
        Lab.objects.create(name="sql_injection_lab", build_location="x", port=5001, is_custom=False)
        self.alice = User.objects.create_user("alice", password="pw")
        self.alice_bob = User.objects.create_user("alice-bob", password="pw")

    def verify(self, host, user=None):
        if user:
            self.client.force_login(user)
        return self.client.get(self.url, HTTP_X_FORWARDED_HOST=host)

    def host(self, user, lab="xss_lab", domain="lvh.me"):
        return f"lab-u{user.pk}-{lab}.{domain}"

    def test_owner_is_allowed(self):
        resp = self.verify(self.host(self.alice), self.alice)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["X-Forwarded-User"], "alice")

    def test_host_with_port_and_mixed_case_is_allowed(self):
        resp = self.verify(f"LAB-U{self.alice.pk}-XSS_lab.lvh.me:80", self.alice)
        self.assertEqual(resp.status_code, 200)

    def test_anonymous_is_rejected(self):
        self.assertEqual(self.verify(self.host(self.alice)).status_code, 401)

    def test_other_users_lab_is_forbidden(self):
        self.assertEqual(self.verify(self.host(self.alice_bob), self.alice).status_code, 403)
        self.assertEqual(self.verify(self.host(self.alice), self.alice_bob).status_code, 403)

    def test_username_based_host_is_forbidden(self):
        self.assertEqual(self.verify("lab-alice-xss_lab.lvh.me", self.alice).status_code, 403)

    def test_colliding_sanitized_username_is_forbidden(self):
        # "al.ice" used to sanitize to "alice" and share alice's labs
        mallory = User.objects.create_user("al.ice", password="pw")
        self.assertEqual(self.verify(self.host(self.alice), mallory).status_code, 403)
        self.assertEqual(self.verify(self.host(mallory), mallory).status_code, 200)

    def test_user_id_prefix_does_not_match_longer_id(self):
        other = User.objects.create_user("other", password="pw", pk=int(f"{self.alice.pk}2"))
        self.assertEqual(self.verify(self.host(other), self.alice).status_code, 403)

    def test_unknown_lab_is_forbidden(self):
        resp = self.verify(self.host(self.alice, lab="not_a_lab"), self.alice)
        self.assertEqual(resp.status_code, 403)

    def test_foreign_domain_is_rejected(self):
        resp = self.verify(self.host(self.alice, domain="evil.com"), self.alice)
        self.assertEqual(resp.status_code, 400)

    def test_missing_forwarded_host_is_rejected(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self.url).status_code, 400)


class RegistrationAndRobotsTests(TestCase):
    def test_register_creates_and_logs_in_user(self):
        resp = self.client.post("/register", {
            "username": "newbie", "email": "n@example.com",
            "password1": "Sup3r-Secret-pw!", "password2": "Sup3r-Secret-pw!",
        })
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(User.objects.filter(username="newbie").exists())
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_robots_redirects_anonymous_instead_of_500(self):
        self.assertEqual(self.client.get("/robots.txt").status_code, 302)

    def test_robots_served_to_logged_in_user(self):
        self.client.force_login(User.objects.create_user("u", password="pw"))
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/plain")


class LegacyIntegratedLabCleanupTests(TestCase):
    def test_removed_csrf_model_is_not_registered(self):
        model_names = {model.__name__ for model in apps.get_models()}
        self.assertNotIn("CSRF_user_tbl", model_names)
