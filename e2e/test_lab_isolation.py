"""
End-to-end lab isolation tests against a running PyGoat stack (web + Traefik
+ Docker), driven over HTTP like a browser user.

    docker compose up -d --build
    PYGOAT_E2E=1 python -m unittest discover -s e2e -v

Env: PYGOAT_URL (default http://lvh.me:8000), PYGOAT_LAB_DOMAIN (lvh.me), PYGOAT_E2E_LAB (xss_lab).
"""
import os
import re
import time
import unittest
import uuid
from urllib.parse import urlparse

import requests

BASE_URL = os.environ.get("PYGOAT_URL", "http://lvh.me:8000").rstrip("/")
LAB_DOMAIN = os.environ.get("PYGOAT_LAB_DOMAIN", "lvh.me")
LAB = os.environ.get("PYGOAT_E2E_LAB", "xss_lab")
START_TIMEOUT = int(os.environ.get("PYGOAT_E2E_START_TIMEOUT", "900"))
ROUTE_TIMEOUT = int(os.environ.get("PYGOAT_E2E_ROUTE_TIMEOUT", "60"))


def register(username: str) -> requests.Session:
    s = requests.Session()
    s.get(f"{BASE_URL}/register", timeout=30).raise_for_status()
    password = f"E2e-{uuid.uuid4().hex}"
    resp = s.post(
        f"{BASE_URL}/register",
        data={
            "csrfmiddlewaretoken": s.cookies["csrftoken"],
            "username": username,
            "email": f"{uuid.uuid4().hex[:8]}@example.com",
            "password1": password,
            "password2": password,
        },
        headers={"Referer": f"{BASE_URL}/register"},
        allow_redirects=False,
        timeout=30,
    )
    if resp.status_code != 302:
        raise AssertionError(f"registering {username!r} failed: HTTP {resp.status_code}")
    return s


def api(session: requests.Session, path: str, timeout=30) -> requests.Response:
    return session.get(f"{BASE_URL}/challenge/{path}", timeout=timeout)


def lab_get(session, url: str) -> requests.Response:
    return session.get(url, allow_redirects=False, timeout=30)


def wait_for_lab(session, url: str) -> requests.Response:
    """Traefik picks up a new container's route a few seconds after it is healthy."""
    deadline = time.time() + ROUTE_TIMEOUT
    while True:
        resp = lab_get(session, url)
        if resp.status_code != 404 or time.time() > deadline:
            return resp
        time.sleep(2)


def start(session) -> str:
    resp = api(session, f"start-lab/{LAB}/", timeout=START_TIMEOUT)
    body = resp.json()
    if resp.status_code != 200:
        raise AssertionError(f"start-lab failed: HTTP {resp.status_code} {body}")
    return body["url"]


def container_name(url: str) -> str:
    return urlparse(url).hostname.split(".")[0]


def lab_names(session):
    resp = api(session, "list-labs/")
    resp.raise_for_status()
    return {lab["name"]: lab["status"] for lab in resp.json()["labs"]}


@unittest.skipUnless(os.environ.get("PYGOAT_E2E") == "1", "set PYGOAT_E2E=1 to run against a live stack")
class LabIsolationE2E(unittest.TestCase):
    """
    The victim and attacker usernames used to sanitize to the same lab owner
    ("e2exxxx" vs "e2e.xxxx"), letting the attacker reach the victim's labs.
    """

    @classmethod
    def setUpClass(cls):
        suffix = uuid.uuid4().hex[:8]
        cls.victim = register(f"e2e{suffix}")
        cls.attacker = register(f"e2e.{suffix}")
        cls.victim_url = start(cls.victim)
        cls.victim_lab = container_name(cls.victim_url)

    @classmethod
    def tearDownClass(cls):
        for session in (cls.attacker, cls.victim):
            try:
                api(session, "stop-labs/", timeout=120)
            except requests.RequestException:
                pass
            session.close()

    def test_1_lab_is_named_after_user_id(self):
        self.assertRegex(self.victim_lab, rf"^pglab-u\d+-{re.escape(LAB)}$")
        self.assertTrue(urlparse(self.victim_url).hostname.endswith("." + LAB_DOMAIN))

    def test_2_owner_can_open_lab(self):
        self.assertEqual(wait_for_lab(self.victim, self.victim_url).status_code, 200)

    def test_3_anonymous_is_rejected(self):
        wait_for_lab(self.victim, self.victim_url)
        with requests.Session() as anonymous:
            self.assertEqual(lab_get(anonymous, self.victim_url).status_code, 401)

    def test_4_colliding_user_cannot_open_victim_lab(self):
        wait_for_lab(self.victim, self.victim_url)
        self.assertEqual(lab_get(self.attacker, self.victim_url).status_code, 403)

    def test_5_colliding_user_cannot_list_victim_lab(self):
        self.assertIn(self.victim_lab, lab_names(self.victim))
        self.assertNotIn(self.victim_lab, lab_names(self.attacker))

    def test_6_colliding_user_cannot_stop_victim_lab(self):
        self.assertEqual(api(self.attacker, f"stop-lab/{LAB}/", timeout=120).status_code, 404)
        resp = api(self.attacker, "stop-labs/", timeout=120)
        self.assertEqual(resp.json()["count"], 0)
        self.assertEqual(lab_names(self.victim).get(self.victim_lab), "running")
        self.assertEqual(wait_for_lab(self.victim, self.victim_url).status_code, 200)

    def test_7_colliding_user_gets_separate_lab(self):
        attacker_url = start(self.attacker)
        self.assertNotEqual(container_name(attacker_url), self.victim_lab)
        self.assertEqual(wait_for_lab(self.attacker, attacker_url).status_code, 200)
        self.assertEqual(lab_get(self.victim, attacker_url).status_code, 403)
        self.assertEqual(lab_get(self.attacker, self.victim_url).status_code, 403)

        api(self.attacker, "stop-labs/", timeout=120)
        self.assertEqual(lab_names(self.victim).get(self.victim_lab), "running")


if __name__ == "__main__":
    unittest.main()
