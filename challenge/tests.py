import json
import os
import threading
import time
from unittest.mock import MagicMock, patch

import docker
from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from challenge.models import Challenge, Lab, UserChallenge
from challenge.views import (
    _ensure_image_built, _get_container_name, _resolve_build_path, _user_lab_lock, wait_for_health,
)


class DoItFastDockerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")
        self.client.force_login(self.user)
        self.chal = Challenge.objects.create(
            name="do-it-fast", docker_image="img", docker_port=5050, start_port=1,
            end_port=2, flag="flag{x}", point=100,
        )

    def _mock_run(self, get_client, container_id="abc123", host_port="49153"):
        container = get_client.return_value.containers.run.return_value
        container.id = container_id
        container.ports = {"5050/tcp": [{"HostPort": host_port}]}
        return container

    @patch("challenge.views.get_docker_client")
    def test_start_uses_docker_sdk_and_docker_assigned_port(self, get_client):
        self._mock_run(get_client)
        resp = self.client.post("/challenge/do-it-fast")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["endpoint"], "http://localhost:49153")
        get_client.return_value.containers.run.assert_called_once_with(
            "img", detach=True, ports={"5050/tcp": None}
        )
        user_chal = UserChallenge.objects.get()
        self.assertEqual((user_chal.container_id, user_chal.port, user_chal.is_live), ("abc123", 49153, True))

    @patch("challenge.views.get_docker_client", return_value=None)
    def test_start_without_docker_returns_503(self, _client):
        self.assertEqual(self.client.post("/challenge/do-it-fast").status_code, 503)

    @patch("challenge.views.get_docker_client")
    def test_start_failure_removes_container(self, get_client):
        container = self._mock_run(get_client)
        container.ports = {}  # exited immediately, no port published
        self.assertEqual(self.client.post("/challenge/do-it-fast").status_code, 500)
        container.remove.assert_called_once_with(force=True)
        self.assertFalse(UserChallenge.objects.exists())

    @patch("challenge.views.get_docker_client")
    def test_running_challenge_is_reused(self, get_client):
        UserChallenge.objects.create(user=self.user, challenge=self.chal, container_id="old", port=49000, is_live=True)
        get_client.return_value.containers.get.return_value.status = "running"
        resp = self.client.post("/challenge/do-it-fast")
        self.assertEqual(resp.json()["message"], "already running")
        get_client.return_value.containers.run.assert_not_called()

    @patch("challenge.views.get_docker_client")
    def test_dead_challenge_container_is_replaced(self, get_client):
        UserChallenge.objects.create(user=self.user, challenge=self.chal, container_id="old", port=49000, is_live=True)
        dead = MagicMock(status="exited")
        get_client.return_value.containers.get.return_value = dead
        self._mock_run(get_client, container_id="new")
        resp = self.client.post("/challenge/do-it-fast")
        self.assertEqual(resp.json()["message"], "success")
        dead.remove.assert_called_once_with(force=True)
        self.assertEqual(UserChallenge.objects.get().container_id, "new")

    @patch("challenge.views.get_docker_client")
    def test_missing_challenge_container_is_replaced(self, get_client):
        UserChallenge.objects.create(user=self.user, challenge=self.chal, container_id="gone", port=49000, is_live=True)
        get_client.return_value.containers.get.side_effect = docker.errors.NotFound("x")
        self._mock_run(get_client, container_id="new")
        self.assertEqual(self.client.post("/challenge/do-it-fast").json()["message"], "success")

    @patch("challenge.views.get_docker_client")
    def test_stop_removes_container(self, get_client):
        UserChallenge.objects.create(
            user=self.user, challenge=self.chal, container_id="abc123", port=8001, is_live=True
        )
        container = get_client.return_value.containers.get.return_value
        resp = self.client.delete("/challenge/do-it-fast")
        self.assertEqual(resp.status_code, 200)
        container.remove.assert_called_once_with(force=True)
        self.assertFalse(UserChallenge.objects.get().is_live)

    @patch("challenge.views.get_docker_client", return_value=None)
    def test_stop_without_docker_keeps_challenge_live(self, _client):
        UserChallenge.objects.create(user=self.user, challenge=self.chal, container_id="abc", port=8001, is_live=True)
        self.assertEqual(self.client.delete("/challenge/do-it-fast").status_code, 503)
        self.assertTrue(UserChallenge.objects.get().is_live)

    @patch("challenge.views.get_docker_client")
    def test_stop_error_keeps_challenge_live(self, get_client):
        UserChallenge.objects.create(user=self.user, challenge=self.chal, container_id="abc", port=8001, is_live=True)
        get_client.return_value.containers.get.return_value.remove.side_effect = docker.errors.APIError("boom")
        self.assertEqual(self.client.delete("/challenge/do-it-fast").status_code, 500)
        self.assertTrue(UserChallenge.objects.get().is_live)


class CustomLabPermissionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("bob", password="pw")
        self.staff = User.objects.create_user("admin", password="pw", is_staff=True)
        self.lab = Lab.objects.create(name="mine", build_location="dockerized_labs/xss_lab", port=5006)

    def post(self, url, data=None):
        return self.client.post(url, data=json.dumps(data or {}), content_type="application/json")

    def test_non_staff_cannot_create_update_or_delete(self):
        self.client.force_login(self.user)
        data = {"name": "x", "build_location": "dockerized_labs/xss_lab", "port": 1}
        self.assertEqual(self.post("/challenge/custom-labs/create/", data).status_code, 403)
        self.assertEqual(self.post(f"/challenge/custom-labs/update/{self.lab.id}/", data).status_code, 403)
        self.assertEqual(self.post(f"/challenge/custom-labs/delete/{self.lab.id}/").status_code, 403)
        self.assertTrue(Lab.objects.filter(pk=self.lab.pk).exists())

    def test_non_staff_can_still_list(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/challenge/custom-labs/list/").status_code, 200)

    def test_staff_cannot_use_paths_outside_lab_dirs(self):
        self.client.force_login(self.staff)
        for bad in ("/etc", "../../etc", "dockerized_labs/../pygoat", "introduction"):
            resp = self.post("/challenge/custom-labs/create/", {"name": "evil", "build_location": bad, "port": 80})
            self.assertEqual(resp.status_code, 400, bad)
        self.assertFalse(Lab.objects.filter(name="evil").exists())

    def test_staff_can_create_with_lab_dir(self):
        self.client.force_login(self.staff)
        resp = self.post("/challenge/custom-labs/create/",
                         {"name": "xss2", "build_location": "dockerized_labs/xss_lab", "port": 5006})
        self.assertEqual(resp.status_code, 200)

    def test_custom_labs_button_hidden_for_non_staff(self):
        self.client.force_login(self.user)
        self.assertNotContains(self.client.get("/"), 'id="custom-labs-btn"')
        self.client.force_login(self.staff)
        self.assertContains(self.client.get("/"), 'id="custom-labs-btn"')


class LabContainerTests(TestCase):
    def test_build_path_accepts_shipped_labs(self):
        for lab in ("dockerized_labs/xss_lab", "challenge/labs/bopla_lab"):
            self.assertTrue(os.path.isdir(_resolve_build_path(lab)))

    def test_build_removes_intermediate_containers(self):
        client = MagicMock()
        client.images.get.side_effect = docker.errors.ImageNotFound("x")
        _ensure_image_built(client, "xss_lab", "dockerized_labs/xss_lab")
        kwargs = client.images.build.call_args.kwargs
        self.assertTrue(kwargs["rm"])
        self.assertTrue(kwargs["forcerm"])

    def test_build_refuses_outside_path(self):
        client = MagicMock()
        client.images.get.side_effect = docker.errors.ImageNotFound("x")
        with self.assertRaises(ValueError):
            _ensure_image_built(client, "evil", "/etc")
        client.images.build.assert_not_called()

    def test_unhealthy_new_container_is_removed(self):
        container = MagicMock()
        container.attrs = {"State": {"Health": {"Status": "unhealthy"}}}
        with self.assertRaises(RuntimeError):
            wait_for_health(container)
        container.remove.assert_called_once_with(force=True)

    def test_unhealthy_existing_container_is_only_stopped(self):
        container = MagicMock()
        container.attrs = {"State": {"Health": {"Status": "unhealthy"}}}
        with self.assertRaises(RuntimeError):
            wait_for_health(container, remove_on_failure=False)
        container.stop.assert_called_once()
        container.remove.assert_not_called()

    def test_user_lab_lock_is_exclusive(self):
        dave = User.objects.create_user("dave", password="pw")
        order = []
        held = threading.Event()

        def first():
            with _user_lab_lock(dave):
                held.set()
                time.sleep(0.3)
                order.append("first-done")

        def second():
            held.wait()
            with _user_lab_lock(dave):
                order.append("second-in")

        threads = [threading.Thread(target=first), threading.Thread(target=second)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(order, ["first-done", "second-in"])


@override_settings(LABS_PER_USER_LIMIT=1)
class LabQuotaTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("carol", password="pw")
        self.client.force_login(self.user)
        Lab.objects.create(name="xss_lab", build_location="dockerized_labs/xss_lab", port=5006)

    def _container(self, lab, status, owner=None):
        owner = owner or self.user
        c = MagicMock()
        c.name, c.status = f"lab-u{owner.pk}-{lab}", status
        c.labels = {"pygoat.owner_id": str(owner.pk)}
        return c

    @patch("challenge.views.check_traefik_reachable", return_value=True)
    @patch("challenge.views.get_docker_client")
    def test_stopped_labs_do_not_count_toward_limit(self, get_client, _traefik):
        client = get_client.return_value
        client.containers.list.return_value = [self._container("sql_injection_lab", "exited")]
        client.containers.get.side_effect = docker.errors.NotFound("x")
        new = client.containers.create.return_value
        new.attrs = {"State": {"Health": {"Status": "healthy"}}}
        resp = self.client.get("/challenge/start-lab/xss_lab/")
        self.assertEqual(resp.status_code, 200, resp.content)
        new.put_archive.assert_called_once()
        new.start.assert_called_once()

    @patch("challenge.views.check_traefik_reachable", return_value=True)
    @patch("challenge.views.get_docker_client")
    def test_restarted_lab_failing_health_is_not_deleted(self, get_client, _traefik):
        client = get_client.return_value
        client.containers.list.return_value = []
        existing = self._container("xss_lab", "exited")
        existing.attrs = {"State": {"Health": {"Status": "unhealthy"}}}
        client.containers.get.return_value = existing
        resp = self.client.get("/challenge/start-lab/xss_lab/")
        self.assertEqual(resp.status_code, 500)
        existing.start.assert_called_once()
        existing.stop.assert_called_once()
        existing.remove.assert_not_called()
        client.containers.create.assert_not_called()

    @patch("challenge.views.check_traefik_reachable", return_value=True)
    @patch("challenge.views.get_docker_client")
    def test_running_labs_count_toward_limit(self, get_client, _traefik):
        get_client.return_value.containers.list.return_value = [
            self._container("sql_injection_lab", "running")
        ]
        get_client.return_value.containers.get.side_effect = docker.errors.NotFound("x")
        self.assertEqual(self.client.get("/challenge/start-lab/xss_lab/").status_code, 429)


class LabOwnerIdentityTests(TestCase):
    """Usernames that sanitize to the same string must not share labs."""

    def setUp(self):
        Lab.objects.create(name="xss_lab", build_location="dockerized_labs/xss_lab", port=5006)
        self.ab = User.objects.create_user("ab", password="pw")
        self.a_dot_b = User.objects.create_user("a.b", password="pw")
        lab = MagicMock()
        lab.name, lab.status = f"lab-u{self.ab.pk}-xss_lab", "running"
        lab.labels = {"pygoat.owner_id": str(self.ab.pk)}
        lab.attrs = {"State": {"Health": {"Status": "healthy"}}}
        self.ab_lab = lab
        # Same victim lab under the old sanitized-username naming scheme
        legacy = MagicMock()
        legacy.name, legacy.status = "lab-ab-xss_lab", "running"
        legacy.labels = {"pygoat.owner_id": str(self.ab.pk)}
        self.legacy_lab = legacy

    def _docker(self, get_client):
        client = get_client.return_value
        client.containers.list.return_value = [self.ab_lab, self.legacy_lab]
        client.containers.get.side_effect = (
            lambda name: self.ab_lab if name == self.ab_lab.name else (_ for _ in ()).throw(docker.errors.NotFound("x"))
        )
        client.containers.create.return_value.attrs = {"State": {"Health": {"Status": "healthy"}}}
        return client

    def test_container_names_use_distinct_user_ids(self):
        self.assertNotEqual(
            _get_container_name(self.ab, "xss_lab"), _get_container_name(self.a_dot_b, "xss_lab")
        )

    @patch("challenge.views.get_docker_client")
    def test_colliding_user_cannot_list_victim_labs(self, get_client):
        self._docker(get_client)
        self.client.force_login(self.a_dot_b)
        self.assertEqual(self.client.get("/challenge/list-labs/").json()["labs"], [])

    @patch("challenge.views.get_docker_client")
    def test_colliding_user_cannot_stop_victim_labs(self, get_client):
        self._docker(get_client)
        self.client.force_login(self.a_dot_b)
        self.assertEqual(self.client.get("/challenge/stop-lab/xss_lab/").status_code, 404)
        self.client.get("/challenge/stop-labs/")
        for lab in (self.ab_lab, self.legacy_lab):
            lab.stop.assert_not_called()
            lab.remove.assert_not_called()

    @patch("challenge.views.check_traefik_reachable", return_value=True)
    @patch("challenge.views.get_docker_client")
    def test_colliding_user_gets_own_container_not_victims(self, get_client, _traefik):
        client = self._docker(get_client)
        self.client.force_login(self.a_dot_b)
        resp = self.client.get("/challenge/start-lab/xss_lab/")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertIn(f"lab-u{self.a_dot_b.pk}-xss_lab.", resp.json()["url"])
        kwargs = client.containers.create.call_args.kwargs
        self.assertEqual(kwargs["name"], f"lab-u{self.a_dot_b.pk}-xss_lab")
        self.assertEqual(kwargs["labels"]["pygoat.owner_id"], str(self.a_dot_b.pk))

    @patch("challenge.views.check_traefik_reachable", return_value=True)
    @patch("challenge.views.get_docker_client")
    def test_container_with_foreign_owner_label_is_not_reused(self, get_client, _traefik):
        client = self._docker(get_client)
        self.ab_lab.labels = {"pygoat.owner_id": str(self.a_dot_b.pk)}
        self.client.force_login(self.ab)
        self.assertEqual(self.client.get("/challenge/start-lab/xss_lab/").status_code, 409)
        client.containers.create.assert_not_called()
