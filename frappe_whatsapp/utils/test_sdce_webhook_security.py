# SDCE security tests for the signed webhook and Embedded Signup (DEC-20261108-004).
import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import frappe
from frappe.utils.password import set_encrypted_password
from werkzeug.test import EnvironBuilder

from frappe_whatsapp.testing import IntegrationTestCase
from frappe_whatsapp.utils import embedded_signup, webhook

ACC = "SDCE Sec Test Account"
OTHER = "SDCE Sec Other Account"
SECRET = "sec-test-app-secret"
WABA = "111111111111111"
PHONE = "222222222222222"
VERIFY = "sec-test-verify-token"


def sign(raw: bytes, secret=SECRET):
	return "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def _jpeg_bytes():
	from io import BytesIO

	from PIL import Image

	buf = BytesIO()
	Image.new("RGB", (4, 4), (200, 10, 10)).save(buf, format="JPEG")
	return buf.getvalue()


def text_payload(mid="wamid.sec_text_1", waba=WABA, phone=PHONE, field="messages"):
	value = {
		"messaging_product": "whatsapp",
		"metadata": {"display_phone_number": "15550000000", "phone_number_id": phone},
		"contacts": [{"profile": {"name": "Sec Tester"}, "wa_id": "15550001111"}],
		"messages": [{"from": "15550001111", "id": mid, "timestamp": "1", "type": "text", "text": {"body": "hello"}}],
	}
	return {"object": "whatsapp_business_account", "entry": [{"id": waba, "changes": [{"field": field, "value": value}]}]}


class TestSDCEWebhookSecurity(IntegrationTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		for name, waba, phone, token, status in (
			(ACC, WABA, PHONE, VERIFY, "Active"),
			(OTHER, "333333333333333", "444444444444444", "other-verify", "Inactive"),
		):
			if not frappe.db.exists("WhatsApp Account", name):
				frappe.get_doc({
					"doctype": "WhatsApp Account", "account_name": name, "status": status,
					"url": "https://graph.facebook.com", "version": "v26.0", "phone_id": phone,
					"business_id": waba, "app_id": "999", "webhook_verify_token": token,
				}).insert(ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit -- fixture visible to later queries

	def setUp(self):
		set_encrypted_password("WhatsApp Account", ACC, SECRET, "app_secret")
		set_encrypted_password("WhatsApp Account", ACC, "sec-test-token", "token")
		set_encrypted_password("WhatsApp Account", OTHER, "inactive-secret", "app_secret")
		frappe.set_user("Guest")

	def tearDown(self):
		frappe.set_user("Administrator")
		for name in frappe.get_all("WhatsApp Message", filters={"message_id": ["like", "wamid.sec_%"]}, pluck="name"):
			frappe.delete_doc("WhatsApp Message", name, force=True, ignore_permissions=True)
		for name in frappe.get_all("WhatsApp Profiles", filters={"number": ["in", ["15550001111", "15550000000", "15550002222"]]}, pluck="name"):
			frappe.delete_doc("WhatsApp Profiles", name, force=True, ignore_permissions=True)
		for name in frappe.get_all("WhatsApp Notification Log", filters={"template": "Webhook"}, pluck="name"):
			frappe.delete_doc("WhatsApp Notification Log", name, force=True, ignore_permissions=True)
		for key in frappe.cache.keys("*frappe_whatsapp:wamid:wamid.sec_*"):
			frappe.cache.delete(key)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit -- cleanup

	# helpers -------------------------------------------------------------
	def _request(self, method="POST", raw=b"", headers=None, query=None):
		req = EnvironBuilder(
			method=method, data=raw, headers=headers or {}, query_string=query, content_type="application/json"
		).get_request()
		return patch.object(frappe.local, "request", req, create=True)

	def _post(self, payload=None, raw=None, signature="auto", secret=SECRET):
		raw = raw if raw is not None else json.dumps(payload).encode()
		headers = {}
		if signature == "auto":
			headers["X-Hub-Signature-256"] = sign(raw, secret)
		elif signature:
			headers["X-Hub-Signature-256"] = signature
		with self._request("POST", raw, headers):
			return webhook.webhook()

	def _counts(self):
		return (
			frappe.db.count("WhatsApp Message", {"message_id": ["like", "wamid.sec_%"]}),
			frappe.db.count("WhatsApp Notification Log", {"template": "Webhook"}),
		)

	# signature -----------------------------------------------------------
	def test_missing_signature_rejected_without_writes(self):
		before = self._counts()
		self.assertEqual(self._post(text_payload(), signature=None).status_code, 403)
		self.assertEqual(self._counts(), before)

	def test_invalid_signature_rejected(self):
		self.assertEqual(self._post(text_payload(), signature="sha256=" + "0" * 64).status_code, 403)
		self.assertEqual(self._post(text_payload(), signature="sha1=abc").status_code, 403)
		self.assertEqual(self._post(text_payload(), secret="wrong-secret").status_code, 403)
		self.assertEqual(self._counts(), (0, 0))

	def test_signature_covers_exact_raw_body(self):
		raw = json.dumps(text_payload()).encode()
		other = json.dumps(text_payload(), indent=2).encode()  # same JSON, different bytes
		self.assertEqual(self._post(raw=other, signature=sign(raw)).status_code, 403)
		self.assertEqual(self._counts(), (0, 0))

	def test_fail_closed_without_app_secret(self):
		frappe.db.delete("__Auth", {"doctype": "WhatsApp Account", "name": ACC, "fieldname": "app_secret"})
		self.assertEqual(self._post(text_payload()).status_code, 403)
		self.assertEqual(self._counts(), (0, 0))

	def test_inactive_account_secret_not_accepted(self):
		self.assertEqual(self._post(text_payload(), secret="inactive-secret").status_code, 403)

	def test_no_media_download_before_signature(self):
		payload = text_payload()
		payload["entry"][0]["changes"][0]["value"]["messages"][0] = {
			"from": "15550001111", "id": "wamid.sec_img_unsigned", "type": "image", "image": {"id": "m1"}}
		with patch("frappe_whatsapp.utils.webhook.requests.get") as get:
			self.assertEqual(self._post(payload, signature=None).status_code, 403)
			get.assert_not_called()

	# ingestion -----------------------------------------------------------
	def test_valid_text_is_stored_once(self):
		payload = text_payload()
		self.assertEqual(self._post(payload).status_code, 200)
		self.assertEqual(self._post(payload).status_code, 200)  # Meta retry
		frappe.cache.delete(frappe.cache.make_key("frappe_whatsapp:wamid:wamid.sec_text_1"))
		self.assertEqual(self._post(payload).status_code, 200)  # retry after lock expiry
		msgs = frappe.get_all("WhatsApp Message", filters={"message_id": "wamid.sec_text_1"},
			fields=["type", "whatsapp_account", "message", "from"])
		self.assertEqual(len(msgs), 1)
		self.assertEqual((msgs[0].type, msgs[0].whatsapp_account, msgs[0].message), ("Incoming", ACC, "hello"))

	def test_failed_request_releases_lock_for_retry(self):
		payload = text_payload(mid="wamid.sec_retry_1")
		payload["entry"][0]["changes"][0]["value"]["statuses"] = [{"id": "wamid.any", "status": "read"}]
		with patch("frappe_whatsapp.utils.webhook.update_message_status", side_effect=RuntimeError("boom")):
			with self.assertRaises(RuntimeError):
				self._post(payload)
		frappe.db.rollback()  # what Frappe does with the failed request
		set_encrypted_password("WhatsApp Account", ACC, SECRET, "app_secret")  # setUp value was rolled back too
		self.assertEqual(self._post(payload).status_code, 200)  # Meta retry
		self.assertEqual(frappe.db.count("WhatsApp Message", {"message_id": "wamid.sec_retry_1"}), 1)

	def test_wrong_waba_or_unknown_phone_not_stored(self):
		self._post(text_payload(mid="wamid.sec_wrongwaba", waba="555555555555555"))
		self._post(text_payload(mid="wamid.sec_wrongphone", phone="666666666666666"))
		self.assertFalse(frappe.db.exists("WhatsApp Message", {"message_id": ["in", ["wamid.sec_wrongwaba", "wamid.sec_wrongphone"]]}))

	def test_image_is_private_file(self):
		payload = text_payload()
		payload["entry"][0]["changes"][0]["value"]["messages"][0] = {
			"from": "15550001111", "id": "wamid.sec_img_1", "type": "image", "image": {"id": "m1", "caption": "cap"}}
		meta = MagicMock(status_code=200); meta.json.return_value = {"url": "https://lookaside.example/m1", "mime_type": "image/jpeg"}
		content = MagicMock(status_code=200, content=_jpeg_bytes())
		with patch("frappe_whatsapp.utils.webhook.requests.get", side_effect=[meta, content]):
			self.assertEqual(self._post(payload).status_code, 200)
		name = frappe.db.get_value("WhatsApp Message", {"message_id": "wamid.sec_img_1"})
		files = frappe.get_all("File", filters={"attached_to_doctype": "WhatsApp Message", "attached_to_name": name},
			fields=["is_private", "file_url"])
		self.assertEqual(len(files), 1)
		self.assertEqual(files[0].is_private, 1)
		self.assertTrue(files[0].file_url.startswith("/private/files/"))
		self.assertEqual(frappe.db.get_value("WhatsApp Message", name, "attach"), files[0].file_url)

	def test_corrupt_media_keeps_message(self):
		payload = text_payload()
		payload["entry"][0]["changes"][0]["value"]["messages"][0] = {
			"from": "15550001111", "id": "wamid.sec_img_bad", "type": "image", "image": {"id": "m2"}}
		meta = MagicMock(status_code=200); meta.json.return_value = {"url": "https://lookaside.example/m2", "mime_type": "image/jpeg"}
		content = MagicMock(status_code=200, content=b"\xff\xd8\xff\xe0broken")
		with patch("frappe_whatsapp.utils.webhook.requests.get", side_effect=[meta, content]):
			self.assertEqual(self._post(payload).status_code, 200)
		name = frappe.db.get_value("WhatsApp Message", {"message_id": "wamid.sec_img_bad"})
		self.assertTrue(name)
		self.assertFalse(frappe.db.get_value("WhatsApp Message", name, "attach"))

	def test_echo_recorded_as_outgoing_without_sending(self):
		value = {
			"messaging_product": "whatsapp",
			"metadata": {"display_phone_number": "15550000000", "phone_number_id": PHONE},
			"message_echoes": [{"from": "15550000000", "to": "15550001111", "id": "wamid.sec_echo_1",
				"timestamp": "1", "type": "text", "text": {"body": "sent from phone"}}],
		}
		payload = {"object": "whatsapp_business_account", "entry": [{"id": WABA, "changes": [{"field": "smb_message_echoes", "value": value}]}]}
		with patch("frappe_whatsapp.frappe_whatsapp.doctype.whatsapp_message.whatsapp_message.WhatsAppMessage.send_outgoing") as send, \
			patch("frappe.integrations.utils.make_post_request") as post:
			self.assertEqual(self._post(payload).status_code, 200)
			send.assert_not_called(); post.assert_not_called()
		row = frappe.db.get_value("WhatsApp Message", {"message_id": "wamid.sec_echo_1"}, ["type", "to", "message", "from"], as_dict=True)
		self.assertEqual((row.type, row.to, row.message), ("Outgoing", "15550001111", "sent from phone"))
		self.assertFalse(row["from"])
		self.assertFalse(frappe.db.exists("WhatsApp Profiles", {"number": "15550000000"}))

	def test_history_and_state_sync_not_ingested(self):
		for field in ("history", "smb_app_state_sync"):
			payload = text_payload(mid=f"wamid.sec_{field}", field=field)
			self.assertEqual(self._post(payload).status_code, 200)
		self.assertEqual(self._counts()[0], 0)

	def test_unknown_status_is_ignored(self):
		value = {"metadata": {"phone_number_id": PHONE}, "statuses": [{"id": "wamid.sec_nope", "status": "read"}]}
		payload = {"object": "whatsapp_business_account", "entry": [{"id": WABA, "changes": [{"field": "messages", "value": value}]}]}
		self.assertEqual(self._post(payload).status_code, 200)

	def test_other_message_types_and_template_status(self):
		base = text_payload()
		msgs = [
			{"from": "15550001111", "id": "wamid.sec_react", "type": "reaction", "reaction": {"message_id": "wamid.x", "emoji": "👍"}},
			{"from": "15550001111", "id": "wamid.sec_btn", "type": "button", "button": {"text": "Yes", "payload": "y"}},
			{"from": "15550001111", "id": "wamid.sec_list", "type": "interactive", "interactive": {"type": "list_reply", "list_reply": {"id": "opt1", "title": "Opt"}}},
			{"from": "15550001111", "id": "wamid.sec_reply", "type": "text", "text": {"body": "re"}, "context": {"from": "15550000000", "id": "wamid.orig"}},
		]
		base["entry"][0]["changes"][0]["value"]["messages"] = msgs
		self.assertEqual(self._post(base).status_code, 200)
		rows = {r.message_id: r for r in frappe.get_all("WhatsApp Message", filters={"message_id": ["in", [m["id"] for m in msgs]]},
			fields=["message_id", "content_type", "message", "is_reply", "reply_to_message_id"])}
		self.assertEqual(rows["wamid.sec_react"].reply_to_message_id, "wamid.x")
		self.assertEqual((rows["wamid.sec_btn"].content_type, rows["wamid.sec_btn"].message), ("button", "Yes"))
		self.assertEqual((rows["wamid.sec_list"].content_type, rows["wamid.sec_list"].message), ("button", "opt1"))
		self.assertEqual((rows["wamid.sec_reply"].is_reply, rows["wamid.sec_reply"].reply_to_message_id), (1, "wamid.orig"))
		tpl = {"object": "whatsapp_business_account", "entry": [{"id": WABA, "changes": [{"field": "message_template_status_update",
			"value": {"event": "APPROVED", "message_template_id": "1234", "message_template_name": "t"}}]}]}
		with patch("frappe_whatsapp.utils.webhook.update_template_status") as upd:
			self.assertEqual(self._post(tpl).status_code, 200)
			upd.assert_called_once()
		tpl["entry"][0]["id"] = "555555555555555"
		with patch("frappe_whatsapp.utils.webhook.update_template_status") as upd:
			self._post(tpl)
			upd.assert_not_called()

	def test_malformed_message_skipped_valid_one_stored(self):
		payload = text_payload(mid="wamid.sec_ok_2")
		payload["entry"][0]["changes"][0]["value"]["messages"].insert(0, {
			"from": "15550001111", "id": "wamid.sec_bad_2", "type": "interactive", "interactive": {"type": "button_reply"}})
		self.assertEqual(self._post(payload).status_code, 200)
		self.assertTrue(frappe.db.exists("WhatsApp Message", {"message_id": "wamid.sec_ok_2"}))
		self.assertFalse(frappe.db.exists("WhatsApp Message", {"message_id": "wamid.sec_bad_2"}))

	def test_status_update_scoped_to_account(self):
		frappe.set_user("Administrator")
		other = frappe.get_doc({"doctype": "WhatsApp Message", "type": "Incoming", "from": "15550002222",
			"message": "x", "message_id": "wamid.sec_other_acc", "content_type": "text", "whatsapp_account": OTHER})
		other.flags.skip_meta_send = True
		other.insert(ignore_permissions=True)
		frappe.set_user("Guest")
		value = {"metadata": {"phone_number_id": PHONE},
			"statuses": [{"id": "wamid.sec_other_acc", "status": "read"}, {"status": "read"}]}
		payload = {"object": "whatsapp_business_account", "entry": [{"id": WABA, "changes": [{"field": "messages", "value": value}]}]}
		self.assertEqual(self._post(payload).status_code, 200)
		self.assertNotEqual(frappe.db.get_value("WhatsApp Message", other.name, "status"), "read")

	def test_signup_rejects_non_coexistence_number_and_foreign_phone(self):
		frappe.set_user("Administrator")
		frappe.db.set_value("WhatsApp Account", ACC, "embedded_signup_config_id", "777")
		before = frappe.db.get_value("WhatsApp Account", ACC, ["business_id", "phone_id"])
		tok = MagicMock(status_code=200); tok.json.return_value = {"access_token": "T2"}
		nums = MagicMock(status_code=200); nums.json.return_value = {"data": [{"id": PHONE}]}
		info = MagicMock(status_code=200); info.json.return_value = {"is_on_biz_app": False, "platform_type": "CLOUD_API"}
		sub_path = "frappe_whatsapp.frappe_whatsapp.doctype.whatsapp_account.whatsapp_account.WhatsAppAccount.subscribe_app"
		state = embedded_signup.start_signup(ACC)["state"]
		with patch("frappe_whatsapp.utils.embedded_signup.requests.get", side_effect=[tok, nums, info]), patch(sub_path) as sub:
			with self.assertRaises(frappe.ValidationError):
				embedded_signup.complete_signup(state, "c", WABA, embedded_signup.COEXISTENCE_EVENT, PHONE)
			sub.assert_not_called()
		state = embedded_signup.start_signup(ACC)["state"]
		with patch("frappe_whatsapp.utils.embedded_signup.requests.get", side_effect=[tok, nums]):
			with self.assertRaises(frappe.ValidationError):
				embedded_signup.complete_signup(state, "c", WABA, embedded_signup.COEXISTENCE_EVENT, "888888888888888")
		self.assertEqual(frappe.db.get_value("WhatsApp Account", ACC, ["business_id", "phone_id"]), before)

	def test_signup_network_error_does_not_chain_secret(self):
		import requests as rq

		frappe.set_user("Administrator")
		frappe.db.set_value("WhatsApp Account", ACC, "embedded_signup_config_id", "777")
		state = embedded_signup.start_signup(ACC)["state"]
		err = rq.ConnectionError(f"failed for url ...client_secret={SECRET}")
		with patch("frappe_whatsapp.utils.embedded_signup.requests.get", side_effect=err):
			with self.assertRaises(frappe.ValidationError) as cm:
				embedded_signup.complete_signup(state, "c", WABA, embedded_signup.COEXISTENCE_EVENT, PHONE)
		self.assertTrue(cm.exception.__suppress_context__)
		self.assertIsNone(cm.exception.__cause__)
		self.assertNotIn(SECRET, str(cm.exception))

	# GET handshake -------------------------------------------------------
	def _get(self, query):
		with self._request("GET", b"", query=query):
			return webhook.webhook()

	def test_get_handshake(self):
		ok = self._get({"hub.mode": "subscribe", "hub.verify_token": VERIFY, "hub.challenge": "1158201444"})
		self.assertEqual((ok.status_code, ok.get_data(as_text=True)), (200, "1158201444"))
		self.assertEqual(self._get({"hub.mode": "subscribe", "hub.verify_token": "bad", "hub.challenge": "1"}).status_code, 403)
		self.assertEqual(self._get({"hub.verify_token": VERIFY, "hub.challenge": "1"}).status_code, 403)
		self.assertEqual(self._get({"hub.mode": "subscribe", "hub.verify_token": VERIFY, "hub.challenge": "<script>"}).status_code, 403)
		self.assertEqual(self._get({"hub.mode": "subscribe", "hub.verify_token": "other-verify", "hub.challenge": "1"}).status_code, 403)

	# routing / whitelisting ---------------------------------------------
	def test_whitelisting(self):
		from frappe_whatsapp.frappe_whatsapp.api import flow_endpoint
		self.assertIn(webhook.webhook, frappe.guest_methods)
		for fn in (webhook.post, webhook.get, flow_endpoint.handle_flow_request):
			with self.assertRaises(frappe.PermissionError):
				frappe.is_whitelisted(fn)

	# Embedded Signup -----------------------------------------------------
	def test_signup_requires_system_manager_and_valid_state(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.PermissionError):
			embedded_signup.start_signup(ACC)
		frappe.set_user("Administrator")
		with self.assertRaises(frappe.PermissionError):
			embedded_signup.complete_signup("bogus", "code", WABA, embedded_signup.COEXISTENCE_EVENT, PHONE)

	def test_signup_rejects_non_coexistence_and_is_single_use(self):
		frappe.set_user("Administrator")
		frappe.db.set_value("WhatsApp Account", ACC, "embedded_signup_config_id", "777")
		state = embedded_signup.start_signup(ACC)["state"]
		with self.assertRaises(frappe.ValidationError):
			embedded_signup.complete_signup(state, "code", WABA, "FINISH", PHONE)
		with self.assertRaises(frappe.PermissionError):  # state consumed
			embedded_signup.complete_signup(state, "code", WABA, embedded_signup.COEXISTENCE_EVENT, PHONE)

	def test_signup_success_stores_token_and_returns_no_secret(self):
		frappe.set_user("Administrator")
		frappe.db.set_value("WhatsApp Account", ACC, "embedded_signup_config_id", "777")
		state = embedded_signup.start_signup(ACC)["state"]
		tok = MagicMock(status_code=200); tok.json.return_value = {"access_token": "NEW-BUSINESS-TOKEN", "token_type": "bearer"}
		info = MagicMock(status_code=200); info.json.return_value = {
			"display_phone_number": "+1 555-000-0000", "verified_name": "SDCE", "is_on_biz_app": True, "platform_type": "CLOUD_API"}
		nums = MagicMock(status_code=200); nums.json.return_value = {"data": [{"id": PHONE}]}
		with patch("frappe_whatsapp.utils.embedded_signup.requests.get", side_effect=[tok, nums, info]) as get, \
			patch("frappe_whatsapp.frappe_whatsapp.doctype.whatsapp_account.whatsapp_account.WhatsAppAccount.subscribe_app") as sub, \
			patch("frappe_whatsapp.utils.embedded_signup.requests.post") as post:
			res = embedded_signup.complete_signup(state, "the-code", WABA, embedded_signup.COEXISTENCE_EVENT, PHONE)
			sub.assert_called_once(); post.assert_not_called()  # no /register
			self.assertEqual(get.call_args_list[0].kwargs["params"]["code"], "the-code")
		self.assertNotIn("NEW-BUSINESS-TOKEN", json.dumps(res))
		self.assertTrue(res["is_on_biz_app"])
		doc = frappe.get_doc("WhatsApp Account", ACC)
		self.assertEqual(doc.get_password("token"), "NEW-BUSINESS-TOKEN")
		self.assertEqual((doc.business_id, doc.phone_id), (WABA, PHONE))

	def test_long_access_token_saved_intact(self):
		"""Meta access tokens can exceed 300 characters; the Password field must keep them intact and encrypted."""
		frappe.set_user("Administrator")
		long_token = "EAA" + frappe.generate_hash(length=397)  # 400 characters
		doc = frappe.get_doc("WhatsApp Account", ACC)
		doc.token = long_token
		doc.save(ignore_permissions=True)
		self.assertEqual(len(doc.get_password("token")), 400)
		self.assertEqual(frappe.get_doc("WhatsApp Account", ACC).get_password("token"), long_token)
		self.assertNotEqual(frappe.db.get_value("WhatsApp Account", ACC, "token"), long_token)  # column holds a mask only
		self.assertEqual(frappe.get_meta("WhatsApp Account").get_field("token").fieldtype, "Password")
