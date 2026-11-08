"""Meta WhatsApp Cloud API webhook.

SDCE hardening (DEC-20261108-004):
- POST is accepted only with a valid X-Hub-Signature-256 (HMAC-SHA256 of the exact raw body, keyed with the
  App Secret of an Active WhatsApp Account, compared in constant time). Missing/invalid signature or no
  configured App Secret -> 403 before any parsing, logging, DB write or media download (fail closed).
- GET verification requires hub.mode=subscribe and a matching verify token of an Active account.
- Every change is scoped to the Active account whose business_id (WABA ID) and phone_id match the payload.
- Messages are idempotent on the Meta message id (Meta retries deliveries for up to 7 days).
- Media is stored as private files.
- Coexistence echoes (smb_message_echoes) are recorded as Outgoing messages without sending anything.
"""
import hashlib
import hmac
import json
import re

import frappe
import requests
from frappe import _
from frappe.utils.password import get_decrypted_password
from werkzeug.wrappers import Response

SIGNATURE_HEADER = "X-Hub-Signature-256"
CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")
MEDIA_TYPES = ("image", "audio", "video", "document", "sticker")
LOCK_SECONDS = 600


@frappe.whitelist(allow_guest=True, methods=["GET", "POST"])
def webhook():
	"""Meta webhook (guest, signature-protected). Reason recorded in DECISIONS.md (DEC-20261108-004)."""
	if frappe.request.method == "GET":
		return get()
	return post()


def _reject(status=403):
	# Also set the status on frappe.local.response: the deprecated `cmd` route ignores returned Response objects.
	frappe.local.response["http_status_code"] = status
	return Response("", status=status)


def get():
	"""Webhook verification handshake."""
	args = frappe.request.args
	mode = args.get("hub.mode") or ""
	token = args.get("hub.verify_token") or ""
	challenge = args.get("hub.challenge") or ""
	if mode != "subscribe" or not token or not CHALLENGE_RE.match(challenge):
		return _reject()

	tokens = frappe.get_all(
		"WhatsApp Account",
		filters={"status": "Active", "webhook_verify_token": ["is", "set"]},
		pluck="webhook_verify_token",
	)
	if not any(hmac.compare_digest(token.encode(), (t or "").encode()) for t in tokens):
		return _reject()

	return Response(challenge, status=200, mimetype="text/plain")


def verified_accounts(raw_body: bytes) -> list[str]:
	"""Return Active accounts whose App Secret signs raw_body. Empty list = reject."""
	header = frappe.get_request_header(SIGNATURE_HEADER) or ""
	if not header.startswith("sha256="):
		return []
	provided = header[len("sha256=") :].strip().lower()
	if not provided:
		return []

	matched = []
	for name in frappe.get_all("WhatsApp Account", filters={"status": "Active"}, pluck="name"):
		secret = get_decrypted_password("WhatsApp Account", name, "app_secret", raise_exception=False)
		if not secret:
			continue
		expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
		if hmac.compare_digest(expected, provided):
			matched.append(name)
	return matched


def post():
	"""Receive notifications. Signature is checked before anything else."""
	raw_body = frappe.request.get_data(cache=True) or b""
	accounts = verified_accounts(raw_body)
	if not accounts:
		return _reject()

	try:
		data = json.loads(raw_body)
	except ValueError:
		return _reject(400)
	if not isinstance(data, dict) or data.get("object") != "whatsapp_business_account":
		return Response("", status=200)

	frappe.get_doc({
		"doctype": "WhatsApp Notification Log",
		"template": "Webhook",
		"meta_data": json.dumps(data),
	}).insert(ignore_permissions=True)

	frappe.local.fwa_locks = []
	try:
		for entry in data.get("entry") or []:
			waba_id = str(entry.get("id") or "")
			for change in entry.get("changes") or []:
				process_change(waba_id, change, accounts)
	except Exception:
		# The request transaction is rolled back; release the dedupe locks so Meta's retry is processed.
		for key in frappe.local.fwa_locks:
			frappe.cache.delete(key)
		raise
	return Response("", status=200)


def scoped_account(waba_id, phone_id, accounts):
	"""The single Active, signature-verified account for this WABA (and phone, when given)."""
	if not waba_id:
		return None
	filters = {"name": ["in", accounts], "status": "Active", "business_id": waba_id}
	if phone_id:
		filters["phone_id"] = phone_id
	names = frappe.get_all("WhatsApp Account", filters=filters, pluck="name")
	return frappe.get_doc("WhatsApp Account", names[0]) if len(names) == 1 else None


def process_change(waba_id, change, accounts):
	field = change.get("field")
	value = change.get("value") or {}
	phone_id = (value.get("metadata") or {}).get("phone_number_id")

	if field == "message_template_status_update":
		if waba_id and frappe.db.exists(
			"WhatsApp Account", {"name": ["in", accounts], "status": "Active", "business_id": waba_id}
		):
			update_template_status(value)
		return

	if field not in ("messages", "smb_message_echoes"):
		# history, smb_app_state_sync, account_update, ...: kept in the Notification Log only.
		return

	account = scoped_account(waba_id, phone_id, accounts)
	if not account:
		# Signed by our app but no single Active account matches this WABA/phone: never fall back to a default.
		frappe.log_error("WhatsApp webhook: no matching account", f"field={field} waba={waba_id} phone_number_id={phone_id}")
		return

	profile_name = next(
		(c.get("profile", {}).get("name") for c in value.get("contacts") or [] if c.get("profile")), None
	)
	for message in value.get("messages") or []:
		ingest_message(message, account, profile_name, "Incoming")
	for echo in value.get("message_echoes") or []:
		ingest_message(echo, account, None, "Outgoing")
	if value.get("statuses"):
		update_message_status(value, account.name)


def ingest_message(message, account, profile_name, direction):
	"""Create one WhatsApp Message, at most once per Meta message id."""
	message_id = message.get("id")
	if not message_id or frappe.db.exists("WhatsApp Message", {"message_id": message_id}):
		return
	try:
		fields, media_id, flow_response = message_fields(message, account, profile_name, direction)
	except (KeyError, TypeError, AttributeError, ValueError):
		# One malformed message must not fail the whole delivery (Meta would retry it for 7 days).
		frappe.log_error("WhatsApp webhook: malformed message skipped", f"id={message_id} type={message.get('type')}")
		return
	lock_key = frappe.cache.make_key(f"frappe_whatsapp:wamid:{message_id}")
	if not frappe.cache.set(lock_key, 1, nx=True, ex=LOCK_SECONDS):
		return
	getattr(frappe.local, "fwa_locks", []).append(lock_key)
	try:
		doc = frappe.get_doc(fields)
		doc.flags.skip_meta_send = True  # never send anything to Meta for webhook-created messages
		doc.insert(ignore_permissions=True)
	except Exception:
		frappe.cache.delete(lock_key)
		raise
	if media_id:
		attach_media(doc, account, media_id)
	if flow_response is not None:
		frappe.publish_realtime(  # nosemgrep: frappe-realtime-pick-room -- upstream behaviour: site-wide event for chat UIs
			"whatsapp_flow_response",
			{"phone": message.get("from"), "message_id": message_id, "flow_response": flow_response,
				"whatsapp_account": account.name},
		)


def message_fields(message, account, profile_name, direction):
	"""Map one Meta message to WhatsApp Message fields. Raises KeyError/TypeError on malformed input."""
	message_type = message.get("type")
	context = message.get("context") or {}
	is_reply = bool(context.get("id")) and "forwarded" not in context
	fields = {
		"doctype": "WhatsApp Message",
		"type": direction,
		"message_id": message["id"],
		"reply_to_message_id": context.get("id") if is_reply else None,
		"is_reply": is_reply,
		"content_type": message_type,
		"profile_name": profile_name,
		"whatsapp_account": account.name,
	}
	if direction == "Incoming":
		fields["from"] = message.get("from")
	else:
		# Echo of a message sent from the phone app: the counterpart is `to`; `from` is our own number.
		fields.update({"to": message.get("to"), "message_type": "Manual"})

	media_id = None
	flow_response = None
	if message_type == "text":
		fields["message"] = (message.get("text") or {}).get("body")
	elif message_type == "reaction":
		fields["message"] = message["reaction"].get("emoji")
		fields["reply_to_message_id"] = message["reaction"].get("message_id")
	elif message_type == "interactive":
		interactive = message["interactive"]
		itype = interactive.get("type")
		if itype in ("button_reply", "list_reply"):
			fields.update({"message": interactive[itype]["id"], "content_type": "button"})
		elif itype == "nfm_reply":
			try:
				flow_response = json.loads(interactive["nfm_reply"].get("response_json") or "{}")
			except json.JSONDecodeError:
				flow_response = {}
			if not isinstance(flow_response, dict):
				flow_response = {}
			parts = [f"{k}: {v}" for k, v in flow_response.items() if v]
			fields.update({
				"message": ", ".join(parts) or "Flow completed",
				"content_type": "flow",
				"flow_response": json.dumps(flow_response),
			})
		else:
			fields.update({"message": json.dumps(interactive), "content_type": "interactive"})
	elif message_type == "order":
		fields.update({"message": _("New Order Received via WhatsApp"), "product_catalog_json": json.dumps(message["order"])})
	elif message_type in MEDIA_TYPES:
		media = message.get(message_type) or {}
		media_id = media.get("id")
		fields["message"] = media.get("caption", "")
		if message_type == "sticker":
			fields["content_type"] = "image"
	elif message_type == "button":
		fields["message"] = (message.get("button") or {}).get("text")
	else:
		payload = message.get(message_type)
		fields["message"] = payload.get(message_type) if isinstance(payload, dict) else None
		allowed = frappe.get_meta("WhatsApp Message").get_field("content_type").options.split("\n")
		if message_type not in allowed:
			fields["content_type"] = "text"
			fields["message"] = fields["message"] or f"[{message_type}]"

	return fields, media_id, flow_response


def attach_media(doc, account, media_id):
	"""Download media with the account token and attach it as a PRIVATE file."""
	token = account.get_password("token", raise_exception=False)
	if not token:
		return
	headers = {"Authorization": f"Bearer {token}"}
	base = f"{account.url}/{account.version}/"
	try:
		meta = requests.get(f"{base}{media_id}/", headers=headers, timeout=30)
		if meta.status_code != 200:
			return
		media_url = meta.json().get("url")
		mime_type = meta.json().get("mime_type") or "application/octet-stream"
		content = requests.get(media_url, headers=headers, timeout=60)
		if content.status_code != 200:
			return
	except (requests.RequestException, ValueError):
		frappe.log_error("WhatsApp media download failed", f"message {doc.name}")
		return

	extension = re.sub(r"[^a-z0-9]", "", mime_type.split("/")[-1].split(";")[0].lower())[:10] or "bin"
	savepoint = "fwa_media"
	frappe.db.savepoint(savepoint)
	try:
		file = frappe.get_doc({
			"doctype": "File",
			"file_name": f"{frappe.generate_hash(length=10)}.{extension}",
			"attached_to_doctype": "WhatsApp Message",
			"attached_to_name": doc.name,
			"attached_to_field": "attach",
			"is_private": 1,
			"content": content.content,
		}).insert(ignore_permissions=True)
	except Exception:
		# A broken media file must not drop the message or make Meta retry forever.
		frappe.db.rollback(save_point=savepoint)
		frappe.log_error("WhatsApp media could not be stored", f"message {doc.name}")
		return
	frappe.db.release_savepoint(savepoint)
	doc.db_set("attach", file.file_url)


def update_template_status(data):
	"""Update template status."""
	frappe.db.sql(
		"""UPDATE `tabWhatsApp Templates`
		SET status = %(event)s
		WHERE id = %(message_template_id)s""",
		data,
	)


def update_message_status(data, account=None):
	"""Update message status, scoped to the account; unknown or missing message ids are ignored."""
	for status in data.get("statuses") or []:
		if not status.get("id"):
			continue
		filters = {"message_id": status["id"]}
		if account:
			filters["whatsapp_account"] = account
		name = frappe.db.get_value("WhatsApp Message", filters=filters)
		if not name:
			continue
		doc = frappe.get_doc("WhatsApp Message", name)
		doc.status = status.get("status")
		conversation = (status.get("conversation") or {}).get("id")
		if conversation:
			doc.conversation_id = conversation
		doc.save(ignore_permissions=True)
