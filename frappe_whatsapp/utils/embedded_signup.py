"""SDCE: Embedded Signup for WhatsApp Business app onboarding (Coexistence) — DEC-20261108-004.

Flow: a System Manager opens the "whatsapp-signup" Desk page, which calls start_signup() (one-time state bound to
the user and account), launches FB.login with the account's Embedded Signup configuration and featureType
whatsapp_business_app_onboarding, and posts the returned code + WABA/phone ids to complete_signup().
complete_signup() exchanges the code server-side (code TTL is 30 s), stores the business token in the encrypted
Password field, verifies the phone is a business-app (coexistence) number, and subscribes the app to the WABA.
Phone registration (/register) is deliberately NOT called: coexistence numbers are already registered.
Secrets and tokens are never returned, logged or included in error messages.
"""
import re

import frappe
import requests
from frappe import _

STATE_TTL = 600
COEXISTENCE_EVENT = "FINISH_WHATSAPP_BUSINESS_APP_ONBOARDING"
ID_RE = re.compile(r"^\d{5,25}$")


def _state_key(state):
	return f"frappe_whatsapp:es_state:{state}"


def _account_for_write(account):
	frappe.only_for("System Manager")
	doc = frappe.get_doc("WhatsApp Account", account)
	doc.check_permission("write")
	return doc


@frappe.whitelist(methods=["POST"])
def start_signup(account):
	doc = _account_for_write(account)
	missing = [f for f in ("app_id", "embedded_signup_config_id", "url", "version") if not doc.get(f)]
	if not doc.get_password("app_secret", raise_exception=False):
		missing.append("app_secret")
	if missing:
		frappe.throw(_("Set these fields on the WhatsApp Account first: {0}").format(", ".join(missing)))
	state = frappe.generate_hash(length=40)
	frappe.cache.set_value(
		_state_key(state), {"user": frappe.session.user, "account": doc.name}, expires_in_sec=STATE_TTL
	)
	return {
		"state": state,
		"app_id": doc.app_id,
		"config_id": doc.embedded_signup_config_id,
		"graph_version": doc.version,
	}


def _graph_get(doc, path, token=None, params=None):
	"""GET on the Graph API. Errors never echo the URL, query (may hold the secret) or token."""
	headers = {"Authorization": f"Bearer {token}"} if token else {}
	response = None
	try:
		response = requests.get(f"{doc.url}/{doc.version}/{path}", params=params, headers=headers, timeout=30)
	except requests.RequestException:
		pass  # do not chain: the exception text can contain the request URL (client_secret / code)
	if response is None:
		raise frappe.ValidationError(_("Could not reach Meta Graph API ({0})").format(path.split("/")[-1])) from None
	if response.status_code != 200:
		try:
			err = response.json().get("error", {})
			detail = f"{err.get('type', '')} {err.get('code', '')}: {err.get('message', '')}"
		except ValueError:
			detail = f"HTTP {response.status_code}"
		frappe.throw(_("Meta Graph API error: {0}").format(frappe.utils.escape_html(detail[:300])))
	return response.json()


@frappe.whitelist(methods=["POST"])
def complete_signup(state, code, waba_id, event, phone_number_id=None):
	data = frappe.cache.get_value(_state_key(state)) if state else None
	frappe.cache.delete_value(_state_key(state))
	if not data or data.get("user") != frappe.session.user:
		frappe.throw(_("Signup session expired or invalid. Start again."), frappe.PermissionError)
	doc = _account_for_write(data["account"])

	if event != COEXISTENCE_EVENT:
		frappe.throw(_("Only WhatsApp Business app onboarding (Coexistence) is accepted. Received: {0}").format(
			frappe.utils.escape_html(str(event)[:60])))
	if not ID_RE.match(str(waba_id or "")) or (phone_number_id and not ID_RE.match(str(phone_number_id))):
		frappe.throw(_("Invalid WABA or phone number id"))
	if not code or len(code) > 2048:
		frappe.throw(_("Missing authorization code"))

	token = _graph_get(doc, "oauth/access_token", params={
		"client_id": doc.app_id,
		"client_secret": doc.get_password("app_secret"),
		"code": code,
	}).get("access_token")
	if not token:
		frappe.throw(_("Meta did not return an access token"))

	numbers = [str(n.get("id")) for n in
		(_graph_get(doc, f"{waba_id}/phone_numbers", token, {"fields": "id"}).get("data") or [])]
	if phone_number_id:
		if str(phone_number_id) not in numbers:
			frappe.throw(_("Phone number id {0} does not belong to WABA {1}").format(phone_number_id, waba_id))
	elif len(numbers) == 1:
		phone_number_id = numbers[0]
	else:
		frappe.throw(_("Expected exactly one phone number on WABA {0}, found {1}").format(waba_id, len(numbers)))

	info = _graph_get(doc, str(phone_number_id), token, {
		"fields": "display_phone_number,verified_name,is_on_biz_app,platform_type,code_verification_status",
	})
	if info.get("is_on_biz_app") is not True or info.get("platform_type") != "CLOUD_API":
		frappe.throw(_("Not a coexistence number (is_on_biz_app={0}, platform_type={1}). Nothing saved.").format(
			frappe.utils.escape_html(str(info.get("is_on_biz_app"))), frappe.utils.escape_html(str(info.get("platform_type")))))

	doc.token = token
	doc.business_id = str(waba_id)
	doc.phone_id = str(phone_number_id)
	doc.save()
	doc.subscribe_app()
	return {
		"waba_id": doc.business_id,
		"phone_number_id": doc.phone_id,
		"display_phone_number": info.get("display_phone_number"),
		"verified_name": info.get("verified_name"),
		"is_on_biz_app": info.get("is_on_biz_app"),
		"platform_type": info.get("platform_type"),
	}
