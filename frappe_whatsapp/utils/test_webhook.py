# Copyright (c) 2025, Shridhar Patil and Contributors
# See license.txt

import frappe
from frappe_whatsapp.testing import IntegrationTestCase

from frappe_whatsapp.utils.webhook import (
    update_message_status,
    update_template_status,
)


class TestWebhookHelpers(IntegrationTestCase):
    """Tests for webhook helper functions."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._ensure_test_account()

    @classmethod
    def _ensure_test_account(cls):
        if not frappe.db.exists("WhatsApp Account", "Test WA Webhook Account"):
            account = frappe.get_doc({
                "doctype": "WhatsApp Account",
                "account_name": "Test WA Webhook Account",
                "status": "Active",
                "url": "https://graph.facebook.com",
                "version": "v17.0",
                "phone_id": "webhook_test_phone_id",
                "business_id": "webhook_test_business_id",
                "app_id": "webhook_test_app_id",
                "webhook_verify_token": "webhook_test_verify_token",
                "is_default_incoming": 1,
                "is_default_outgoing": 1,
            })
            account.insert(ignore_permissions=True)
            from frappe.utils.password import set_encrypted_password
            set_encrypted_password("WhatsApp Account", account.name, "test_webhook_token", "token")
            frappe.db.commit()  # nosemgrep: frappe-manual-commit -- test fixture must be visible to later queries

    def setUp(self):
        # Set password within each test's transaction scope
        from frappe.utils.password import set_encrypted_password
        set_encrypted_password("WhatsApp Account", "Test WA Webhook Account", "test_webhook_token", "token")

    def tearDown(self):
        for name in frappe.get_all("WhatsApp Message", filters={"message_id": ["like", "wamid.webhook_%"]}, pluck="name"):
            frappe.delete_doc("WhatsApp Message", name, force=True)
        for name in frappe.get_all("WhatsApp Notification Log", filters={"template": "Webhook"}, pluck="name"):
            frappe.delete_doc("WhatsApp Notification Log", name, force=True)
        frappe.db.commit()  # nosemgrep: frappe-manual-commit -- test fixture must be visible to later queries

    def test_update_message_status(self):
        """Test update_message_status updates WhatsApp Message status."""
        # Create a message first
        msg = frappe.get_doc({
            "doctype": "WhatsApp Message",
            "type": "Outgoing",
            "to": "919900112233",
            "message": "Status test",
            "message_id": "wamid.webhook_status_test",
            "content_type": "text",
            "whatsapp_account": "Test WA Webhook Account",
        })
        msg.flags.ignore_validate = True
        msg.db_insert()
        frappe.db.commit()  # nosemgrep: frappe-manual-commit -- test fixture must be visible to later queries

        data = {
            "statuses": [{
                "id": "wamid.webhook_status_test",
                "status": "delivered",
                "conversation": {"id": "conv_123"}
            }]
        }
        update_message_status(data)

        msg.reload()
        self.assertEqual(msg.status, "delivered")
        self.assertEqual(msg.conversation_id, "conv_123")

    def test_update_message_status_without_conversation(self):
        """Test update_message_status when no conversation ID."""
        msg = frappe.get_doc({
            "doctype": "WhatsApp Message",
            "type": "Outgoing",
            "to": "919900112234",
            "message": "No conv test",
            "message_id": "wamid.webhook_no_conv",
            "content_type": "text",
            "whatsapp_account": "Test WA Webhook Account",
        })
        msg.flags.ignore_validate = True
        msg.db_insert()
        frappe.db.commit()  # nosemgrep: frappe-manual-commit -- test fixture must be visible to later queries

        data = {
            "statuses": [{
                "id": "wamid.webhook_no_conv",
                "status": "sent",
            }]
        }
        update_message_status(data)

        msg.reload()
        self.assertEqual(msg.status, "sent")

    def test_update_template_status(self):
        """Test update_template_status updates template status via SQL."""
        # Create a template directly
        template_name = "test_webhook_tmpl-en"
        if not frappe.db.exists("WhatsApp Templates", template_name):
            doc = frappe.get_doc({
                "doctype": "WhatsApp Templates",
                "template_name": "test_webhook_tmpl",
                "actual_name": "test_webhook_tmpl",
                "template": "Webhook test template",
                "category": "TRANSACTIONAL",
                "language": frappe.db.get_value("Language", {"language_code": "en"}) or "en",
                "language_code": "en",
                "whatsapp_account": "Test WA Webhook Account",
                "status": "PENDING",
                "id": "webhook_tmpl_id_123",
            })
            doc.db_insert()
            frappe.db.commit()  # nosemgrep: frappe-manual-commit -- test fixture must be visible to later queries

        data = {
            "event": "APPROVED",
            "message_template_id": "webhook_tmpl_id_123",
        }
        update_template_status(data)

        status = frappe.db.get_value("WhatsApp Templates", {"id": "webhook_tmpl_id_123"}, "status")
        self.assertEqual(status, "APPROVED")


# SDCE (DEC-20261108-004): the unsigned endpoint tests (TestWebhookEndpoint) were replaced by signed-request
# tests in test_sdce_webhook_security.py, because the endpoint now rejects any POST without X-Hub-Signature-256.
