# Signed webhook and Coexistence onboarding (fork changes)

This fork of [shridarpatil/frappe_whatsapp](https://github.com/shridarpatil/frappe_whatsapp) adds security
controls to the Meta webhook and an Embedded Signup page for WhatsApp Business app onboarding (Coexistence).
The upstream license (MIT) and attribution stay unchanged.

## Webhook

Endpoint: `/api/method/frappe_whatsapp.utils.webhook.webhook` (guest, `GET` and `POST` only).

- `POST` requires the `X-Hub-Signature-256` header. The app computes HMAC-SHA256 of the exact raw request body with
  the **App Secret** of each Active WhatsApp Account and compares in constant time.
- If the header is missing, the signature is wrong, or no Active account has an App Secret, the endpoint returns
  `403`. It does not parse, log, write or download anything before this check.
- `GET` verification needs `hub.mode=subscribe` and a `hub.verify_token` that matches an Active account. The
  `hub.challenge` value must be alphanumeric (`-` and `_` allowed). Otherwise the endpoint returns `403`.
- Each change is processed only for the single Active, verified account whose `business_id` (WABA ID) and `phone_id`
  match the payload. There is no fallback to a default account.
- A message is stored at most once per Meta message id. Meta can repeat a delivery for up to 7 days.
- Media files are stored as **private** files.
- `smb_message_echoes` (messages sent from the WhatsApp Business app) are stored as `Outgoing` messages. Nothing is
  sent to Meta for them.
- `history`, `smb_app_state_sync` and `account_update` are kept in the WhatsApp Notification Log only. They are not
  imported.
- The WhatsApp Flow endpoint `handle_flow_request` is not whitelisted.
- `Allow auto read receipt` now defaults to off.

## Account setup

On the **WhatsApp Account**:

1. Set `URL` (`https://graph.facebook.com`), `Version` (for example `v24.0`), `App ID`, **App Secret**,
   **Embedded Signup Config ID** and a random `Webhook Verify Token`.
2. Set `Status` to `Active` only when you are ready to receive webhooks.

## Coexistence onboarding

Prerequisites (Meta): the app must be a Solution Partner or Tech Provider. The Embedded Signup configuration must
support WhatsApp Business app onboarding, and the page domain must be in the app's allowed domains.

1. Open the Desk page `whatsapp-signup` (System Manager only).
2. Select the WhatsApp Account and click **Connect WhatsApp Business app**.
3. Complete the Meta popup on the phone owner's side.

The server accepts only the `FINISH_WHATSAPP_BUSINESS_APP_ONBOARDING` event. It exchanges the code on the server,
checks that the phone number belongs to the WABA and reports `is_on_biz_app=true` and `platform_type=CLOUD_API`, and
then saves the token and IDs and subscribes the app to the WABA. It does not call `/register`, because the number is
already registered on the WhatsApp Business app.

## Tests

`frappe_whatsapp/utils/test_sdce_webhook_security.py` covers signatures, scoping, idempotency, private media, echoes,
the GET handshake, whitelisting and the signup checks.
