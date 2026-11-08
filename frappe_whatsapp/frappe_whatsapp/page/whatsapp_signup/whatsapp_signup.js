// SDCE (DEC-20261108-004): Embedded Signup for WhatsApp Business app onboarding (Coexistence) only.
frappe.pages["whatsapp-signup"].on_page_load = function (wrapper) {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title: __("WhatsApp Coexistence Signup"),
		single_column: true,
	});
	const METHOD = "frappe_whatsapp.utils.embedded_signup.";
	const FB_ORIGIN = /^https:\/\/([a-z0-9-]+\.)*facebook\.com$/;
	let session_info = null;

	const account = page.add_field({
		fieldname: "account", label: __("WhatsApp Account"), fieldtype: "Link", options: "WhatsApp Account", reqd: 1,
	});
	const $out = $('<pre class="mt-4" style="white-space: pre-wrap"></pre>').appendTo(page.body);
	const log = (msg) => $out.text(($out.text() ? $out.text() + "\n" : "") + msg);

	window.addEventListener("message", (event) => {
		if (!FB_ORIGIN.test(event.origin)) return;
		try {
			const data = JSON.parse(event.data);
			if (data.type === "WA_EMBEDDED_SIGNUP") {
				session_info = data;
				log(__("Meta event: {0}", [data.event]));
			}
		} catch (e) {
			/* non-JSON messages from the SDK are ignored */
		}
	});

	function load_sdk(app_id, version) {
		return new Promise((resolve) => {
			if (window.FB) {
				FB.init({ appId: app_id, autoLogAppEvents: true, xfbml: false, version: version });
				return resolve();
			}
			window.fbAsyncInit = function () {
				FB.init({ appId: app_id, autoLogAppEvents: true, xfbml: false, version: version });
				resolve();
			};
			const s = document.createElement("script");
			s.src = "https://connect.facebook.net/en_US/sdk.js";
			s.async = true;
			s.crossOrigin = "anonymous";
			document.body.appendChild(s);
		});
	}

	function wait_for_session(ms) {
		return new Promise((resolve) => {
			const start = Date.now();
			const tick = () => (session_info || Date.now() - start > ms ? resolve(session_info) : setTimeout(tick, 200));
			tick();
		});
	}

	page.set_primary_action(__("Connect WhatsApp Business app"), async () => {
		if (!account.get_value()) return frappe.msgprint(__("Select the WhatsApp Account first."));
		session_info = null;
		$out.text("");
		const start = await frappe.call({ method: METHOD + "start_signup", type: "POST", args: { account: account.get_value() } });
		const cfg = start.message;
		await load_sdk(cfg.app_id, cfg.graph_version);
		FB.login(
			(response) => {
				const code = response.authResponse && response.authResponse.code;
				if (!code) return log(__("Signup cancelled or no code returned."));
				wait_for_session(5000).then((info) => {
					const data = (info && info.data) || {};
					if (!info || !data.waba_id) return log(__("No WABA id received from Meta. Nothing saved."));
					frappe.call({
						method: METHOD + "complete_signup",
						type: "POST",
						args: {
							state: cfg.state, code: code, event: info.event,
							waba_id: data.waba_id, phone_number_id: data.phone_number_id || null,
						},
						callback: (r) => r.message && log(JSON.stringify(r.message, null, 1)),
					});
				});
			},
			{
				config_id: cfg.config_id,
				response_type: "code",
				override_default_response_type: true,
				extras: { setup: {}, featureType: "whatsapp_business_app_onboarding", sessionInfoVersion: "3" },
			}
		);
	});
};
