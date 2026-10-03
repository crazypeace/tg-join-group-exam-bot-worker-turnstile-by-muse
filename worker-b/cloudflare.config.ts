import { bindings, defineConfig } from "cf/config";

export default defineConfig({
	worker: {
		name: "tg-verify-b",
		compatibilityDate: "2026-10-01",
		entrypoint: "src/index.js",
		env: {
			// 公开变量(占位值,部署后按实际填写)
			WHITELIST_CHAT_IDS: bindings.text("-1001234567890"),
			TG_CLIENT_ID: bindings.text("<bot的数字id>"),
			TURNSTILE_SITE_KEY: bindings.text("<TURNSTILE_SITE_KEY>"),
			VERIFY_TTL_SECONDS: bindings.text("1800"),
			// 机密(通过 cf deploy --secrets-file 或 cf workers secrets update 设置,永不写进配置)
			BOT_TOKEN: bindings.secret(),
			SIGNING_SECRET: bindings.secret(),
			TG_CLIENT_SECRET: bindings.secret(),
			TURNSTILE_SECRET_KEY: bindings.secret(),
		},
	},
});
