import { bindings, defineConfig } from "cf/config";

export default defineConfig({
	worker: {
		name: "tg-verify-a",
		compatibilityDate: "2026-10-01",
		entrypoint: "src/index.js",
		env: {
			// 公开变量(占位值,部署后按实际填写)
			WORKER_B_URL: bindings.text("https://tg-verify-b.<你的子域名>.workers.dev"),
			WHITELIST_CHAT_IDS: bindings.text("-1001234567890"),
			VERIFY_TTL_SECONDS: bindings.text("1800"),
			// 机密(通过 cf deploy --secrets-file 或 cf workers secrets update 设置,永不写进配置)
			BOT_TOKEN: bindings.secret(),
			SIGNING_SECRET: bindings.secret(),
			WEBHOOK_SECRET_TOKEN: bindings.secret(),
		},
	},
});
