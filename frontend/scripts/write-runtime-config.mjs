import { writeFile } from "node:fs/promises";

const config = {
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL ?? "",
  authMode: process.env.AUTH_PROVIDER ?? process.env.NEXT_PUBLIC_AUTH_MODE ?? "local",
  cognitoIssuer: process.env.COGNITO_ISSUER ?? process.env.NEXT_PUBLIC_COGNITO_ISSUER ?? "",
  cognitoClientId: process.env.COGNITO_CLIENT_ID ?? process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID ?? "",
  cognitoDomain: process.env.COGNITO_DOMAIN ?? process.env.NEXT_PUBLIC_COGNITO_DOMAIN ?? "",
  cognitoRedirectUri:
    process.env.COGNITO_REDIRECT_URI ?? process.env.NEXT_PUBLIC_COGNITO_REDIRECT_URI ?? "",
  cognitoPostLogoutRedirectUri:
    process.env.COGNITO_POST_LOGOUT_REDIRECT_URI
    ?? process.env.NEXT_PUBLIC_COGNITO_POST_LOGOUT_REDIRECT_URI
    ?? "",
};

await writeFile(
  "/app/public/runtime-config.js",
  `window.__APP_CONFIG__ = ${JSON.stringify(config)};\n`,
  { mode: 0o644 },
);
