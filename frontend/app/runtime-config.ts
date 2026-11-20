export type RuntimeConfig = {
  apiBaseUrl: string;
  authMode: "local" | "cognito";
  cognitoIssuer: string;
  cognitoClientId: string;
  cognitoDomain: string;
  cognitoRedirectUri: string;
  cognitoPostLogoutRedirectUri: string;
};

declare global {
  interface Window {
    __APP_CONFIG__?: Partial<RuntimeConfig>;
  }
}

export function getRuntimeConfig(): RuntimeConfig {
  const runtime = typeof window === "undefined" ? undefined : window.__APP_CONFIG__;
  const authMode = runtime?.authMode ?? process.env.NEXT_PUBLIC_AUTH_MODE ?? "local";
  return {
    apiBaseUrl:
      runtime?.apiBaseUrl ?? process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
    authMode: authMode === "cognito" ? "cognito" : "local",
    cognitoIssuer: runtime?.cognitoIssuer ?? process.env.NEXT_PUBLIC_COGNITO_ISSUER ?? "",
    cognitoClientId: runtime?.cognitoClientId ?? process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID ?? "",
    cognitoDomain: runtime?.cognitoDomain ?? process.env.NEXT_PUBLIC_COGNITO_DOMAIN ?? "",
    cognitoRedirectUri:
      runtime?.cognitoRedirectUri ?? process.env.NEXT_PUBLIC_COGNITO_REDIRECT_URI ?? "",
    cognitoPostLogoutRedirectUri:
      runtime?.cognitoPostLogoutRedirectUri
      ?? process.env.NEXT_PUBLIC_COGNITO_POST_LOGOUT_REDIRECT_URI
      ?? "",
  };
}
