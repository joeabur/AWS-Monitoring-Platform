"use client";

import {
  InMemoryWebStorage,
  UserManager,
  WebStorageStateStore,
  type User,
} from "oidc-client-ts";
import { getRuntimeConfig } from "./runtime-config";

let userManager: UserManager | undefined;

function getUserManager(): UserManager {
  if (userManager) return userManager;

  const config = getRuntimeConfig();
  const authority = config.cognitoIssuer;
  const clientId = config.cognitoClientId;
  if (!authority || !clientId) {
    throw new Error("Cognito issuer and client ID must be configured.");
  }
  const redirectUri = config.cognitoRedirectUri || window.location.origin;

  userManager = new UserManager({
    authority,
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email",
    client_authentication: "client_secret_post",
    automaticSilentRenew: false,
    monitorSession: false,
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
  });
  return userManager;
}

export async function beginCognitoSignIn(): Promise<void> {
  await getUserManager().signinRedirect();
}

export async function completeCognitoSignIn(): Promise<User> {
  const user = await getUserManager().signinRedirectCallback();
  if (!user.access_token || user.expired) {
    throw new Error("Cognito returned an expired or incomplete access token.");
  }
  return user;
}

export async function currentCognitoAccessToken(): Promise<string> {
  const manager = getUserManager();
  const user = await manager.getUser();
  if (!user || !user.refresh_token) {
    throw new Error("Cognito session is missing or expired. Sign in again.");
  }
  if (user.expires_at !== undefined && user.expires_at <= Date.now() / 1000 + 60) {
    const refreshed = await manager.signinSilent();
    if (!refreshed?.access_token || refreshed.expired) {
      throw new Error("Cognito session could not be refreshed. Sign in again.");
    }
    return refreshed.access_token;
  }
  if (user.expired) {
    throw new Error("Cognito session is expired. Sign in again.");
  }
  return user.access_token;
}

export async function signOutCognito(): Promise<void> {
  const manager = getUserManager();
  await manager.removeUser();

  const config = getRuntimeConfig();
  const clientId = config.cognitoClientId;
  const hostedDomain = config.cognitoDomain;
  if (!clientId || !hostedDomain) {
    throw new Error("Cognito client ID and hosted domain must be configured for sign-out.");
  }
  const domainUrl = new URL(hostedDomain);
  if (
    domainUrl.protocol !== "https:"
    || domainUrl.username
    || domainUrl.password
    || domainUrl.pathname !== "/"
    || domainUrl.search
    || domainUrl.hash
  ) {
    throw new Error("Cognito hosted domain must be an HTTPS origin.");
  }

  const logoutUri = config.cognitoPostLogoutRedirectUri || window.location.origin;
  const logoutUrl = new URL("/logout", domainUrl);
  logoutUrl.searchParams.set("client_id", clientId);
  logoutUrl.searchParams.set("logout_uri", logoutUri);
  window.location.assign(logoutUrl);
}
