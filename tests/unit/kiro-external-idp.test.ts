/**
 * Kiro External IdP (Enterprise SSO) — import + refresh tests
 *
 * Validates the 5th Kiro auth method (external_idp) that handles federated
 * logins through an external Identity Provider such as Microsoft Entra ID.
 * Unlike the AWS SSO OIDC path, the refresh token is issued by the IdP's own
 * token endpoint and must be refreshed against it.
 */

import test from "node:test";
import assert from "node:assert/strict";

const { KiroService } = await import("../../src/lib/oauth/services/kiro.ts");
const { refreshKiroToken } = await import("../../open-sse/services/tokenRefresh.ts");

// A minimal Microsoft Entra ID-style JWT (header.payload.sig) for testing.
// Payload: { exp: 2000000000, iat: 1000000000 } → expiresIn = 1000000000
const FAKE_JWT = [
  Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url"),
  Buffer.from(
    JSON.stringify({ exp: 2000000000, iat: 1000000000, preferred_username: "user@example.com" })
  ).toString("base64url"),
  "fake-signature",
].join(".");

const EXTERNAL_IDP_INPUT = {
  accessToken: FAKE_JWT,
  refreshToken: "1.AcYAPhi8FakeRefreshToken",
  tokenEndpoint: "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
  issuerUrl: "https://login.microsoftonline.com/test-tenant/v2.0",
  clientId: "482b5fd8-bb62-4a8e-be45-2229f0df6540",
  scopes:
    "api://482b5fd8-bb62-4a8e-be45-2229f0df6540/codewhisperer:conversations api://482b5fd8-bb62-4a8e-be45-2229f0df6540/codewhisperer:completions offline_access",
};

const ORIGINAL_FETCH = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
});

// ── validateExternalIdpToken ────────────────────────────────────────────────

test("validateExternalIdpToken extracts expiresIn from JWT exp/iat claims", () => {
  const svc = new KiroService();
  const result = svc.validateExternalIdpToken(EXTERNAL_IDP_INPUT);

  assert.equal(result.authMethod, "external_idp");
  assert.equal(result.accessToken, FAKE_JWT);
  assert.equal(result.refreshToken, EXTERNAL_IDP_INPUT.refreshToken);
  assert.equal(result.tokenEndpoint, EXTERNAL_IDP_INPUT.tokenEndpoint);
  assert.equal(result.issuerUrl, EXTERNAL_IDP_INPUT.issuerUrl);
  assert.equal(result.clientId, EXTERNAL_IDP_INPUT.clientId);
  assert.equal(result.scopes, EXTERNAL_IDP_INPUT.scopes);
  // exp (2000000000) - iat (1000000000) = 1000000000 seconds
  assert.equal(result.expiresIn, 1000000000);
});

test("validateExternalIdpToken falls back to 3600s when JWT is malformed", () => {
  const svc = new KiroService();
  const result = svc.validateExternalIdpToken({
    ...EXTERNAL_IDP_INPUT,
    accessToken: "not-a-jwt",
  });

  assert.equal(result.expiresIn, 3600);
});

test("validateExternalIdpToken forwards optional profileArn", () => {
  const svc = new KiroService();
  const result = svc.validateExternalIdpToken({
    ...EXTERNAL_IDP_INPUT,
    profileArn: "arn:aws:codewhisperer:us-east-1:123456789012:profile/ABC",
  });

  assert.equal(result.profileArn, "arn:aws:codewhisperer:us-east-1:123456789012:profile/ABC");
});

test("validateExternalIdpToken omits profileArn when not provided", () => {
  const svc = new KiroService();
  const result = svc.validateExternalIdpToken(EXTERNAL_IDP_INPUT);

  assert.equal(result.profileArn, undefined);
});

test("extractEmailFromJWT reads preferred_username from external IdP token", () => {
  const svc = new KiroService();
  const email = svc.extractEmailFromJWT(FAKE_JWT);
  assert.equal(email, "user@example.com");
});

// ── refreshKiroToken — external_idp branch ──────────────────────────────────

test("refreshKiroToken external_idp calls the IdP token endpoint with form-encoded body", async () => {
  let capturedUrl = "";
  let capturedBody = "";
  let capturedHeaders: Record<string, string> = {};

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    capturedUrl = String(url);
    capturedBody = typeof init?.body === "string" ? init.body : "";
    capturedHeaders = init?.headers as Record<string, string>;
    return new Response(
      JSON.stringify({
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        expires_in: 3600,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }) as typeof fetch;

  const result = await refreshKiroToken(
    EXTERNAL_IDP_INPUT.refreshToken,
    {
      authMethod: "external_idp",
      tokenEndpoint: EXTERNAL_IDP_INPUT.tokenEndpoint,
      clientId: EXTERNAL_IDP_INPUT.clientId,
      scopes: EXTERNAL_IDP_INPUT.scopes,
    },
    null
  );

  // Must have called the IdP token endpoint
  assert.equal(capturedUrl, EXTERNAL_IDP_INPUT.tokenEndpoint);

  // Must use form-encoded body (Microsoft Entra ID standard)
  assert.equal(capturedHeaders["Content-Type"], "application/x-www-form-urlencoded");

  // Body must contain the right grant_type, client_id, refresh_token and scope
  const params = new URLSearchParams(capturedBody);
  assert.equal(params.get("client_id"), EXTERNAL_IDP_INPUT.clientId);
  assert.equal(params.get("grant_type"), "refresh_token");
  assert.equal(params.get("refresh_token"), EXTERNAL_IDP_INPUT.refreshToken);
  assert.equal(params.get("scope"), EXTERNAL_IDP_INPUT.scopes);

  // Result must map IdP response (snake_case) to OmniRoute shape (camelCase)
  assert.equal(result.accessToken, "new-access-token");
  assert.equal(result.refreshToken, "new-refresh-token");
  assert.equal(result.expiresIn, 3600);
});

test("refreshKiroToken external_idp returns unrecoverable_refresh_error on invalid_grant", async () => {
  globalThis.fetch = (async () => {
    return new Response(
      JSON.stringify({ error: "invalid_grant", error_description: "Token has been revoked" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }) as typeof fetch;

  const result = await refreshKiroToken(
    EXTERNAL_IDP_INPUT.refreshToken,
    {
      authMethod: "external_idp",
      tokenEndpoint: EXTERNAL_IDP_INPUT.tokenEndpoint,
      clientId: EXTERNAL_IDP_INPUT.clientId,
      scopes: EXTERNAL_IDP_INPUT.scopes,
    },
    null
  );

  assert.equal(result.error, "unrecoverable_refresh_error");
  assert.equal(result.code, "invalid_grant");
});

test("refreshKiroToken external_idp returns missing_idp_metadata when tokenEndpoint absent", async () => {
  const result = await refreshKiroToken(
    EXTERNAL_IDP_INPUT.refreshToken,
    {
      authMethod: "external_idp",
      // Missing tokenEndpoint, clientId, scopes
    },
    null
  );

  assert.equal(result.error, "unrecoverable_refresh_error");
  assert.equal(result.code, "missing_idp_metadata");
});

test("refreshKiroToken external_idp does NOT call AWS SSO OIDC endpoint", async () => {
  const calledUrls: string[] = [];
  globalThis.fetch = (async (url: string | URL | Request) => {
    const u = String(url);
    calledUrls.push(u);
    return new Response(
      JSON.stringify({ access_token: "x", refresh_token: "y", expires_in: 3600 }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }) as typeof fetch;

  await refreshKiroToken(
    EXTERNAL_IDP_INPUT.refreshToken,
    {
      authMethod: "external_idp",
      tokenEndpoint: EXTERNAL_IDP_INPUT.tokenEndpoint,
      clientId: EXTERNAL_IDP_INPUT.clientId,
      scopes: EXTERNAL_IDP_INPUT.scopes,
    },
    null
  );

  // Must never hit oidc.amazonaws.com or auth.desktop.kiro.dev
  assert.ok(
    !calledUrls.some((u) => u.includes("oidc.amazonaws.com")),
    "external_idp refresh must not call AWS SSO OIDC"
  );
  assert.ok(
    !calledUrls.some((u) => u.includes("auth.desktop.kiro.dev")),
    "external_idp refresh must not call Kiro social auth endpoint"
  );
});
