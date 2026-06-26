import { NextResponse } from "next/server";
import { KiroService } from "@/lib/oauth/services/kiro";
import { createProviderConnection, isCloudEnabled, resolveProxyForProvider } from "@/models";
import { getConsistentMachineId } from "@/shared/utils/machineId";
import { syncToCloud } from "@/lib/cloudSync";
import { kiroExternalIdpSchema } from "@/shared/validation/schemas";
import { isValidationFailure, validateBody } from "@/shared/validation/helpers";
import { isAuthRequired, isAuthenticated } from "@/shared/utils/apiAuth";
import { sanitizeErrorMessage } from "@omniroute/open-sse/utils/error";

async function requireOAuthImportAuth(request: Request) {
  if (!(await isAuthRequired(request))) return null;
  if (await isAuthenticated(request)) return null;
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

/**
 * Sync to Cloud if enabled
 */
async function syncToCloudIfEnabled() {
  try {
    const cloudEnabled = await isCloudEnabled();
    if (!cloudEnabled) return;

    const machineId = await getConsistentMachineId();
    await syncToCloud(machineId);
  } catch (error) {
    console.log("Error syncing to cloud after Kiro external-idp import:", error);
  }
}

/**
 * POST /api/oauth/kiro/import-external-idp
 *
 * Import a Kiro External IdP (Enterprise SSO) credential blob.
 *
 * Unlike the standard import route (which expects an AWS SSO OIDC refresh
 * token starting with "aorAAAAAG"), this accepts the full credential JSON
 * that Kiro's desktop client stores when authenticating through an external
 * Identity Provider (e.g. Microsoft Entra ID / Azure AD).
 *
 * The access token is a JWT issued by the external IdP, and the refresh
 * token must be refreshed against the IdP's token endpoint — not AWS SSO.
 * We store the IdP metadata in providerSpecificData so the scheduled refresh
 * path knows which endpoint to call.
 */
export async function POST(request: Request) {
  const authResponse = await requireOAuthImportAuth(request);
  if (authResponse) return authResponse;

  let rawBody;
  try {
    rawBody = await request.json();
  } catch {
    return NextResponse.json(
      {
        error: {
          message: "Invalid request",
          details: [{ field: "body", message: "Invalid JSON body" }],
        },
      },
      { status: 400 }
    );
  }

  try {
    const { searchParams } = new URL(request.url);
    const targetProvider = searchParams.get("targetProvider") === "amazon-q" ? "amazon-q" : "kiro";

    const validation = validateBody(kiroExternalIdpSchema, rawBody);
    if (isValidationFailure(validation)) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    const { accessToken, refreshToken, tokenEndpoint, issuerUrl, clientId, scopes, profileArn } =
      validation.data;

    const kiroService = new KiroService();

    // Validate the credential blob (extracts expiry from JWT, no network call)
    const tokenData = kiroService.validateExternalIdpToken({
      accessToken,
      refreshToken,
      tokenEndpoint,
      issuerUrl,
      clientId,
      scopes,
      profileArn,
    });
    // Extract email from JWT if available
    const email = kiroService.extractEmailFromJWT(tokenData.accessToken);

    // Discover profileArn if not provided in the credential blob.
    // The CodeWhisperer generateAssistantResponse API requires a profileArn for
    // desktop-style auth (which is what external_idp uses). Without it, the API
    // returns 403 "The bearer token included in the request is invalid."
    // We call ListAvailableProfiles against the us-east-1 endpoint (the
    // canonical CodeWhisperer home region) to discover it.
    let discoveredProfileArn = tokenData.profileArn;
    if (!discoveredProfileArn) {
      try {
        const profileResponse = await fetch(
          "https://codewhisperer.us-east-1.amazonaws.com/ListAvailableProfiles",
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${tokenData.accessToken}`,
              "Content-Type": "application/x-amz-json-1.0",
              "x-amz-target": "AmazonCodeWhispererService.ListAvailableProfiles",
              Accept: "application/json",
              // The TokenType header is REQUIRED for external_idp tokens —
              // without it ListAvailableProfiles returns an empty array
              // even though the profile exists.
              TokenType: "EXTERNAL_IDP",
            },
            body: JSON.stringify({ maxResults: 10 }),
            signal: AbortSignal.timeout(15000),
          }
        );
        if (profileResponse.ok) {
          const profileData = await profileResponse.json();
          const profiles = Array.isArray(profileData?.profiles) ? profileData.profiles : [];
          if (profiles.length > 0) {
            const matched =
              profiles.find((p: any) => {
                const arn = typeof p?.arn === "string" ? p.arn : "";
                return arn.toLowerCase().includes(":us-east-1:");
              }) || profiles[0];
            discoveredProfileArn =
              typeof matched?.arn === "string" && matched.arn.length > 0 ? matched.arn : undefined;
            if (discoveredProfileArn) {
              console.log(`[kiro external-idp] Discovered profileArn: ${discoveredProfileArn}`);
            }
          }
        } else {
          console.warn(
            `[kiro external-idp] ListAvailableProfiles returned ${profileResponse.status}: ${await profileResponse.text().catch(() => "")}`
          );
        }
      } catch (discoverErr) {
        console.warn("[kiro external-idp] Failed to discover profileArn (non-fatal):", discoverErr);
      }
    }

    // Save to database
    const connection: any = await createProviderConnection({
      provider: targetProvider,
      authType: "oauth",
      accessToken: tokenData.accessToken,
      refreshToken: tokenData.refreshToken,
      expiresAt: new Date(Date.now() + tokenData.expiresIn * 1000).toISOString(),
      email: email || null,
      providerSpecificData: {
        authMethod: "external_idp",
        provider: "ExternalIdp",
        tokenEndpoint: tokenData.tokenEndpoint,
        issuerUrl: tokenData.issuerUrl,
        clientId: tokenData.clientId,
        scopes: tokenData.scopes,
        region: "us-east-1",
        ...(discoveredProfileArn ? { profileArn: discoveredProfileArn } : {}),
      },
      testStatus: "active",
    });

    // Auto sync to Cloud if enabled
    await syncToCloudIfEnabled();

    return NextResponse.json({
      success: true,
      connection: {
        id: connection.id,
        provider: connection.provider,
        email: connection.email,
      },
    });
  } catch (error: any) {
    console.error("Kiro external-idp import error:", error);
    const raw = error instanceof Error ? error.message : String(error ?? "");
    const message = sanitizeErrorMessage(raw) || "Internal server error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
