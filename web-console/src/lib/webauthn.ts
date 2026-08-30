/** WebAuthn option/credential conversion for login 2FA and content unlock. */

function b64urlToBuf(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodePublicKeyOptions(opts: Record<string, unknown>): any {
  const o = JSON.parse(JSON.stringify(opts)) as Record<string, any>;
  o.challenge = b64urlToBuf(o.challenge);
  if (o.user && o.user.id) o.user.id = b64urlToBuf(o.user.id);
  (o.excludeCredentials || []).forEach((c: { id: string | ArrayBuffer }) => {
    c.id = b64urlToBuf(String(c.id));
  });
  (o.allowCredentials || []).forEach((c: { id: string | ArrayBuffer }) => {
    c.id = b64urlToBuf(String(c.id));
  });
  return o;
}

export function credentialToJson(cred: PublicKeyCredential): Record<string, unknown> {
  const r = cred.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const out: Record<string, unknown> = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
  const response = out.response as Record<string, unknown>;
  if ("attestationObject" in r && r.attestationObject) {
    response.attestationObject = bufToB64url(r.attestationObject);
    if (typeof (r as AuthenticatorAttestationResponse).getTransports === "function") {
      response.transports = (r as AuthenticatorAttestationResponse).getTransports();
    }
  } else {
    response.authenticatorData = bufToB64url(r.authenticatorData);
    response.signature = bufToB64url(r.signature);
    if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
  }
  return out;
}
