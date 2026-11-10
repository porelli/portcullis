// Copy of Keycloak 26.8.1 themes/.../base/login/resources/js/webauthnRegister.js
// (Apache-2.0). Portcullis changes: attestation is always `direct` and the
// WebAuthn `hints` come from the extension's portcullisHints (both below),
// and the label in returnSuccess. Keep in sync when the Keycloak version of
// ghcr.io/porelli/portcullis-keycloak is upgraded.
import { base64url } from "rfc4648";

export async function registerByWebAuthn(input) {

    // Check if WebAuthn is supported by this browser
    if (!window.PublicKeyCredential) {
        returnFailure("WebAuthnUnsupportedBrowser");
        return;
    }

    const publicKey = {
        challenge: base64url.parse(input.challenge, {loose: true}),
        rp: {id: input.rpId, name: input.rpEntityName},
        user: {
            id: base64url.parse(input.userid, {loose: true}),
            name: input.username,
            displayName: input.username
        },
        pubKeyCredParams: getPubKeyCredParams(input.signatureAlgorithms),
    };

    // Portcullis: always `direct`. The sign-in extension classifies the new
    // passkey from its attestation (contract §8.1); `none` still registers,
    // as a synced passkey.
    publicKey.attestation = "direct";

    // Portcullis: WebAuthn hints, in the order the extension's registration
    // action chose (portcullisHints, a JSON array: the security key first
    // for lldap_admin members). Only the three known values are passed on.
    const hints = getHints(input.portcullisHints);
    if (hints.length > 0) {
        publicKey.hints = hints;
    }

    const authenticatorSelection = {};
    let isAuthenticatorSelectionSpecified = false;

    if (input.authenticatorAttachment !== 'not specified') {
        authenticatorSelection.authenticatorAttachment = input.authenticatorAttachment;
        isAuthenticatorSelectionSpecified = true;
    }

    if (input.residentKey && input.residentKey !== 'not specified') {
        // residentKey is the current spec field and the source of truth. requireResidentKey is
        // deprecated but still set for older clients: it is true iff residentKey is 'required'.
        authenticatorSelection.residentKey = input.residentKey;
        authenticatorSelection.requireResidentKey = input.residentKey === 'required';
        isAuthenticatorSelectionSpecified = true;
    } else if (input.requireResidentKey !== 'not specified') {
        // fall back to the deprecated option when residentKey is not specified
        if (input.requireResidentKey === 'Yes') {
            authenticatorSelection.residentKey = 'required';
            authenticatorSelection.requireResidentKey = true;
        } else {
            authenticatorSelection.residentKey = 'discouraged';
            authenticatorSelection.requireResidentKey = false;
        }
        isAuthenticatorSelectionSpecified = true;
    }

    if (input.userVerificationRequirement !== 'not specified') {
        authenticatorSelection.userVerification = input.userVerificationRequirement;
        isAuthenticatorSelectionSpecified = true;
    }

    if (isAuthenticatorSelectionSpecified) {
        publicKey.authenticatorSelection = authenticatorSelection;
    }

    if (input.createTimeout !== 0) {
        publicKey.timeout = input.createTimeout * 1000;
    }

    const excludeCredentials = getExcludeCredentials(input.excludeCredentialIds);
    if (excludeCredentials.length > 0) {
        publicKey.excludeCredentials = excludeCredentials;
    }

    try {
        const result = await doRegister(publicKey);
        returnSuccess(result, input.initLabel, input.initLabelPrompt);
    } catch (error) {
        returnFailure(error);
    }
}

function doRegister(publicKey) {
    return navigator.credentials.create({publicKey});
}

function getHints(portcullisHints) {
    let parsed;
    try {
        parsed = JSON.parse(portcullisHints || "[]");
    } catch (e) {
        return [];
    }
    if (!Array.isArray(parsed)) {
        return [];
    }
    const known = ["security-key", "client-device", "hybrid"];
    return parsed.filter((h, i) => known.includes(h) && parsed.indexOf(h) === i);
}

function getPubKeyCredParams(signatureAlgorithmsList) {
    const pubKeyCredParams = [];
    if (signatureAlgorithmsList.length === 0) {
        pubKeyCredParams.push({type: "public-key", alg: -7});
        return pubKeyCredParams;
    }

    for (const entry of signatureAlgorithmsList) {
        pubKeyCredParams.push({
            type: "public-key",
            alg: entry
        });
    }

    return pubKeyCredParams;
}

function getExcludeCredentials(excludeCredentialIds) {
    const excludeCredentials = [];
    if (excludeCredentialIds === "") {
        return excludeCredentials;
    }

    for (const entry of excludeCredentialIds.split(',')) {
        excludeCredentials.push({
            type: "public-key",
            id: base64url.parse(entry, {loose: true})
        });
    }

    return excludeCredentials;
}

function getTransportsAsString(transportsList) {
    if (!Array.isArray(transportsList)) {
        return "";
    }

    return transportsList.join();
}

function returnSuccess(result, initLabel, initLabelPrompt) {
    document.getElementById("clientDataJSON").value = base64url.stringify(new Uint8Array(result.response.clientDataJSON), {pad: false});
    document.getElementById("attestationObject").value = base64url.stringify(new Uint8Array(result.response.attestationObject), {pad: false});
    document.getElementById("publicKeyCredentialId").value = base64url.stringify(new Uint8Array(result.rawId), {pad: false});

    if (typeof result.response.getTransports === "function") {
        const transports = result.response.getTransports();
        if (transports) {
            document.getElementById("transports").value = getTransportsAsString(transports);
        }
    } else {
        console.log("Your browser is not able to recognize supported transport media for the authenticator.");
    }

    if (result.authenticatorAttachment) {
        document.getElementById("authenticatorAttachment").value = result.authenticatorAttachment;
    }

    // Portcullis: no label prompt (registering the key is the only step) and
    // a label that is unique per user, so a second key (lost-key recovery,
    // a spare key) never fails with "Device already exists with the same
    // name": "<initLabel> <local date time>". Renamable in the account console.
    void initLabelPrompt;
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    document.getElementById("authenticatorLabel").value = `${initLabel} ${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

    document.getElementById("register").requestSubmit();
}

function returnFailure(err) {
    document.getElementById("error").value = err;
    document.getElementById("register").requestSubmit();
}
