// @ts-nocheck
// Browser-side push enrollment for the deployment's session channel — the
// channel this SPA itself fronts, learned from `GET /session` (never a
// hardcoded channel name).
//
// The service worker (`public/sw.js`) displays pushes; this module owns
// registration and the per-browser subscription lifecycle against the
// generic notification-setup surface
// (`/api/webchat/v2/channels/{extension_id}/notifications/*`). The
// enable/disable payloads and the status `detail` are that channel's own
// opaque documents — this module is the client half that interprets them.
// All entry points are defensive: missing browser APIs degrade to an
// "unsupported" state and never throw into app boot or the settings panel.

import {
  disableNotificationSetup,
  enableNotificationSetup,
  getSessionChannelExtensionId,
} from "./api";

// `registerServiceWorker` lives in the dependency-free `./register-sw` module
// so app boot (`main.tsx`) does not pull this enrollment lib — and its api +
// WebCrypto imports — into the initial `/chat` bundle. Re-exported here so the
// automations-page hook keeps one import site for the device-push surface.
export { registerServiceWorker } from "./register-sw";

function pushSupported() {
  return (
    typeof navigator !== "undefined" &&
    "serviceWorker" in navigator &&
    typeof window !== "undefined" &&
    "PushManager" in window &&
    typeof Notification !== "undefined"
  );
}

async function pushRegistration() {
  // Deliberately `getRegistration()`, never `serviceWorker.ready`: `ready`
  // resolves only once SOME registration activates and never rejects, so
  // after a failed boot registration (non-secure origin, /sw.js 404,
  // private mode) it hangs forever and every state probe hangs with it.
  // `getRegistration()` resolves promptly with `undefined` in exactly those
  // cases, which callers surface as "unsupported".
  if (!navigator.serviceWorker || typeof navigator.serviceWorker.getRegistration !== "function") {
    return null;
  }
  try {
    const registration = await navigator.serviceWorker.getRegistration();
    if (!registration || !registration.pushManager) return null;
    return registration;
  } catch (_) {
    return null;
  }
}

/** Lowercase hex SHA-256 of the endpoint URL string. Used only as the local
 * storage key for this origin's endpoint-to-registration association; it
 * never crosses the product boundary. Returns null when WebCrypto is
 * unavailable (push itself requires a secure context, so this is effectively
 * test-environment-only). */
export async function endpointDigestHex(endpoint) {
  if (typeof endpoint !== "string" || !endpoint) return null;
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) return null;
  try {
    const bytes = new TextEncoder().encode(endpoint);
    const digest = await subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  } catch (_) {
    return null;
  }
}

const DEVICE_REGISTRATION_IDS_KEY = "ironclaw.device-push.registration-ids.v1";

function readRegistrationIndex() {
  try {
    const storage = globalThis.localStorage;
    if (!storage || typeof storage.getItem !== "function") return {};
    const raw = storage.getItem(DEVICE_REGISTRATION_IDS_KEY);
    if (!raw || raw.length > 64 * 1024) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (_) {
    return {};
  }
}

function writeRegistrationIndex(index) {
  try {
    const storage = globalThis.localStorage;
    if (!storage || typeof storage.setItem !== "function") return;
    storage.setItem(DEVICE_REGISTRATION_IDS_KEY, JSON.stringify(index));
  } catch (_) {
    // Correlation is a presentation safeguard, not enrollment authority. A
    // blocked/full localStorage degrades to enrolled-unverified after reload.
  }
}

async function registrationAssociationKey(extensionId, endpoint) {
  if (typeof extensionId !== "string" || !extensionId) return null;
  const digest = await endpointDigestHex(endpoint);
  return digest ? `${extensionId}:${digest}` : null;
}

async function registrationIdsForEndpoint(extensionId, endpoint) {
  const key = await registrationAssociationKey(extensionId, endpoint);
  if (!key) return [];
  const values = readRegistrationIndex()[key];
  if (!Array.isArray(values)) return [];
  return values.filter((value) => typeof value === "string" && value).slice(0, 100);
}

async function rememberRegistrationId(extensionId, endpoint, registrationId) {
  if (typeof registrationId !== "string" || !registrationId) return;
  const key = await registrationAssociationKey(extensionId, endpoint);
  if (!key) return;
  const index = readRegistrationIndex();
  const current = Array.isArray(index[key]) ? index[key] : [];
  index[key] = [
    ...new Set([
      ...current.filter((value) => typeof value === "string" && value),
      registrationId,
    ]),
  ].slice(-100);
  writeRegistrationIndex(index);
}

async function forgetRegistrationIds(extensionId, endpoint, registrationIds) {
  const key = await registrationAssociationKey(extensionId, endpoint);
  if (!key || !Array.isArray(registrationIds)) return [];
  const index = readRegistrationIndex();
  const removed = new Set(
    registrationIds.filter((value) => typeof value === "string" && value),
  );
  const remaining = (Array.isArray(index[key]) ? index[key] : []).filter(
    (value) => typeof value === "string" && value && !removed.has(value),
  );
  if (remaining.length > 0) {
    index[key] = remaining;
  } else {
    delete index[key];
  }
  writeRegistrationIndex(index);
  return remaining;
}

/**
 * The current browser's push state:
 *   { state: "unsupported" }
 *   { state: "permission-denied" }
 *   { state: "not-enrolled" }
 *   { state: "enrolled", endpoint, accountMatch }
 *
 * `accountMatch` correlates the browser-global subscription with the
 * SIGNED-IN account's enrollment set (`accountRegistrationIds`, the opaque
 * host ids from the setup-status `detail`):
 *   true  — this account holds a record for this browser's subscription;
 *   false — a subscription exists but belongs to no record of this account
 *           (typically another account enrolled in this browser profile);
 *   null  — the account registration-id list was unavailable.
 * Callers offer account-scoped disable only when `accountMatch === true`.
 */
export async function getDevicePushState({
  extensionId,
  accountRegistrationIds = null,
} = {}) {
  if (!pushSupported()) return { state: "unsupported" };
  if (Notification.permission === "denied") return { state: "permission-denied" };
  try {
    const registration = await pushRegistration();
    if (!registration) return { state: "unsupported" };
    const subscription = await registration.pushManager.getSubscription();
    if (!subscription || !subscription.endpoint) {
      return { state: "not-enrolled" };
    }
    if (Array.isArray(accountRegistrationIds)) {
      const knownRegistrationIds = await registrationIdsForEndpoint(
        extensionId,
        subscription.endpoint,
      );
      const accountIds = new Set(
        accountRegistrationIds.filter(
          (candidate) => typeof candidate === "string" && candidate,
        ),
      );
      if (knownRegistrationIds.some((registrationId) => accountIds.has(registrationId))) {
        return { state: "enrolled", endpoint: subscription.endpoint, accountMatch: true };
      }
      if (knownRegistrationIds.length > 0) {
        return { state: "enrolled", endpoint: subscription.endpoint, accountMatch: false };
      }
      if (accountIds.size === 0) {
        // A physical PushSubscription may outlive all server registrations.
        // It is reusable, but this account is definitively not enrolled.
        return { state: "not-enrolled" };
      }
      // The server knows this account has registrations, but this browser no
      // longer has the local opaque-id association (for example after site
      // data was cleared). Re-enrollment safely reuses the subscription and
      // restores correlation without severing any other account.
      return { state: "enrolled", endpoint: subscription.endpoint, accountMatch: false };
    }
    return { state: "enrolled", endpoint: subscription.endpoint, accountMatch: null };
  } catch (_) {
    return { state: "not-enrolled" };
  }
}

/** Decode an unpadded base64url VAPID public key into the byte array
 * `pushManager.subscribe` expects. */
export function urlBase64ToUint8Array(base64String) {
  if (typeof base64String !== "string" || !base64String) {
    throw new Error("a base64url key is required");
  }
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const output = new Uint8Array(raw.length);
  for (let index = 0; index < raw.length; index += 1) {
    output[index] = raw.charCodeAt(index);
  }
  return output;
}

function subscriptionKeys(subscription) {
  const json = subscription.toJSON ? subscription.toJSON() : {};
  const keys = json.keys || {};
  if (!keys.p256dh || !keys.auth) {
    throw new Error("push subscription did not expose p256dh/auth keys");
  }
  return { p256dh: keys.p256dh, auth: keys.auth };
}

/** Ask for permission, subscribe this browser, and register the
 * subscription with the backend. Returns the resulting browser state.
 *
 * Also the "enable for this account" path when the browser already holds a
 * subscription enrolled by a different account: the existing subscription is
 * reused as-is and registered under the current caller — never unsubscribed,
 * so the other account's enrollment is left intact. */
export async function enrollThisBrowser({ extensionId, vapidPublicKey } = {}) {
  if (!vapidPublicKey) {
    throw new Error("vapidPublicKey is required");
  }
  if (!pushSupported()) return { state: "unsupported" };
  const permission = await Notification.requestPermission();
  if (permission !== "granted") {
    return Notification.permission === "denied"
      ? { state: "permission-denied" }
      : { state: "not-enrolled" };
  }
  const registration = await pushRegistration();
  if (!registration) return { state: "unsupported" };
  let subscription = await registration.pushManager.getSubscription();
  let createdSubscription = false;
  if (!subscription) {
    subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
    });
    createdSubscription = true;
  }
  try {
    const resolvedExtensionId = extensionId || getSessionChannelExtensionId();
    const response = await enableNotificationSetup({
      extensionId: resolvedExtensionId,
      payload: {
        endpoint: subscription.endpoint,
        keys: subscriptionKeys(subscription),
        user_agent: typeof navigator !== "undefined" ? navigator.userAgent : undefined,
      },
    });
    await rememberRegistrationId(
      resolvedExtensionId,
      subscription.endpoint,
      response?.detail?.active_registration_id,
    );
  } catch (error) {
    // Evidence rule: the browser must never report "enrolled" without a
    // server record. Roll back a subscription THIS call created; a
    // pre-existing one is left alone (it may back another account).
    if (createdSubscription) {
      try {
        await subscription.unsubscribe();
      } catch (rollbackError) {
        console.warn("device push enrollment rollback failed", rollbackError);
      }
    }
    throw error;
  }
  return { state: "enrolled", endpoint: subscription.endpoint, accountMatch: true };
}

/** Remove this account's registration for this browser from the backend.
 * Returns the resulting browser state.
 *
 * The physical PushSubscription is deliberately retained: multiple signed-in
 * accounts may register the same browser-global subscription, so locally
 * unsubscribing for one account could silently break another. A later enable
 * reuses it. */
export async function unenrollThisBrowser({ extensionId, accountRegistrationIds = [] } = {}) {
  if (!pushSupported()) return { state: "unsupported" };
  const registration = await pushRegistration();
  if (!registration) return { state: "unsupported" };
  const subscription = await registration.pushManager.getSubscription();
  if (!subscription) return { state: "not-enrolled" };
  const endpoint = subscription.endpoint;
  const resolvedExtensionId = extensionId || getSessionChannelExtensionId();
  await disableNotificationSetup({
    extensionId: resolvedExtensionId,
    payload: { endpoint },
  });
  const remaining = await forgetRegistrationIds(
    resolvedExtensionId,
    endpoint,
    accountRegistrationIds,
  );
  return remaining.length > 0
    ? { state: "enrolled", endpoint, accountMatch: false }
    : { state: "not-enrolled" };
}
