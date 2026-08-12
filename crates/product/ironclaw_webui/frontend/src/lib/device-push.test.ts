// @ts-nocheck
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { afterEach, test, vi } from "vitest";

vi.mock("./api", () => ({
  enableNotificationSetup: vi.fn(async () => ({ enabled: true })),
  disableNotificationSetup: vi.fn(async () => ({ enabled: false })),
  getSessionChannelExtensionId: vi.fn(() => "session-channel"),
}));

import {
  disableNotificationSetup,
  enableNotificationSetup,
} from "./api";
import {
  endpointDigestHex,
  enrollThisBrowser,
  getDevicePushState,
  registerServiceWorker,
  unenrollThisBrowser,
  urlBase64ToUint8Array,
} from "./device-push";

const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalNotification = Object.getOwnPropertyDescriptor(globalThis, "Notification");
const originalLocalStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");

function setGlobal(name, value) {
  Object.defineProperty(globalThis, name, {
    value,
    configurable: true,
    writable: true,
  });
}

function restoreGlobal(name, descriptor) {
  if (descriptor) {
    Object.defineProperty(globalThis, name, descriptor);
  } else {
    delete globalThis[name];
  }
}

afterEach(() => {
  restoreGlobal("navigator", originalNavigator);
  restoreGlobal("window", originalWindow);
  restoreGlobal("Notification", originalNotification);
  restoreGlobal("localStorage", originalLocalStorage);
  vi.clearAllMocks();
});

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function memoryStorage() {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  };
}

function browserEnvironment({
  permission = "default",
  subscription = null,
  subscribeResult = null,
  hasRegistration = true,
} = {}) {
  const subscribeCalls = [];
  const registration = {
    pushManager: {
      getSubscription: async () => subscription,
      subscribe: async (options) => {
        subscribeCalls.push(options);
        if (subscribeResult) return subscribeResult;
        throw new Error("no subscribe result configured");
      },
    },
  };
  const registerCalls = [];
  setGlobal("navigator", {
    userAgent: "TestBrowser/1.0",
    serviceWorker: {
      register: async (url) => {
        registerCalls.push(url);
        return registration;
      },
      // The module must never await `serviceWorker.ready` — it hangs forever
      // when no registration exists — so the fake only offers the prompt
      // `getRegistration()` probe, and `undefined` models the failed-boot-
      // registration case.
      getRegistration: async () => (hasRegistration ? registration : undefined),
    },
  });
  setGlobal("window", { PushManager: function PushManager() {} });
  setGlobal("Notification", {
    permission,
    requestPermission: async () => {
      const next = permission === "default" ? "granted" : permission;
      globalThis.Notification.permission = next;
      return next;
    },
  });
  return { registration, registerCalls, subscribeCalls };
}

function fakeSubscription(endpoint) {
  return {
    endpoint,
    toJSON: () => ({ endpoint, keys: { p256dh: "pk", auth: "as" } }),
    unsubscribe: vi.fn(async () => true),
  };
}

test("urlBase64ToUint8Array decodes an unpadded base64url key", () => {
  // "AQAB" base64url → bytes [1, 0, 1].
  assert.deepEqual(Array.from(urlBase64ToUint8Array("AQAB")), [1, 0, 1]);
  // URL-safe alphabet round-trip: "_-8" → [0xff, 0xef].
  assert.deepEqual(Array.from(urlBase64ToUint8Array("_-8")), [0xff, 0xef]);
  assert.throws(() => urlBase64ToUint8Array(""), /base64url key is required/);
});

test("endpointDigestHex matches an independent SHA-256 and rejects junk", async () => {
  const endpoint = "https://fcm.googleapis.com/fcm/send/abc";
  assert.equal(await endpointDigestHex(endpoint), sha256Hex(endpoint));
  assert.equal(await endpointDigestHex(""), null);
  assert.equal(await endpointDigestHex(undefined), null);
});

test("registerServiceWorker registers /sw.js and swallows failures", async () => {
  const { registerCalls } = browserEnvironment();
  await registerServiceWorker();
  assert.deepEqual(registerCalls, ["/sw.js"]);

  setGlobal("navigator", {
    serviceWorker: {
      register: async () => {
        throw new Error("registration exploded");
      },
    },
  });
  const result = await registerServiceWorker();
  assert.equal(result, null, "a failed registration resolves null, never throws");

  setGlobal("navigator", {});
  assert.equal(await registerServiceWorker(), null, "no serviceWorker support is a no-op");
});

test("getDevicePushState distinguishes unsupported, denied, not-enrolled, and enrolled", async () => {
  setGlobal("navigator", {});
  setGlobal("window", {});
  assert.deepEqual(await getDevicePushState(), { state: "unsupported" });

  browserEnvironment({ permission: "denied" });
  assert.deepEqual(await getDevicePushState(), { state: "permission-denied" });

  browserEnvironment({ permission: "granted", subscription: null });
  assert.deepEqual(await getDevicePushState(), { state: "not-enrolled" });

  browserEnvironment({
    permission: "granted",
    subscription: fakeSubscription("https://fcm.googleapis.com/fcm/send/abc"),
  });
  assert.deepEqual(await getDevicePushState(), {
    state: "enrolled",
    endpoint: "https://fcm.googleapis.com/fcm/send/abc",
    accountMatch: null,
  });
});

test("getDevicePushState resolves promptly as unsupported when no registration exists", async () => {
  // A failed boot registration leaves getRegistration() → undefined;
  // `serviceWorker.ready` would hang forever here, which is the regression
  // this pins (CodeRabbit stability finding on PR #7398).
  browserEnvironment({ permission: "granted", hasRegistration: false });
  assert.deepEqual(await getDevicePushState(), { state: "unsupported" });
});

test("getDevicePushState correlates a subscription with opaque account registration ids", async () => {
  const endpoint = "https://fcm.googleapis.com/fcm/send/mine";
  setGlobal("localStorage", memoryStorage());
  browserEnvironment({ permission: "granted", subscription: fakeSubscription(endpoint) });
  enableNotificationSetup.mockResolvedValueOnce({
    enabled: true,
    detail: { active_registration_id: "registration-mine" },
  });
  await enrollThisBrowser({ extensionId: "web-app", vapidPublicKey: "AQAB" });

  const matched = await getDevicePushState({
    extensionId: "web-app",
    accountRegistrationIds: ["registration-mine"],
  });
  assert.deepEqual(matched, { state: "enrolled", endpoint, accountMatch: true });

  const foreign = await getDevicePushState({
    extensionId: "web-app",
    accountRegistrationIds: ["registration-other"],
  });
  assert.deepEqual(foreign, { state: "enrolled", endpoint, accountMatch: false });

  const emptyAccount = await getDevicePushState({
    extensionId: "web-app",
    accountRegistrationIds: [],
  });
  assert.deepEqual(
    emptyAccount,
    { state: "enrolled", endpoint, accountMatch: false },
    "a locally known registration for another account remains distinguishable",
  );
});

test("getDevicePushState keeps enrollment recoverable when local correlation was cleared", async () => {
  const endpoint = "https://fcm.googleapis.com/fcm/send/recover";
  setGlobal("localStorage", memoryStorage());
  browserEnvironment({ permission: "granted", subscription: fakeSubscription(endpoint) });

  assert.deepEqual(
    await getDevicePushState({
      extensionId: "web-app",
      accountRegistrationIds: ["registration-current"],
    }),
    { state: "enrolled", endpoint, accountMatch: false },
    "the UI must offer the safe re-enrollment path when only local correlation is missing",
  );
});

test("enrollThisBrowser subscribes with the VAPID key and registers with the backend", async () => {
  const { subscribeCalls } = browserEnvironment({
    permission: "default",
    subscription: null,
    subscribeResult: fakeSubscription("https://fcm.googleapis.com/fcm/send/new"),
  });

  const state = await enrollThisBrowser({ vapidPublicKey: "AQAB" });

  assert.deepEqual(state, {
    state: "enrolled",
    endpoint: "https://fcm.googleapis.com/fcm/send/new",
    accountMatch: true,
  });
  assert.equal(subscribeCalls.length, 1);
  assert.equal(subscribeCalls[0].userVisibleOnly, true);
  assert.deepEqual(Array.from(subscribeCalls[0].applicationServerKey), [1, 0, 1]);
  assert.equal(enableNotificationSetup.mock.calls.length, 1);
  assert.deepEqual(enableNotificationSetup.mock.calls[0][0], {
    extensionId: "session-channel",
    payload: {
      endpoint: "https://fcm.googleapis.com/fcm/send/new",
      keys: { p256dh: "pk", auth: "as" },
      user_agent: "TestBrowser/1.0",
    },
  });
});

test("enrollThisBrowser rolls back a freshly created subscription when the backend rejects", async () => {
  const created = fakeSubscription("https://fcm.googleapis.com/fcm/send/fresh");
  browserEnvironment({
    permission: "granted",
    subscription: null,
    subscribeResult: created,
  });
  enableNotificationSetup.mockRejectedValueOnce(new Error("backend rejected"));

  await assert.rejects(enrollThisBrowser({ vapidPublicKey: "AQAB" }), /backend rejected/);
  assert.equal(
    created.unsubscribe.mock.calls.length,
    1,
    "a created-but-unregistered subscription must be unsubscribed so the browser never reports enrolled without a server record",
  );
});

test("enrollThisBrowser never unsubscribes a pre-existing subscription on backend failure", async () => {
  // The pre-existing subscription may belong to ANOTHER account in this
  // browser profile; rolling it back would sever that account's enrollment.
  const existing = fakeSubscription("https://fcm.googleapis.com/fcm/send/other-account");
  browserEnvironment({ permission: "granted", subscription: existing });
  enableNotificationSetup.mockRejectedValueOnce(new Error("backend rejected"));

  await assert.rejects(enrollThisBrowser({ vapidPublicKey: "AQAB" }), /backend rejected/);
  assert.equal(existing.unsubscribe.mock.calls.length, 0);
});

test("enrollThisBrowser reports a denied permission without subscribing", async () => {
  const { subscribeCalls } = browserEnvironment({ permission: "denied" });
  const state = await enrollThisBrowser({ vapidPublicKey: "AQAB" });
  assert.deepEqual(state, { state: "permission-denied" });
  assert.equal(subscribeCalls.length, 0);
  assert.equal(enableNotificationSetup.mock.calls.length, 0);
  await assert.rejects(enrollThisBrowser({}), /vapidPublicKey is required/);
});

test("unenrollThisBrowser keeps the shared browser subscription when backend removal fails", async () => {
  const subscription = fakeSubscription("https://fcm.googleapis.com/fcm/send/old");
  browserEnvironment({ permission: "granted", subscription });
  disableNotificationSetup.mockRejectedValueOnce(new Error("backend offline"));

  await assert.rejects(
    unenrollThisBrowser({
      extensionId: "web-app",
      accountRegistrationIds: ["registration-mine"],
    }),
    /backend offline/,
  );

  assert.equal(subscription.unsubscribe.mock.calls.length, 0);
  assert.equal(disableNotificationSetup.mock.calls.length, 1);
  assert.deepEqual(disableNotificationSetup.mock.calls[0][0], {
    extensionId: "web-app",
    payload: { endpoint: "https://fcm.googleapis.com/fcm/send/old" },
  });
});

test("unenrollThisBrowser removes only this account's local association", async () => {
  const endpoint = "https://fcm.googleapis.com/fcm/send/shared";
  const subscription = fakeSubscription(endpoint);
  setGlobal("localStorage", memoryStorage());
  browserEnvironment({ permission: "granted", subscription });
  enableNotificationSetup
    .mockResolvedValueOnce({
      enabled: true,
      detail: { active_registration_id: "registration-current" },
    })
    .mockResolvedValueOnce({
      enabled: true,
      detail: { active_registration_id: "registration-other" },
    });
  await enrollThisBrowser({ extensionId: "web-app", vapidPublicKey: "AQAB" });
  await enrollThisBrowser({ extensionId: "web-app", vapidPublicKey: "AQAB" });

  const state = await unenrollThisBrowser({
    extensionId: "web-app",
    accountRegistrationIds: ["registration-current"],
  });

  assert.deepEqual(state, { state: "enrolled", endpoint, accountMatch: false });
  assert.equal(subscription.unsubscribe.mock.calls.length, 0);
  assert.deepEqual(
    await getDevicePushState({
      extensionId: "web-app",
      accountRegistrationIds: ["registration-other"],
    }),
    { state: "enrolled", endpoint, accountMatch: true },
  );
});
