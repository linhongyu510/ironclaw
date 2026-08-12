// @vitest-environment jsdom
// @ts-nocheck
import assert from "node:assert/strict";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, test, vi } from "vitest";

const notificationSetupApi = vi.hoisted(() => ({
  getNotificationSetupStatus: vi.fn(),
}));
const devicePush = vi.hoisted(() => ({
  enrollThisBrowser: vi.fn(),
  getDevicePushState: vi.fn(),
  unenrollThisBrowser: vi.fn(),
}));

vi.mock("../../../lib/api", () => notificationSetupApi);
vi.mock("../../../lib/device-push", () => devicePush);

import { useDevicePush } from "./useDevicePush";

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const mountedRoots = [];

beforeEach(() => {
  vi.clearAllMocks();
  devicePush.getDevicePushState.mockResolvedValue({ state: "not-enrolled" });
});

afterEach(async () => {
  while (mountedRoots.length > 0) {
    const root = mountedRoots.pop();
    await act(async () => root.unmount());
  }
  document.body.replaceChildren();
});

async function mountDevicePushHook(extensionId = "web-app") {
  const state = { current: null };
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  function Probe() {
    state.current = useDevicePush({ extensionId });
    return null;
  }
  const container = document.body.appendChild(document.createElement("div"));
  const root = createRoot(container);
  mountedRoots.push(root);
  await act(async () => {
    root.render(
      React.createElement(
        QueryClientProvider,
        { client: queryClient },
        React.createElement(Probe),
      ),
    );
  });
  return state;
}

async function settleUntil(predicate, description) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
  throw new Error(`timed out waiting for: ${description}`);
}

test("the production notification status shape enables browser enrollment", async () => {
  notificationSetupApi.getNotificationSetupStatus.mockResolvedValue({
    extension_id: "web-app",
    requires_setup: true,
    enabled: false,
    detail: {
      bootstrap: { vapid_public_key: "production-vapid-key" },
      registration_count: 0,
      registrations: [],
    },
  });

  const state = await mountDevicePushHook();
  await settleUntil(
    () => state.current?.browser?.state === "not-enrolled",
    "the real hook to consume notification setup status",
  );

  assert.equal(
    state.current.vapidPublicKey,
    "production-vapid-key",
    "the nested bootstrap key must reach the button enablement gate",
  );
  assert.equal(state.current.subscriptionCount, 0);
  assert.deepEqual(devicePush.getDevicePushState.mock.calls[0][0], {
    extensionId: "web-app",
    accountRegistrationIds: [],
  });
});

test("an enrolled browser is correlated with opaque host registration ids", async () => {
  notificationSetupApi.getNotificationSetupStatus.mockResolvedValue({
    extension_id: "web-app",
    requires_setup: true,
    enabled: true,
    detail: {
      bootstrap: { vapid_public_key: "production-vapid-key" },
      registration_count: 2,
      registrations: [
        { registration_id: "registration-a", created_at: "2026-08-12T12:00:00Z" },
        { registration_id: "registration-b", created_at: "2026-08-12T12:01:00Z" },
      ],
    },
  });

  const state = await mountDevicePushHook();
  await settleUntil(
    () => devicePush.getDevicePushState.mock.calls.length > 0,
    "the account registration ids to reach the browser probe",
  );

  assert.equal(state.current.subscriptionCount, 2);
  assert.deepEqual(devicePush.getDevicePushState.mock.calls[0][0], {
    extensionId: "web-app",
    accountRegistrationIds: ["registration-a", "registration-b"],
  });
});
