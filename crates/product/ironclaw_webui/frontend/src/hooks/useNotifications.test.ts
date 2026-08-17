// @ts-nocheck
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "vitest";
import vm from "node:vm";

function sourceForTest() {
  const source = readFileSync(new URL("./useNotifications.ts", import.meta.url), "utf8");
  const lines = [];
  let skippingImport = false;
  for (const line of source.split("\n")) {
    if (!skippingImport && line.startsWith("import ")) {
      skippingImport = !line.trimEnd().endsWith(";");
      continue;
    }
    if (skippingImport) {
      skippingImport = !line.trimEnd().endsWith(";");
      continue;
    }
    lines.push(line.replace(/^export function /, "function "));
  }
  return `${lines.join("\n")}\nglobalThis.__testExports = { useNotifications };`;
}

function instantiate({ data, profile = { tenant_id: "tenant", user_id: "user" }, activeThreadId = null }) {
  let queryOptions;
  const readCalls = [];
  const allReadCalls = [];
  const listCalls = [];
  const queryClient = {
    cancelQueries: async () => {},
    getQueryData: () => data,
    setQueryData: () => {},
    invalidateQueries: () => {},
  };
  const React = {
    useMemo: (fn) => fn(),
    useCallback: (fn) => fn,
    useEffect: (fn) => fn(),
  };
  const context = {
    React,
    useI18n: () => ({ t: (key) => key }),
    useQueryClient: () => queryClient,
    useQuery: (options) => {
      queryOptions = options;
      return { data, isLoading: false, error: null, refetch: () => {} };
    },
    useMutation: ({ mutationFn }) => ({
      mutate: (value) => mutationFn(value),
      isPending: false,
      error: null,
    }),
    listNotifications: async (request) => {
      listCalls.push(request);
      return data;
    },
    markNotificationRead: async (id) => readCalls.push(id),
    markAllNotificationsRead: async () => allReadCalls.push(true),
    notificationMessages: (notifications) => (notifications || []).map((notification) => ({
      id: notification.id,
      href: `/chat/${notification.action.thread_id}`,
      read: Boolean(notification.read_at),
    })),
    globalThis: {},
  };
  vm.runInNewContext(sourceForTest(), context);
  const hook = context.globalThis.__testExports.useNotifications({ profile, activeThreadId });
  return { hook, queryOptions, readCalls, allReadCalls, listCalls };
}

function notification(id = "notification-1", readAt = null) {
  return {
    id,
    action: { kind: "open_thread", thread_id: "thread-1" },
    read_at: readAt,
  };
}

test("queries the server-backed inbox only after profile hydration", async () => {
  const harness = instantiate({ data: { notifications: [], unread_count: 0 } });
  assert.equal(harness.queryOptions.enabled, true);
  await harness.queryOptions.queryFn();
  assert.deepEqual(JSON.parse(JSON.stringify(harness.listCalls)), [{ limit: 30 }]);

  const pending = instantiate({
    data: { notifications: [], unread_count: 0 },
    profile: null,
  });
  assert.equal(pending.queryOptions.enabled, false);
});

test("uses authoritative unread state and marks one notification read", () => {
  const harness = instantiate({
    data: { notifications: [notification()], unread_count: 1 },
  });
  assert.equal(harness.hook.unreadCount, 1);
  assert.equal(harness.hook.unreadIds.has("notification-1"), true);
  harness.hook.dismissMessage("notification-1");
  assert.deepEqual(harness.readCalls, ["notification-1"]);
});

test("marks the active thread notification read and supports mark-all", () => {
  const harness = instantiate({
    data: { notifications: [notification()], unread_count: 1 },
    activeThreadId: "thread-1",
  });
  assert.deepEqual(harness.readCalls, ["notification-1"]);
  harness.hook.markAllRead();
  assert.deepEqual(harness.allReadCalls, [true]);
});
