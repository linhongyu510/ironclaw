// @ts-nocheck
import assert from "node:assert/strict";
import { test } from "vitest";
import { notificationMessages } from "./notifications";

const t = (key) => ({
  "notifications.approval.title": "Approval required",
  "notifications.approval.body": "A run is waiting for your approval.",
  "notifications.approval.detail": "Needs your approval",
  "notifications.failed.title": "Run failed",
  "notifications.failed.body": "A background run did not complete.",
  "notifications.failed.detail": "Open the thread to review",
  "notifications.resolved": "Resolved",
}[key] || key);

test("notificationMessages presents typed server notifications", () => {
  const messages = notificationMessages([
    {
      id: "notification-1",
      kind: "approval_required",
      severity: "warning",
      action: { kind: "open_thread", thread_id: "thread/1" },
      created_at: "2026-06-30T07:43:00Z",
      read_at: null,
      resolved_at: null,
    },
  ], t);

  assert.equal(messages.length, 1);
  assert.equal(messages[0].type, "approval_required");
  assert.equal(messages[0].icon, "shield");
  assert.equal(messages[0].title, "Approval required");
  assert.equal(messages[0].body, "A run is waiting for your approval.");
  assert.equal(messages[0].href, "/chat/thread%2F1");
  assert.equal(messages[0].read, false);
});

test("notificationMessages preserves resolved records and sorts newest first", () => {
  const messages = notificationMessages([
    {
      id: "older",
      kind: "run_failed",
      action: { kind: "open_thread", thread_id: "thread-old" },
      created_at: "2026-06-30T07:43:00Z",
      read_at: "2026-06-30T07:44:00Z",
      resolved_at: "2026-06-30T07:44:00Z",
    },
    {
      id: "newer",
      kind: "run_failed",
      action: { kind: "open_thread", thread_id: "thread-new" },
      created_at: "2026-06-30T08:43:00Z",
      read_at: null,
      resolved_at: null,
    },
  ], t);

  assert.deepEqual(messages.map((message) => message.id), ["newer", "older"]);
  assert.equal(messages[1].detail, "Resolved");
  assert.equal(messages[1].read, true);
});

test("notificationMessages does not trust arbitrary action URLs", () => {
  const [message] = notificationMessages([
    {
      id: "unsafe-action",
      kind: "run_failed",
      action: { kind: "open_url", url: "https://example.invalid" },
      created_at: "2026-06-30T08:43:00Z",
    },
  ], t);
  assert.equal(message.href, null);
});
