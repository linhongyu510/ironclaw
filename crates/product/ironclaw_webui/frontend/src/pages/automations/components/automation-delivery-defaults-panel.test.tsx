// @vitest-environment happy-dom

import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { test, vi } from "vitest";

vi.mock("../../../lib/i18n", () => ({
  useT: () => (key: string) => key,
}));

const { AutomationDeliveryDefaultsPanel } = await import(
  "./automation-delivery-defaults-panel"
);

function target(
  id: string,
  status: "available" | "unavailable",
  overrides: Record<string, unknown> = {},
) {
  return {
    target: {
      target_id: id,
      display_name: `${id} name`,
      description: `${id} description`,
      status,
      ...overrides,
    },
    capabilities: {
      final_replies: true,
      gate_prompts: true,
      auth_prompts: true,
    },
  };
}

function renderPanel({
  targets,
  currentTarget = null,
  currentStatus = "none_configured",
}: {
  targets: ReturnType<typeof target>[];
  currentTarget?: Record<string, unknown> | null;
  currentStatus?: "none_configured" | "available" | "unavailable";
}) {
  const deliveryState = {
    targets,
    finalReplyTargets: targets.filter((option) => option.capabilities.final_replies),
    currentTarget,
    currentStatus,
    isLoading: false,
    isSaving: false,
    saveError: null,
    saveFinalReplyTarget: vi.fn(() => Promise.resolve()),
  };

  return renderToStaticMarkup(
    <AutomationDeliveryDefaultsPanel deliveryState={deliveryState} />,
  );
}

function parseMarkup(html: string) {
  const container = document.createElement("div");
  container.innerHTML = html;
  return container;
}

test("available delivery targets remain selectable", () => {
  const html = renderPanel({
    targets: [target("slack-ready", "available")],
  });

  assert.match(
    html,
    /<input[^>]*type="radio"[^>]*value="slack-ready"[^>]*>/,
  );
  assert.match(html, /slack-ready name/);
  assert.match(html, /automations\.delivery\.pill\.ready/);
});

test("unavailable delivery targets render as named read-only status information", () => {
  const html = renderPanel({
    targets: [
      target("slack-offline", "unavailable", {
        display_name: "Slack support DM",
        unavailable_reason: "The Slack workspace is no longer paired.",
      }),
    ],
  });

  assert.doesNotMatch(
    html,
    /<input[^>]*type="radio"[^>]*value="slack-offline"[^>]*>/,
  );
  assert.match(html, /Slack support DM/);
  assert.match(html, /The Slack workspace is no longer paired\./);
  assert.match(html, /automations\.delivery\.pill\.unavailable/);
  const markup = parseMarkup(html);
  assert.doesNotMatch(
    markup.querySelector('[role="radiogroup"]')?.textContent ?? "",
    /Slack support DM/,
  );
  assert.match(
    markup.querySelector('[data-delivery-target-status="unavailable"]')
      ?.textContent ?? "",
    /Slack support DM.*The Slack workspace is no longer paired\./,
  );
});

test("a configured target that becomes unavailable stays visible and leaves Web App selectable", () => {
  const currentTarget = {
    target_id: "slack-current",
    display_name: "Current Slack DM",
  };
  const availableHtml = renderPanel({
    targets: [target("slack-current", "available")],
    currentTarget,
    currentStatus: "available",
  });
  const unavailableHtml = renderPanel({
    targets: [
      target("slack-current", "unavailable", {
        display_name: "Current Slack DM",
        unavailable_reason: "Reconnect Slack to resume delivery.",
        // The current wire contract reports this through currentStatus rather
        // than requiring a status field on every listed target.
        status: undefined,
      }),
    ],
    currentTarget,
    currentStatus: "unavailable",
  });

  assert.match(
    availableHtml,
    /<input[^>]*type="radio"[^>]*value="slack-current"[^>]*>/,
  );
  assert.doesNotMatch(
    unavailableHtml,
    /<input[^>]*type="radio"[^>]*value="slack-current"[^>]*>/,
  );
  assert.match(unavailableHtml, /Current Slack DM/);
  assert.match(unavailableHtml, /Reconnect Slack to resume delivery\./);
  const unavailableMarkup = parseMarkup(unavailableHtml);
  const webFallback = unavailableMarkup.querySelector<HTMLInputElement>(
    '[role="radiogroup"] input[value=""]',
  );
  assert.ok(webFallback);
  assert.equal(webFallback.disabled, false);
});
