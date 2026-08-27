// @ts-nocheck

// @vitest-environment happy-dom

import assert from "node:assert/strict";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider, notifyManager } from "@tanstack/react-query";
import { test, vi } from "vitest";
import "../../../i18n/en";
import { ApiError } from "../../../lib/api";
import { I18nProvider } from "../../../lib/i18n";

notifyManager.setScheduler((callback) => callback());
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const requests = vi.hoisted(() => ({
  setSkillLearning: vi.fn(),
  fetchUserModelCatalog: vi.fn(),
}));

vi.mock("../lib/settings-api", () => ({
  setSkillLearning: requests.setSkillLearning,
  fetchUserModelCatalog: requests.fetchUserModelCatalog,
}));

import { SkillLearningSection } from "./skill-learning-section";

function providerState(overrides = {}) {
  return {
    activeProviderId: "openai_compatible",
    selectedModel: "mock-model",
    providers: [
      {
        id: "openai_compatible",
        adapter: "open_ai_completions",
        base_url: "http://127.0.0.1:1234/v1",
        default_model: "mock-model",
      },
    ],
    userModelPolicy: null,
    hasActiveProvider: true,
    skillLearning: { enabled: false, model: null, status: "disabled", reason: null },
    ...overrides,
  };
}

async function renderSection(state) {
  const container = document.createElement("div");
  document.body.append(container);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRoot(container);
  await act(async () => {
    root.render(
      <QueryClientProvider client={queryClient}>
        <I18nProvider>
          <SkillLearningSection providerState={state} />
        </I18nProvider>
      </QueryClientProvider>
    );
  });
  // Let pending react-query fetches (e.g. the shared model catalog) resolve
  // before the test interacts with the rendered control.
  await act(async () => {});
  return { container, queryClient, root };
}

async function clickSwitch(rendered) {
  const toggle = rendered.container.querySelector<HTMLButtonElement>(
    '[data-testid="settings-skill-learning-switch"]'
  );
  assert.ok(toggle);
  await act(async () => toggle.click());
}

function switchChecked(rendered) {
  const toggle = rendered.container.querySelector<HTMLButtonElement>(
    '[data-testid="settings-skill-learning-switch"]'
  );
  return toggle?.getAttribute("aria-checked") === "true";
}

async function openModelMenu(rendered) {
  const trigger = rendered.container.querySelector<HTMLButtonElement>(
    '[data-testid="settings-skill-learning-model"] [aria-haspopup="listbox"]'
  );
  assert.ok(trigger, "the learning model selector renders an accessible trigger");
  await act(async () => trigger.click());
}

function menuOptionLabels(rendered) {
  return [...rendered.container.querySelectorAll('[role="option"]')].map(
    (option) => option.textContent ?? ""
  );
}

test("learning stays off until an admin enables it and offers the provider catalog", async () => {
  requests.fetchUserModelCatalog.mockResolvedValue({
    selection_enabled: true,
    workspace_default: "mock-model",
    models: ["mock-model", "claude-opus-4"],
  });
  const rendered = await renderSection(providerState());
  try {
    assert.equal(switchChecked(rendered), false, "learning must not claim to run when disabled");
    assert.equal(
      rendered.container.querySelector('[role="alert"]')?.textContent ?? "",
      "",
      "no error should be announced on first render"
    );
    const text = rendered.container.textContent ?? "";
    assert.match(text, /Learn skills after successful runs/);
    assert.match(text, /background review/, "supporting copy explains what enabling does");
    // The learning model menu sources its options from the shared model
    // catalog plus the active selection.
    await openModelMenu(rendered);
    const options = menuOptionLabels(rendered);
    for (const model of ["mock-model", "claude-opus-4"]) {
      assert.ok(options.includes(model), `${model} should be offered from the provider catalog`);
    }
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.fetchUserModelCatalog.mockReset();
  }
});

test("enabling requires choosing a learning model first and sends nothing", async () => {
  const rendered = await renderSection(
    providerState({
      skillLearning: { enabled: false, model: null, status: "disabled", reason: null },
    })
  );
  try {
    await clickSwitch(rendered);
    assert.equal(requests.setSkillLearning.mock.calls.length, 0, "no request without a model");
    const alert = rendered.container.querySelector('[role="alert"]');
    assert.match(alert?.textContent ?? "", /Choose a learning model/);
    assert.equal(switchChecked(rendered), false, "the switch must not flip before saving");
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
  }
});

test("enabling with a retained model sends one coherent PUT body", async () => {
  const authoritativeSnapshot = {
    providers: [],
    active: { provider_id: "openai_compatible", model: "mock-model" },
    user_model_policy: null,
    skill_learning: { enabled: true, model: "mock-model", status: "ready", reason: null },
  };
  requests.setSkillLearning.mockResolvedValue(authoritativeSnapshot);
  const rendered = await renderSection(
    providerState({
      skillLearning: { enabled: false, model: "mock-model", status: "disabled", reason: null },
    })
  );
  try {
    await clickSwitch(rendered);
    assert.deepEqual(requests.setSkillLearning.mock.calls[0]?.[0], {
      enabled: true,
      model: "mock-model",
    });
    assert.equal(requests.setSkillLearning.mock.calls.length, 1, "exactly one request per gesture");
    assert.equal(switchChecked(rendered), true, "the adopted snapshot drives the switch");
    // The response is authoritative — every consumer of the providers cache
    // sees the applied snapshot.
    assert.equal(rendered.queryClient.getQueryData(["llm-providers"]), authoritativeSnapshot);
    assert.match(
      rendered.container.querySelector('[data-testid="settings-skill-learning-status"]')
        ?.textContent ?? "",
      /On/
    );
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.setSkillLearning.mockReset();
  }
});

test("disabling preserves the chosen model for later re-enable", async () => {
  requests.setSkillLearning.mockResolvedValue({
    providers: [],
    active: null,
    user_model_policy: null,
    skill_learning: { enabled: false, model: "mock-model", status: "disabled", reason: null },
  });
  const rendered = await renderSection(
    providerState({
      skillLearning: { enabled: true, model: "mock-model", status: "ready", reason: null },
    })
  );
  try {
    await clickSwitch(rendered);
    assert.deepEqual(requests.setSkillLearning.mock.calls[0]?.[0], {
      enabled: false,
      model: "mock-model",
    });
    assert.equal(switchChecked(rendered), false);
    assert.equal(
      rendered.queryClient.getQueryData(["llm-providers"])?.skill_learning?.model,
      "mock-model"
    );
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.setSkillLearning.mockReset();
  }
});

test("changing the model while learning runs saves the new choice", async () => {
  requests.fetchUserModelCatalog.mockResolvedValue({
    selection_enabled: true,
    workspace_default: "mock-model",
    models: ["mock-model", "claude-opus-4"],
  });
  requests.setSkillLearning.mockResolvedValue({
    providers: [],
    active: { provider_id: "openai_compatible", model: "claude-opus-4" },
    user_model_policy: null,
    skill_learning: { enabled: true, model: "claude-opus-4", status: "ready", reason: null },
  });
  const rendered = await renderSection(
    providerState({
      skillLearning: { enabled: true, model: "mock-model", status: "ready", reason: null },
    })
  );
  try {
    await openModelMenu(rendered);
    const option = rendered.container.querySelector<HTMLButtonElement>(
      '[role="option"][aria-selected="false"]'
    );
    assert.ok(option, "the unselected catalog option appears in the menu");
    await act(async () => option.click());
    assert.deepEqual(requests.setSkillLearning.mock.calls[0]?.[0], {
      enabled: true,
      model: "claude-opus-4",
    });
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.setSkillLearning.mockReset();
    requests.fetchUserModelCatalog.mockReset();
  }
});

test("invalid deployments surface the backend reason without claiming learning runs", async () => {
  const rendered = await renderSection(
    providerState({
      skillLearning: {
        enabled: true,
        model: "mock-model",
        status: "invalid",
        reason: "model missing from provider catalog",
      },
    })
  );
  try {
    const text = rendered.container.textContent ?? "";
    assert.match(text, /model missing from provider catalog/, "the reason must be readable");
    assert.doesNotMatch(text, /On — /, "invalid state must not render the ready copy");
    assert.ok(switchChecked(rendered), "the saved setting is what the deployment stored");
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
  }
});

test("save failures keep sanitized API errors and never flip the switch", async () => {
  requests.setSkillLearning.mockRejectedValue(new ApiError("learning model rejected by provider"));
  const rendered = await renderSection(
    providerState({
      skillLearning: { enabled: false, model: "mock-model", status: "disabled", reason: null },
    })
  );
  try {
    await clickSwitch(rendered);
    const alert = rendered.container.querySelector('[role="alert"]');
    assert.match(alert?.textContent ?? "", /learning model rejected by provider/);
    assert.equal(switchChecked(rendered), false);
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.setSkillLearning.mockReset();
  }
});

test("unexpected save failures fall back to generic copy, not raw errors", async () => {
  requests.setSkillLearning.mockRejectedValue(new TypeError("network down"));
  const rendered = await renderSection(
    providerState({
      skillLearning: { enabled: false, model: "mock-model", status: "disabled", reason: null },
    })
  );
  try {
    await clickSwitch(rendered);
    const alert = rendered.container.querySelector('[role="alert"]');
    assert.match(alert?.textContent ?? "", /Could not update skill learning/);
    assert.doesNotMatch(alert?.textContent ?? "", /network down/);
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.setSkillLearning.mockReset();
  }
});

test("controls lock down without an active provider", async () => {
  requests.setSkillLearning.mockResolvedValue({});
  const rendered = await renderSection(providerState({ hasActiveProvider: false }));
  try {
    const toggle = rendered.container.querySelector<HTMLButtonElement>(
      '[data-testid="settings-skill-learning-switch"]'
    );
    assert.ok(toggle?.disabled, "the switch must be disabled without an active provider");
    const trigger = rendered.container.querySelector<HTMLButtonElement>(
      '[data-testid="settings-skill-learning-model"] [aria-haspopup="listbox"]'
    );
    assert.ok(trigger?.disabled, "the model selector must be disabled without an active provider");
    await clickSwitch(rendered);
    assert.equal(requests.setSkillLearning.mock.calls.length, 0);
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.setSkillLearning.mockReset();
  }
});

test("controls are pending while the save is in flight", async () => {
  const { promise, resolve } = Promise.withResolvers();
  requests.setSkillLearning.mockReturnValue(promise);
  const rendered = await renderSection(
    providerState({
      skillLearning: { enabled: false, model: "mock-model", status: "disabled", reason: null },
    })
  );
  try {
    await clickSwitch(rendered);
    const toggle = rendered.container.querySelector<HTMLButtonElement>(
      '[data-testid="settings-skill-learning-switch"]'
    );
    assert.ok(toggle?.disabled, "controls lock while saving");
    const status = rendered.container.querySelector(
      '[data-testid="settings-skill-learning-status"]'
    );
    assert.match(status?.textContent ?? "", /Saving/);
    await act(async () =>
      resolve({
        providers: [],
        active: null,
        user_model_policy: null,
        skill_learning: { enabled: true, model: "mock-model", status: "ready", reason: null },
      })
    );
    assert.equal(switchChecked(rendered), true);
  } finally {
    act(() => rendered.root.unmount());
    rendered.container.remove();
    requests.setSkillLearning.mockReset();
  }
});
