import assert from "node:assert/strict";
import { test } from "vitest";

import {
  WORKSPACE_DEFAULT_MODEL_VALUE,
  buildModelPickerState,
} from "./model-picker-state";

const catalog = {
  selection_enabled: true,
  workspace_default: "model-a",
  models: ["model-a", "model-b"],
};

test("model picker exposes only the tenant allowlist plus workspace default", () => {
  const state = buildModelPickerState({
    threadId: "thread-a",
    catalog,
    preference: { thread_id: "thread-a", model: "model-b" },
  });

  assert.equal(state.status, "ready");
  assert.equal(state.value, "model-b");
  assert.equal(state.disabled, false);
  assert.deepEqual(state.models, ["model-a", "model-b"]);
  assert.equal(WORKSPACE_DEFAULT_MODEL_VALUE, "");
});

test("model picker keeps a removed preference visible as unavailable", () => {
  const state = buildModelPickerState({
    threadId: "thread-a",
    catalog,
    preference: { thread_id: "thread-a", model: "removed-model" },
  });

  assert.equal(state.status, "removed");
  assert.equal(state.value, "removed-model");
  assert.equal(state.removedModel, "removed-model");
  assert.equal(state.disabled, false);
});

test("model picker distinguishes loading, empty policy, and request failures", () => {
  assert.equal(
    buildModelPickerState({ threadId: "thread-a", isLoading: true }).status,
    "loading",
  );
  const empty = buildModelPickerState({
    threadId: "thread-a",
    catalog: { selection_enabled: false, workspace_default: null, models: [] },
    preference: { thread_id: "thread-a" },
  });
  assert.equal(empty.status, "empty");
  assert.equal(empty.disabled, true);

  const failed = buildModelPickerState({
    threadId: "thread-a",
    loadError: new Error("offline"),
  });
  assert.equal(failed.status, "error");
  assert.equal(failed.disabled, true);

  const saveFailed = buildModelPickerState({
    threadId: "thread-a",
    catalog,
    preference: { thread_id: "thread-a" },
    saveError: new Error("rejected"),
  });
  assert.equal(saveFailed.status, "save_error");
  assert.equal(saveFailed.value, WORKSPACE_DEFAULT_MODEL_VALUE);
});

test("model picker disables selection before a conversation exists and while saving", () => {
  const noThread = buildModelPickerState({ catalog });
  assert.equal(noThread.status, "no_thread");
  assert.equal(noThread.disabled, true);

  const saving = buildModelPickerState({
    threadId: "thread-a",
    catalog,
    preference: { thread_id: "thread-a", model: "model-a" },
    isSaving: true,
  });
  assert.equal(saving.status, "saving");
  assert.equal(saving.disabled, true);
});
