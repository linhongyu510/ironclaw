import assert from "node:assert/strict";
import { test } from "vitest";

import { INFERENCE_FIELDS } from "../lib/settings-schema";
import { filterSettingsSections, matchesSearch } from "../lib/settings-search";
import { runVmModuleForTest } from "../../../test-support/vm-module-harness";

function html(strings, ...values) {
  return { strings: Array.from(strings), values };
}

function visit(node, fn) {
  if (Array.isArray(node)) {
    for (const item of node) visit(item, fn);
    return;
  }
  if (!node || typeof node !== "object") return;
  fn(node);
  if (Array.isArray(node.values)) {
    for (const value of node.values) visit(value, fn);
  }
}

function findComponentNodes(root, component) {
  const found = [];
  visit(root, (node) => {
    if (Array.isArray(node.values) && node.values.includes(component)) {
      found.push(node);
    }
  });
  return found;
}

function componentProps(node, component): Record<string, any> {
  const props = {};
  const start = node.values.indexOf(component);
  for (let index = start + 1; index < node.values.length; index += 1) {
    const name = node.strings[index]?.match(/([A-Za-z][A-Za-z0-9]*)=\s*$/)?.[1];
    if (name) props[name] = node.values[index];
  }
  return props;
}

function component(name) {
  return function TestComponent() {
    return name;
  };
}

function renderInferenceModule() {
  const context = {
    Badge: component("Badge"),
    Button: component("Button"),
    Card: component("Card"),
    ConfirmDialog: component("ConfirmDialog"),
    ProviderManagement: component("ProviderManagement"),
    SettingsGroup: component("SettingsGroup"),
    SettingsSearchEmpty: component("SettingsSearchEmpty"),
    React: {
      useCallback: (fn) => fn,
      useState: (initial) => [initial, () => {}],
    },
    html,
    INFERENCE_FIELDS,
    filterSettingsSections,
    matchesSearch,
    useLlmProviders: () => ({
      activeProviderId: "openai",
      selectedModel: "gpt-4.1",
      providers: [{ id: "openai", default_model: "gpt-4.1" }],
      hasActiveProvider: true,
      isResetting: false,
      resetConfig: async () => {},
    }),
    useT: () => (key) => key,
  };

  const exports = runVmModuleForTest(
    "./inference-tab.tsx",
    ["InferenceTab"],
    context,
    import.meta.url
  );
  return { context, exports };
}

// The shared harness stubs `useState` with a no-op setter, which is fine for
// static prop assertions but cannot exercise state transitions. This variant
// keeps real state across re-renders so the dialog open/close and error flows
// can be driven: each render() call re-runs the component with the same
// state slots (call order is stable) and the setters mutate them.
function renderInferenceModuleWithState() {
  const { context, exports } = renderInferenceModule();
  const state = [];
  let callIndex = 0;
  context.React.useState = (initial) => {
    const index = callIndex;
    callIndex += 1;
    if (state[index] === undefined) state[index] = initial;
    return [state[index], (value) => { state[index] = value; }];
  };
  const render = (props) => {
    callIndex = 0;
    return exports.InferenceTab(props);
  };
  return { context, exports, render };
}

function componentPropsByName(root, componentName) {
  return findComponentNodes(root, componentName).map((node) =>
    componentProps(node, componentName)
  );
}

function scalarStrings(root) {
  const scalars = [];
  visit(root, (node) => {
    if (Array.isArray(node.values)) {
      for (const value of node.values) {
        if (typeof value === "string") scalars.push(value);
      }
    }
  });
  return scalars;
}

test("Inference tab omits unsupported operator-config fields", () => {
  const { context, exports } = renderInferenceModule();
  const rendered = exports.InferenceTab({
    settings: {},
    gatewayStatus: null,
    onSave: () => {},
    savedKeys: {},
    isLoading: false,
    searchQuery: "",
  });

  assert.equal(
    findComponentNodes(rendered, context.SettingsGroup).length,
    0,
    "unsupported settings like temperature must not render editable controls"
  );
  assert.equal(
    findComponentNodes(rendered, context.ProviderManagement).length,
    1,
    "LLM provider management should remain visible"
  );
});

test("Inference tab resets model settings only after shared-dialog confirmation", () => {
  const { context, exports } = renderInferenceModule();
  const rendered = exports.InferenceTab({
    settings: {},
    gatewayStatus: null,
    onSave: () => {},
    savedKeys: {},
    isLoading: false,
    searchQuery: "",
  });

  const buttonScalars = findComponentNodes(rendered, context.Button)
    .flatMap((node) => node.values)
    .filter((value) => typeof value === "string");
  assert.ok(buttonScalars.includes("llm.resetToDefaults"));

  const [dialog] = findComponentNodes(rendered, context.ConfirmDialog).map((node) =>
    componentProps(node, context.ConfirmDialog)
  );
  assert.equal(dialog.open, false);
  assert.equal(dialog.title, "llm.confirmResetToDefaults");
  assert.equal(dialog.confirmLabel, "llm.resetToDefaults");
  assert.equal(typeof dialog.onConfirm, "function");
});

test("Inference tab surfaces reset failure and keeps the dialog open", async () => {
  const { context, render } = renderInferenceModuleWithState();
  context.useT = (() => (key, params) =>
    key === "error.loadFailed" && params
      ? `error.loadFailed: ${params.message}`
      : key) as typeof context.useT;
  context.useLlmProviders = () => ({
    activeProviderId: "openai",
    selectedModel: "gpt-4.1",
    providers: [{ id: "openai", default_model: "gpt-4.1" }],
    hasActiveProvider: true,
    isResetting: false,
    resetConfig: async () => { throw new Error("boom"); },
  });
  const props = {
    settings: {},
    gatewayStatus: null,
    onSave: () => {},
    savedKeys: {},
    isLoading: false,
    searchQuery: "",
  };

  const rendered = render(props);
  const [button] = componentPropsByName(rendered, context.Button);
  button.onClick();
  const openDialog = componentPropsByName(render(props), context.ConfirmDialog)[0];
  assert.equal(openDialog.open, true, "reset button must open the confirm dialog");
  await openDialog.onConfirm();

  const afterFailure = render(props);
  assert.equal(
    componentPropsByName(afterFailure, context.ConfirmDialog)[0].open,
    true,
    "a failed reset must keep the dialog open"
  );
  assert.ok(
    scalarStrings(afterFailure).some((text) => text.includes("boom")),
    "the reset failure must surface through the status region"
  );
});

test("Inference tab closes the dialog after a successful reset", async () => {
  const { context, render } = renderInferenceModuleWithState();
  const props = {
    settings: {},
    gatewayStatus: null,
    onSave: () => {},
    savedKeys: {},
    isLoading: false,
    searchQuery: "",
  };

  const rendered = render(props);
  const [button] = componentPropsByName(rendered, context.Button);
  button.onClick();
  const openDialog = componentPropsByName(render(props), context.ConfirmDialog)[0];
  assert.equal(openDialog.open, true);
  await openDialog.onConfirm();

  const afterSuccess = render(props);
  assert.equal(
    componentPropsByName(afterSuccess, context.ConfirmDialog)[0].open,
    false,
    "a successful reset must close the confirm dialog"
  );
  assert.ok(
    !scalarStrings(afterSuccess).some((text) => text.includes("Failed to load")),
    "no error status may render after a successful reset"
  );
});
