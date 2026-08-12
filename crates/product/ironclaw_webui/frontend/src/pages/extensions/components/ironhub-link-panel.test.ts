// @ts-nocheck
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "vitest";
import vm from "node:vm";

function panelSourceForTest() {
  const source = readFileSync(new URL("./ironhub-link-panel.tsx", import.meta.url), "utf8");
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
  return `${lines.join("\n")}\nglobalThis.__testExports = { IronhubLinkPanel };`;
}

function renderPanel(query) {
  const context = {
    Card() {},
    Button() {},
    Icon() {},
    React: { useState: () => ["", () => {}] },
    useQuery: () => query,
    useMutation: () => ({ mutate: () => {}, isPending: false, error: null }),
    useQueryClient: () => ({ setQueryData: () => {} }),
    getIronhubLink: () => {},
    setIronhubSharedKey: () => {},
    clearIronhubSharedKey: () => {},
    globalThis: {},
    html(strings, ...values) {
      return { strings: Array.from(strings), values };
    },
    useT: () => (key) => key,
  };
  vm.runInNewContext(panelSourceForTest(), context);
  return context.globalThis.__testExports.IronhubLinkPanel();
}

function renderedText(node, found = []) {
  if (Array.isArray(node)) {
    for (const item of node) renderedText(item, found);
    return found;
  }
  if (!node || typeof node !== "object") {
    if (typeof node === "string") found.push(node);
    return found;
  }
  if (Array.isArray(node.strings)) found.push(...node.strings);
  if (Array.isArray(node.values)) {
    for (const value of node.values) renderedText(value, found);
  }
  return found;
}

test("a 403 hides the panel entirely rather than showing an error", () => {
  const rendered = renderPanel({
    isPending: false,
    error: { status: 403 },
    data: undefined,
  });
  assert.equal(rendered, null, "a non-operator must not see the panel at all");
});

test("a non-403 failure surfaces an error instead of vanishing silently", () => {
  const rendered = renderPanel({
    isPending: false,
    error: { status: 500 },
    data: undefined,
  });
  assert.notEqual(rendered, null, "a real failure must not be swallowed");
  assert.ok(
    renderedText(rendered).some((text) => text.includes("ironhub.link.loadFailed")),
    "the operator must be told the details could not load",
  );
});

test("while loading, the panel renders nothing", () => {
  const rendered = renderPanel({ isPending: true, error: null, data: undefined });
  assert.equal(rendered, null);
});

test("a stored but inactive key raises the restart notice", () => {
  const rendered = renderPanel({
    isPending: false,
    error: null,
    data: {
      register_url: "https://agent.example.com/api/ironhub/register",
      key_stored: true,
      key_active: false,
    },
  });
  const text = renderedText(rendered);
  assert.ok(
    text.some((entry) => entry.includes("settings.restartRequired")),
    "stored-but-not-active is the restart-pending state",
  );
  assert.ok(text.some((entry) => entry.includes("ironhub.link.stateStored")));
});

test("an active key shows no restart notice", () => {
  const rendered = renderPanel({
    isPending: false,
    error: null,
    data: {
      register_url: "https://agent.example.com/api/ironhub/register",
      key_stored: false,
      key_active: true,
    },
  });
  const text = renderedText(rendered);
  assert.ok(!text.some((entry) => entry.includes("settings.restartRequired")));
  assert.ok(text.some((entry) => entry.includes("ironhub.link.stateActive")));
});

test("an env override explains itself and promises no restart", () => {
  const rendered = renderPanel({
    isPending: false,
    error: null,
    data: {
      register_url: "https://agent.example.com/api/ironhub/register",
      key_stored: true,
      key_active: true,
      env_override: true,
    },
  });
  const text = renderedText(rendered);
  assert.ok(
    text.some((entry) => entry.includes("ironhub.link.envOverride")),
    "the operator must be told the environment variable wins",
  );
  assert.ok(
    !text.some((entry) => entry.includes("settings.restartRequired")),
    "no restart would promote the stored key, so none may be promised",
  );
});

test("the remove affordance appears only when a key is stored", () => {
  const stored = renderedText(
    renderPanel({
      isPending: false,
      error: null,
      data: { register_url: null, key_stored: true, key_active: false },
    }),
  );
  assert.ok(
    stored.some((entry) => entry.includes("ironhub.link.clearKey")),
    "a stored key must be removable",
  );

  const absent = renderedText(
    renderPanel({
      isPending: false,
      error: null,
      data: { register_url: null, key_stored: false, key_active: false },
    }),
  );
  assert.ok(
    !absent.some((entry) => entry.includes("ironhub.link.clearKey")),
    "there is nothing to remove when no key is stored",
  );
});

test("the panel never renders key material", () => {
  const rendered = renderPanel({
    isPending: false,
    error: null,
    data: {
      register_url: "https://agent.example.com/api/ironhub/register",
      key_stored: true,
      key_active: true,
    },
  });
  const text = renderedText(rendered).join(" ");
  assert.ok(!text.includes("ihub_sk_TestSharedKey"), "no key material may reach the DOM");
});
