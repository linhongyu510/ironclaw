#!/usr/bin/env node
/**
 * Assert the design-token contract survives the CSS build.
 *
 * Why this exists as a separate gate: every other check in this repo inspects
 * *source*. The component tests assert Tailwind class STRINGS, the story tests
 * assert rendered structure, and `pnpm build` exits 0 whenever Vite produced a
 * bundle. None of them reads the emitted CSS.
 *
 * That gap is not hypothetical. A malformed comment in `app.css` —
 * `spacing -> p-*&#47;m-*` , where the `*&#47;` closes the comment early — made
 * Tailwind silently drop an entire `@theme` block, all 29 keys. `build`,
 * `test`, `test:storybook` and `build-storybook` all stayed green while the
 * emitted CSS carried no `rounded-control` utility at all, which would have
 * shipped every button with square corners.
 *
 * So: read what actually reached `dist/`, and fail loudly when a token or a
 * utility the design system promises is not there.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Custom properties that must be declared in the emitted CSS.
 *
 * Tailwind tree-shakes `@theme` keys that no generated utility references,
 * which is why the block in `app.css` is `@theme static`. These are the keys
 * that would vanish first if that keyword were dropped — they have no consumer
 * yet and exist as a contract for Phase 3a to build on.
 */
export const REQUIRED_PROPERTIES = [
  // Radius scale — the axis Button consumes today.
  "--v2-radius-chip",
  "--v2-radius-field",
  "--v2-radius-control-sm",
  "--v2-radius-control",
  "--v2-radius-control-lg",
  "--v2-radius-control-xl",
  "--v2-radius-surface",
  "--v2-radius-surface-lg",
  "--v2-radius-pill",
  // Tailwind-namespace aliases: these are what actually generate utilities.
  "--radius-control",
  "--radius-control-sm",
  "--radius-control-lg",
  "--radius-control-xl",
  // Elevation. `--shadow-e*` has no consumer yet and is the canary for
  // `@theme static` regressing to a plain `@theme`.
  "--shadow-e0",
  "--shadow-e1",
  "--shadow-e2",
  "--shadow-e3",
  // Spacing and motion — likewise consumer-free today.
  "--spacing-gutter",
  "--spacing-inset-sm",
  "--spacing-inset",
  "--spacing-inset-lg",
  "--spacing-stack-sm",
  "--spacing-stack",
  "--spacing-stack-lg",
  "--ease-standard",
  "--ease-emphasized",
  "--ease-exit",
  // Motion vocabulary consumed as `var()` directly (no Tailwind namespace).
  "--v2-duration-instant",
  "--v2-duration-fast",
  "--v2-duration-base",
  "--v2-duration-slow",
  // Editorial type steps.
  "--text-title-sm",
  "--text-title",
  "--text-title-lg",
  "--text-display",
  "--text-ui-xs",
  // Button's accent surface.
  "--v2-accent-gradient",
  "--v2-accent-gradient-hover",
  "--v2-accent-edge",
  "--v2-accent-glow",
];

/**
 * Utility class selectors that must be generated. A declared token with no
 * emitted utility is exactly the failure the comment bug produced: the custom
 * property was fine, but `.rounded-control` never existed, so the class on
 * `<Button>` matched nothing.
 *
 * Written as they appear in the bundle — Tailwind escapes the `:` of a variant.
 */
export const REQUIRED_UTILITIES = [
  ".rounded-control",
  ".rounded-control-sm",
  ".rounded-control-xl",
  ".md\\:rounded-control-lg",
];

/** Declarations that must NOT appear — see `app.css` on why flat is `0 0 #0000`. */
export const FORBIDDEN_PATTERNS = [
  {
    pattern: /--v2-elevation-\d\s*:\s*none/,
    reason:
      "flat elevation must be `0 0 #0000`, never `none` — Tailwind composes box-shadow as a comma list where `none` is only legal alone, so `shadow-e1 ring-2` would silently lose its ring",
  },
];

export interface ContractViolations {
  missingProperties: string[];
  missingUtilities: string[];
  forbidden: string[];
}

/** @param css concatenated text of every emitted stylesheet */
export function findContractViolations(css: string): ContractViolations {
  const missingProperties = REQUIRED_PROPERTIES.filter(
    // Match a declaration (`--token:`), not a `var(--token)` reference — a
    // reference proves only that something asked for it, not that it exists.
    (token) => !new RegExp(`${escapeForRegExp(token)}\\s*:`).test(css)
  );
  const missingUtilities = REQUIRED_UTILITIES.filter(
    (selector) => !css.includes(selector)
  );
  const forbidden = FORBIDDEN_PATTERNS.filter(({ pattern }) => pattern.test(css)).map(
    ({ reason }) => reason
  );
  return { missingProperties, missingUtilities, forbidden };
}

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function readBundledCss(assetsDir: string): string {
  const files = readdirSync(assetsDir).filter((name) => name.endsWith(".css"));
  if (files.length === 0) {
    throw new Error(`No .css emitted in ${assetsDir} — run \`pnpm build\` first.`);
  }
  return files.map((name) => readFileSync(join(assetsDir, name), "utf8")).join("\n");
}

function main(): void {
  const assetsDir = process.argv[2] ?? "dist/assets";
  const css = readBundledCss(assetsDir);
  const { missingProperties, missingUtilities, forbidden } = findContractViolations(css);

  if (missingProperties.length === 0 && missingUtilities.length === 0 && forbidden.length === 0) {
    console.log(
      `Design-token bundle contract OK — ${REQUIRED_PROPERTIES.length} properties and ` +
        `${REQUIRED_UTILITIES.length} utilities present in ${assetsDir}.`
    );
    return;
  }

  console.error("Design-token contract broken in the EMITTED CSS.\n");
  if (missingProperties.length > 0) {
    console.error("Missing custom properties:");
    for (const token of missingProperties) console.error(`  ${token}`);
    console.error(
      "\n  A whole block vanishing usually means `app.css` lost `@theme static`,\n" +
        "  or a comment above it closed early (a literal `*/` inside the comment\n" +
        "  body — `p-*/m-*` is the known trap).\n"
    );
  }
  if (missingUtilities.length > 0) {
    console.error("Missing utility selectors:");
    for (const selector of missingUtilities) console.error(`  ${selector}`);
    console.error(
      "\n  The token may exist while its utility does not. Components using the\n" +
        "  class then render with no radius at all.\n"
    );
  }
  if (forbidden.length > 0) {
    console.error("Forbidden declarations:");
    for (const reason of forbidden) console.error(`  ${reason}`);
  }
  process.exit(1);
}

// Only run when invoked as a CLI, so the unit test can import the helpers.
// Same shape as check-bundle-budgets.ts next door.
const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) main();
