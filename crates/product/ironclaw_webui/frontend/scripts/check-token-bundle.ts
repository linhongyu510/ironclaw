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
  { selector: ".rounded-control", declares: "border-radius" },
  { selector: ".rounded-control-sm", declares: "border-radius" },
  { selector: ".rounded-control-xl", declares: "border-radius" },
  { selector: ".md\\:rounded-control-lg", declares: "border-radius" },
];

/** Just the selectors — used for reporting and by the contract tests. */
export const REQUIRED_UTILITY_SELECTORS = REQUIRED_UTILITIES.map(({ selector }) => selector);

/**
 * Declarations that must NOT appear — see `app.css` on why flat is `0 0 #0000`.
 *
 * Matched against PARSED declarations, so a quoted value mentioning `none`
 * cannot trigger a false failure any more than it could satisfy a contract.
 */
export const FORBIDDEN_DECLARATIONS = [
  {
    matches: ({ property, value }: Declaration) =>
      /^--v2-elevation-\d$/.test(property) && value.trim() === "none",
    reason:
      "flat elevation must be `0 0 #0000`, never `none` — Tailwind composes box-shadow as a comma list where `none` is only legal alone, so `shadow-e1 ring-2` would silently lose its ring",
  },
];

/**
 * Strip `/* … *\/` spans so a comment can never stand in as evidence.
 *
 * Tailwind emits a licence banner and Vite can preserve annotations, so
 * comments genuinely do reach `dist/`. A comment mentioning `--v2-radius-chip:`
 * or `.rounded-control` would otherwise satisfy this contract while no rule was
 * emitted at all — which is the exact shape of failure the gate exists to
 * catch, so it must not be satisfiable by prose.
 */
export function stripCssComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, " ");
}

export interface Declaration {
  property: string;
  value: string;
}

export interface StyleRule {
  /** The selector list, split into its members and trimmed. */
  selectors: string[];
  /** Declarations made DIRECTLY in this rule's own block. */
  declarations: Declaration[];
  /**
   * True when this rule is nested inside another STYLE rule (CSS nesting), so
   * its selector is scoped by a parent. `@media`/`@supports` nesting does not
   * set this: a conditional group does not narrow the selector.
   */
  nestedUnderSelector: boolean;
}

/** Split on top-level commas only — `:is(a, b)` is one selector, not two. */
function splitSelectorList(prelude: string): string[] {
  const members: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = "";
  for (const ch of prelude) {
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "(" || ch === "[") depth++;
    if (ch === ")" || ch === "]") depth--;
    if (ch === "," && depth === 0) {
      members.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) members.push(current.trim());
  return members;
}

/** Split a block into declaration chunks on SEMICOLONS OUTSIDE quotes.
 *
 * A naive `split(";")` lets `content: "; border-radius: 1rem"` masquerade as
 * two declarations, the second of which appears to set `border-radius`. The
 * whole point of this gate is that only real declarations count. */
function splitDeclarations(flat: string): string[] {
  const chunks: string[] = [];
  let quote: string | null = null;
  let depth = 0;
  let current = "";
  for (const ch of flat) {
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === ";" && depth === 0) {
      chunks.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  chunks.push(current);
  return chunks;
}

/**
 * Declarations made directly in a block.
 *
 * Nested blocks are removed first, and each declaration is split at its FIRST
 * top-level `:` — so `content: "border-radius: 1rem"` yields the property
 * `content`, not `border-radius`. Quoted text is never a declaration.
 */
function parseDeclarations(body: string): Declaration[] {
  let flat = "";
  let depth = 0;
  for (const ch of body) {
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    else if (depth === 0) flat += ch;
  }
  const declarations: Declaration[] = [];
  for (const chunk of splitDeclarations(flat)) {
    let quote: string | null = null;
    let depthInner = 0;
    for (let i = 0; i < chunk.length; i++) {
      const ch = chunk[i];
      if (quote) {
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === "'") { quote = ch; continue; }
      if (ch === "(") depthInner++;
      else if (ch === ")") depthInner--;
      else if (ch === ":" && depthInner === 0) {
        const property = chunk.slice(0, i).trim();
        if (property) declarations.push({ property, value: chunk.slice(i + 1).trim() });
        break;
      }
    }
  }
  return declarations;
}

/**
 * Every style rule in the sheet, descending through at-rules (`@media`,
 * `@supports`, `@layer`) and CSS nesting.
 *
 * Parsing rather than pattern-matching is the point. A regex over raw text
 * cannot tell `.rounded-control{…}` from `.wrap .rounded-control{…}`,
 * `.other.rounded-control{…}` or `.wrap { .rounded-control{…} }` without
 * re-implementing selector grammar badly — and each of those styles something
 * other than the bare utility a component asking for the class relies on.
 */
export function parseStyleRules(css: string): StyleRule[] {
  const rules: StyleRule[] = [];
  const walk = (text: string, nestedUnderSelector: boolean): void => {
    let prelude = "";
    let i = 0;
    while (i < text.length) {
      const ch = text[i];
      if (ch === "{") {
        let depth = 1;
        let j = i + 1;
        while (j < text.length && depth > 0) {
          if (text[j] === "{") depth++;
          else if (text[j] === "}") depth--;
          j++;
        }
        const body = text.slice(i + 1, Math.max(i + 1, j - 1));
        const head = prelude.trim();
        if (head.startsWith("@")) {
          // A conditional group rule does not narrow the selector, so its
          // children keep whatever nesting context we already had.
          walk(body, nestedUnderSelector);
        } else if (head) {
          rules.push({
            selectors: splitSelectorList(head),
            declarations: parseDeclarations(body),
            nestedUnderSelector,
          });
          // Anything inside a style rule IS scoped by that rule's selector.
          walk(body, true);
        }
        prelude = "";
        i = j;
        continue;
      }
      if (ch === "}" || ch === ";") {
        prelude = "";
        i++;
        continue;
      }
      prelude += ch;
      i++;
    }
  };
  walk(css, false);
  return rules;
}

export interface ContractViolations {
  missingProperties: string[];
  missingUtilities: string[];
  forbidden: string[];
}

/** @param rawCss concatenated text of every emitted stylesheet */
export function findContractViolations(rawCss: string): ContractViolations {
  const rules = parseStyleRules(stripCssComments(rawCss));
  const allDeclarations = rules.flatMap((rule) => rule.declarations);

  // Compare PARSED property names. A regex over raw text also matches
  // `content: "--v2-radius-control:"`, letting a quoted value satisfy the
  // contract — and a `var(--token)` reference proves only that something asked
  // for the token, not that it is declared anywhere.
  const declaredProperties = new Set(allDeclarations.map(({ property }) => property));
  const missingProperties = REQUIRED_PROPERTIES.filter(
    (token) => !declaredProperties.has(token)
  );

  // A utility counts only when some STANDALONE rule lists it as an exact
  // selector-list member and that rule's own block declares the property the
  // utility exists to set. Excluded by construction: `.wrap .rounded-control`,
  // `.other.rounded-control`, `.rounded-control:hover`, `.rounded-control-sm`,
  // `.wrap { .rounded-control { … } }`, and an empty block.
  const missingUtilities = REQUIRED_UTILITIES.filter(
    ({ selector, declares }) =>
      !rules.some(
        (rule) =>
          !rule.nestedUnderSelector &&
          rule.selectors.includes(selector) &&
          rule.declarations.some(({ property }) => property === declares)
      )
  ).map(({ selector }) => selector);

  const forbidden = FORBIDDEN_DECLARATIONS.filter(({ matches }) =>
    allDeclarations.some(matches)
  ).map(({ reason }) => reason);

  return { missingProperties, missingUtilities, forbidden };
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
      "\n  The token may exist while its utility does not — or the rule exists\n" +
        "  but is empty, or only a `:hover`/descendant variant survived. A\n" +
        "  component using the class then renders with no radius at all.\n"
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
