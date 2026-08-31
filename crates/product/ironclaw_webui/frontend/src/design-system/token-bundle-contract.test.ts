import { describe, expect, it } from "vitest";

import {
  FORBIDDEN_PATTERNS,
  REQUIRED_PROPERTIES,
  REQUIRED_UTILITIES,
  findContractViolations,
} from "../../scripts/check-token-bundle";

/**
 * Guardrails are code (`.claude/rules/review-discipline.md`): the bundle check
 * only earns its place if it actually fails on the shapes it claims to catch.
 *
 * Each case below reproduces a real regression the emitted-CSS gate exists to
 * stop — most importantly the one that shipped green through every other gate
 * in this repo.
 */

/** A minimal stylesheet that satisfies the whole contract. */
function compliantCss(): string {
  const properties = REQUIRED_PROPERTIES.map((token) => `${token}: 1rem;`).join("\n");
  const utilities = REQUIRED_UTILITIES.map(
    (selector) => `${selector} { border-radius: 1rem; }`
  ).join("\n");
  return `:root{\n${properties}\n--v2-elevation-1: 0 0 #0000;\n}\n${utilities}`;
}

describe("design-token bundle contract", () => {
  it("passes on a bundle carrying every token and utility", () => {
    expect(findContractViolations(compliantCss())).toEqual({
      missingProperties: [],
      missingUtilities: [],
      forbidden: [],
    });
  });

  // The exact failure this gate was written for: a comment in `app.css`
  // closing early dropped a whole `@theme` block, and every existing gate
  // stayed green because they read source, not output.
  it("fails when a dropped @theme block removes the radius aliases", () => {
    const css = compliantCss()
      .replace(/--radius-control-sm\s*:[^;]*;/, "")
      .replace(/--radius-control-lg\s*:[^;]*;/, "");
    const { missingProperties } = findContractViolations(css);
    expect(missingProperties).toContain("--radius-control-sm");
    expect(missingProperties).toContain("--radius-control-lg");
  });

  // Tree-shaking hits consumer-free tokens first, so these are the canaries
  // for `@theme static` silently regressing to a plain `@theme`.
  it("fails when the consumer-free elevation and spacing steps are tree-shaken", () => {
    const css = compliantCss().replace(/--shadow-e[0-3]\s*:[^;]*;/g, "");
    expect(findContractViolations(css).missingProperties).toEqual(
      expect.arrayContaining(["--shadow-e0", "--shadow-e1", "--shadow-e2", "--shadow-e3"])
    );
  });

  it("fails when a token exists but its utility was never generated", () => {
    const css = compliantCss().replace(".rounded-control-sm { border-radius: 1rem; }", "");
    const { missingProperties, missingUtilities } = findContractViolations(css);
    // The property survives — which is exactly why a source-level check misses this.
    expect(missingProperties).not.toContain("--radius-control-sm");
    expect(missingUtilities).toEqual([".rounded-control-sm"]);
  });

  it("requires the escaped md: variant, not just the base utility", () => {
    const css = compliantCss().replace(".md\\:rounded-control-lg { border-radius: 1rem; }", "");
    expect(findContractViolations(css).missingUtilities).toEqual([".md\\:rounded-control-lg"]);
  });

  // A `var(--token)` reference proves someone asked for the token, not that it
  // resolves. Counting references would make the gate pass on a broken bundle.
  it("does not accept a var() reference as a declaration", () => {
    const css = compliantCss().replace(
      /--v2-accent-edge\s*:[^;]*;/,
      "border-color: var(--v2-accent-edge);"
    );
    expect(findContractViolations(css).missingProperties).toContain("--v2-accent-edge");
  });

  it("rejects `none` as a flat elevation value", () => {
    const css = compliantCss().replace("--v2-elevation-1: 0 0 #0000;", "--v2-elevation-1: none;");
    expect(findContractViolations(css).forbidden).toHaveLength(1);
    expect(findContractViolations(css).forbidden[0]).toMatch(/never `none`/);
  });

  it("keeps the forbidden list non-empty so the check cannot silently no-op", () => {
    expect(FORBIDDEN_PATTERNS.length).toBeGreaterThan(0);
    expect(REQUIRED_PROPERTIES.length).toBeGreaterThan(0);
    expect(REQUIRED_UTILITIES.length).toBeGreaterThan(0);
  });
});
