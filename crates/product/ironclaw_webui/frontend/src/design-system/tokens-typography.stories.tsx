import type { Meta, StoryObj } from "@storybook/react-vite";

const FONTS = [
  { token: "--font-sans", label: "Sans — Geist" },
  { token: "--font-serif", label: "Serif — Newsreader" },
  { token: "--font-mono", label: "Mono — Geist Mono" },
];

// Control text — labels, buttons, form copy.
const SCALE = [
  { token: "--text-ui-xs", label: "text-ui-xs", size: "0.6875rem" },
  { token: "--text-ui-sm", label: "text-ui-sm", size: "0.75rem" },
  { token: "--text-ui", label: "text-ui", size: "0.8125rem" },
  { token: "--text-ui-lg", label: "text-ui-lg", size: "1rem" },
];

// Editorial text — headings and display copy, a tier the ramp could not
// express before. 539 of the app's ~618 type usages are still raw `text-xs` /
// `text-sm` against 21 on the semantic ramp; these steps are what the rest
// migrate onto, and what Phase 3a (#7781 WS3) retunes when it takes the
// density decision.
const EDITORIAL = [
  { token: "--text-title-sm", label: "text-title-sm", size: "0.9375rem" },
  { token: "--text-title", label: "text-title", size: "1.125rem" },
  { token: "--text-title-lg", label: "text-title-lg", size: "1.5rem" },
  { token: "--text-display", label: "text-display", size: "2rem" },
];

const PANGRAM = "The quick brown fox jumps over the lazy dog";

const meta = {
  title: "Tokens/Typography",
} satisfies Meta;

export default meta;
type Story = StoryObj;

export const Typography: Story = {
  render: () => (
    <div className="flex flex-col gap-8 text-[var(--v2-text-strong)]">
      <section>
        <h3 className="mb-3 font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-[var(--v2-text-muted)]">
          Font families
        </h3>
        <div className="flex flex-col gap-4">
          {FONTS.map(({ token, label }) => (
            <div key={token}>
              <div className="font-mono text-[0.625rem] text-[var(--v2-text-muted)]">{token}</div>
              <div className="text-xl" style={{ fontFamily: `var(${token})` }}>{PANGRAM}</div>
              <div className="text-xs text-[var(--v2-text-muted)]">{label}</div>
            </div>
          ))}
        </div>
      </section>
      <section>
        <h3 className="mb-3 font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-[var(--v2-text-muted)]">
          UI type scale
        </h3>
        <div className="flex flex-col gap-3">
          {SCALE.map(({ token, label, size }) => (
            <div key={token} className="flex flex-wrap items-baseline gap-3">
              <span style={{ fontSize: `var(${token})` }}>{PANGRAM}</span>
              <span className="font-mono text-[0.625rem] text-[var(--v2-text-muted)]">
                {label} · {size}
              </span>
            </div>
          ))}
        </div>
      </section>
      <section>
        <h3 className="mb-3 font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-[var(--v2-text-muted)]">
          Editorial type scale
        </h3>
        <div className="flex flex-col gap-3">
          {EDITORIAL.map(({ token, label, size }) => (
            <div key={token} className="flex flex-wrap items-baseline gap-3">
              <span style={{ fontSize: `var(${token})` }}>{PANGRAM}</span>
              <span className="font-mono text-[0.625rem] text-[var(--v2-text-muted)]">
                {label} · {size}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  ),
};
