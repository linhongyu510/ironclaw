import type { Meta, StoryObj } from "@storybook/react-vite";

import { Spinner } from "./spinner";

const MOTION = [
  { token: "--v2-duration-instant", note: "100ms — hover/press feedback" },
  { token: "--v2-duration-fast", note: "150ms — state changes on a control" },
  { token: "--v2-duration-base", note: "250ms — a surface entering or leaving" },
  { token: "--v2-duration-slow", note: "400ms — a full-screen or layout transition" },
  { token: "--v2-ease-standard", note: "M3 standard — state changes" },
  { token: "--v2-ease-emphasized", note: "M3 emphasized — entering, expanding" },
  { token: "--v2-ease-exit", note: "M3 accelerate — dismissal" },
];

const meta = {
  title: "Tokens/Motion",
} satisfies Meta;

export default meta;
type Story = StoryObj;

export const Motion: Story = {
  render: () => (
    <div className="flex max-w-xl flex-col gap-6 text-[var(--v2-text)]">
      <div className="flex items-center gap-4">
        <Spinner className="h-8 w-8 text-[var(--v2-accent-text)]" />
        <div>
          <div className="font-mono text-xs text-[var(--v2-text-strong)]">.v2-spin</div>
          <div className="text-xs text-[var(--v2-text-muted)]">
            0.8s linear infinite — the one always-on animation
          </div>
        </div>
      </div>
      <p className="text-sm leading-6 text-[var(--v2-text-muted)]">
        The app ships a static-motion policy: a global{" "}
        <code className="rounded bg-[var(--v2-surface-soft)] px-1 font-mono text-xs">
          {"* { animation: none !important }"}
        </code>{" "}
        rule disables transitions and animations by default. Only a few class-scoped exceptions
        (notably <code className="font-mono text-xs">.v2-spin</code> for loading spinners) opt back
        in, and <code className="font-mono text-xs">prefers-reduced-motion</code> re-suppresses even
        those.
      </p>

      <section>
        <h3 className="mb-1 font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-[var(--v2-text-muted)]">
          Motion vocabulary
        </h3>
        <p className="mb-3 text-sm leading-6 text-[var(--v2-text-muted)]">
          The tokens below are the vocabulary Phase 4 (#7782 WS4) opts components back into — they
          do not lift the policy above. They exist so an animation says how long and with what
          curve by NAME: under{" "}
          <code className="font-mono text-xs">prefers-reduced-motion</code> every duration token
          collapses to <code className="font-mono text-xs">0ms</code> at the token layer, so a
          component that takes its duration from one is gated by construction rather than by a
          reviewer noticing.
        </p>
        <div className="flex flex-col gap-2">
          {MOTION.map(({ token, note }) => (
            <div
              key={token}
              className="flex items-baseline justify-between gap-4 rounded-[12px] border border-[var(--v2-panel-border)] bg-[var(--v2-surface)] p-3"
            >
              <span className="font-mono text-xs text-[var(--v2-text-strong)]">{token}</span>
              <span className="text-[0.6875rem] text-[var(--v2-text-muted)]">{note}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  ),
};
