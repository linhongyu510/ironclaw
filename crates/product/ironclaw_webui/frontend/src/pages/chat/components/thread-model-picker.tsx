import React from "react";

import { useT } from "../../../lib/i18n";
import { useThreadModelPreference } from "../hooks/useThreadModelPreference";
import {
  WORKSPACE_DEFAULT_MODEL_VALUE,
  buildModelPickerState,
} from "../lib/model-picker-state";
import type {
  ModelPickerState,
  UserModelCatalog,
} from "../lib/model-picker-state";

interface ThreadModelPickerProps {
  threadId?: string | null;
  disabled?: boolean;
}

function workspaceDefaultLabel(
  t: ReturnType<typeof useT>,
  catalog: UserModelCatalog | null,
) {
  return catalog?.workspace_default
    ? t("chat.modelWorkspaceDefaultWithModel", {
        model: catalog.workspace_default,
      })
    : t("chat.modelWorkspaceDefault");
}

function pickerStatusText(t: ReturnType<typeof useT>, state: ModelPickerState) {
  switch (state.status) {
    case "error":
      return t("chat.modelLoadFailed");
    case "empty":
      return t("chat.modelSelectionDisabled");
    case "removed":
      return t("chat.modelUnavailable", { model: state.removedModel });
    case "save_error":
      return t("chat.modelSaveFailed");
    case "saving":
      return t("common.saving");
    default:
      return "";
  }
}

export function ThreadModelPicker({
  threadId = null,
  disabled = false,
}: ThreadModelPickerProps) {
  const t = useT();
  const selection = useThreadModelPreference(threadId);
  const state = buildModelPickerState({ threadId, ...selection });
  const statusText = pickerStatusText(t, state);
  const defaultLabel = state.status === "loading"
    ? t("common.loading")
    : workspaceDefaultLabel(t, selection.catalog);

  const handleChange = React.useCallback(
    (event) => {
      const model = event.currentTarget.value;
      if (model && !state.models.includes(model)) return;
      void selection.selectModel(model || null).catch(() => {});
    },
    [selection.selectModel, state.models],
  );

  return (
    <div className="flex min-w-0 items-center gap-2">
      <label className="sr-only" htmlFor="chat-thread-model-picker">
        {t("llm.model")}
      </label>
      <select
        id="chat-thread-model-picker"
        data-testid="chat-model-picker"
        aria-label={t("llm.model")}
        value={state.value}
        onChange={handleChange}
        disabled={state.disabled || disabled}
        title={statusText || t("llm.model")}
        className="h-8 max-w-[15rem] min-w-0 rounded-lg border border-[var(--v2-panel-border)] bg-[var(--v2-surface-soft)] px-2 text-xs text-[var(--v2-text-muted)] outline-none transition hover:border-[color-mix(in_srgb,var(--v2-accent)_35%,var(--v2-panel-border))] focus:border-[var(--v2-accent)] disabled:cursor-not-allowed disabled:opacity-60"
      >
        <option value={WORKSPACE_DEFAULT_MODEL_VALUE}>{defaultLabel}</option>
        {state.removedModel && (
          <option value={state.removedModel} disabled>
            {t("chat.modelUnavailable", { model: state.removedModel })}
          </option>
        )}
        {state.models.map((model) => (
          <option key={model} value={model}>{model}</option>
        ))}
      </select>
      {statusText && (
        <span
          data-testid="chat-model-picker-status"
          role={state.status === "error" || state.status === "save_error" ? "alert" : "status"}
          className="hidden max-w-64 truncate text-xs text-[var(--v2-text-faint)] sm:inline"
          title={statusText}
        >
          {statusText}
        </span>
      )}
    </div>
  );
}
