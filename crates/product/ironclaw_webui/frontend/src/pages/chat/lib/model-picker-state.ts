export const WORKSPACE_DEFAULT_MODEL_VALUE = "";

export interface UserModelCatalog {
  selection_enabled: boolean;
  workspace_default: string | null;
  models: string[];
}

export interface ThreadModelPreference {
  thread_id: string;
  model?: string | null;
}

export type ModelPickerStatus =
  | "no_thread"
  | "error"
  | "loading"
  | "empty"
  | "save_error"
  | "saving"
  | "removed"
  | "ready";

interface ModelPickerInput {
  threadId?: string | null;
  catalog?: UserModelCatalog | null;
  preference?: ThreadModelPreference | null;
  isLoading?: boolean;
  loadError?: unknown;
  isSaving?: boolean;
  saveError?: unknown;
}

export interface ModelPickerState {
  status: ModelPickerStatus;
  disabled: boolean;
  value: string;
  models: string[];
  removedModel: string | null;
}

export function buildModelPickerState({
  threadId = null,
  catalog = null,
  preference = null,
  isLoading = false,
  loadError = null,
  isSaving = false,
  saveError = null,
}: ModelPickerInput = {}): ModelPickerState {
  const models = Array.from(
    new Set(
      (Array.isArray(catalog?.models) ? catalog.models : []).filter(
        (model) => typeof model === "string" && model.length > 0,
      ),
    ),
  );
  const preferredModel =
    typeof preference?.model === "string" && preference.model.length > 0
      ? preference.model
      : null;
  const value = preferredModel || WORKSPACE_DEFAULT_MODEL_VALUE;

  if (!threadId) {
    return {
      status: "no_thread",
      disabled: true,
      value: WORKSPACE_DEFAULT_MODEL_VALUE,
      models,
      removedModel: null,
    };
  }
  if (loadError) {
    return {
      status: "error",
      disabled: true,
      value,
      models,
      removedModel: null,
    };
  }
  if (isLoading || !catalog || !preference) {
    return {
      status: "loading",
      disabled: true,
      value,
      models,
      removedModel: null,
    };
  }
  if (!catalog.selection_enabled || models.length === 0) {
    return {
      status: "empty",
      disabled: true,
      value: WORKSPACE_DEFAULT_MODEL_VALUE,
      models,
      removedModel: null,
    };
  }

  const removedModel = preferredModel && !models.includes(preferredModel)
    ? preferredModel
    : null;
  const status = saveError
    ? "save_error"
    : isSaving
      ? "saving"
      : removedModel
        ? "removed"
        : "ready";
  return {
    status,
    disabled: isSaving,
    value,
    models,
    removedModel,
  };
}
