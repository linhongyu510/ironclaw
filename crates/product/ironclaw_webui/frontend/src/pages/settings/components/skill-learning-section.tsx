// @ts-nocheck
import React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card } from "../../../design-system/card";
import { SelectMenu } from "../../../design-system/select-menu";
import { Switch } from "../../../design-system/switch";
import { ApiError } from "../../../lib/api";
import { useT } from "../../../lib/i18n";
import { fetchUserModelCatalog, setSkillLearning } from "../lib/settings-api";

// The skill-learning settings live on the shared LLM config snapshot, so the
// mutation writes back into the same `["llm-providers"]` query cache the rest
// of the Inference tab reads — no extra fetch and no divergent state.
const PROVIDERS_CACHE_KEY = ["llm-providers"];
const MODEL_CATALOG_QUERY_KEY = ["user-model-catalog"];

function normalizeModels(models) {
  const seen = new Set();
  const normalized = [];
  for (const value of models || []) {
    const model = String(value || "").trim();
    if (!model || seen.has(model)) continue;
    seen.add(model);
    normalized.push(model);
  }
  return normalized;
}

// Admin-only deployment-wide control (Settings → Inference). Enabling turns on
// a background review after every successful run; the chosen learning model
// rides the active provider's endpoint/credentials. All writes go through one
// coherent PUT body `{ enabled, model }` whose response is the authoritative
// snapshot.
export function SkillLearningSection({ providerState }) {
  const t = useT();
  const queryClient = useQueryClient();
  const toggleLabelId = React.useId();
  // The PUT response is authoritative. Pin it locally until the shared
  // `["llm-providers"]` cache propagates the same value, so the control
  // reflects reality immediately and can never disagree with the backend.
  const [authoritativeSkillLearning, setAuthoritativeSkillLearning] = React.useState(null);
  const skillLearning = authoritativeSkillLearning || providerState.skillLearning || null;
  const enabled = Boolean(skillLearning?.enabled);
  const invalid = enabled && skillLearning?.status === "invalid";
  const savedModel = String(skillLearning?.model || "").trim();

  const activeProvider = providerState.providers.find(
    (provider) => provider.id === providerState.activeProviderId
  );
  const noActiveProvider = !providerState.hasActiveProvider || !activeProvider;

  // Options come from state the active provider already exposes: the server
  // model catalog (`/llm/models`, shared query cache), the tenant model
  // policy, the active selection, and the stored learning model itself so it
  // stays visible after being toggled off or invalidated.
  const catalogQuery = useQuery({
    queryKey: MODEL_CATALOG_QUERY_KEY,
    queryFn: fetchUserModelCatalog,
    staleTime: 60_000,
    enabled: !noActiveProvider,
  });
  const modelOptions = normalizeModels([
    ...(catalogQuery.data?.models || []),
    ...(providerState.userModelPolicy?.allowed_models || []),
    providerState.selectedModel,
    activeProvider?.default_model,
    savedModel,
  ]);
  const selectOptions = modelOptions.map((model) => ({ value: model, label: model }));

  // Retain the last selected model locally so toggling off does not force a
  // re-choice on re-enable; the authoritative snapshot wins whenever it lands.
  const [draftModel, setDraftModel] = React.useState("");
  const [localError, setLocalError] = React.useState(null);
  React.useEffect(() => {
    setDraftModel(savedModel);
    setLocalError(null);
  }, [savedModel, providerState.activeProviderId]);

  const saveMutation = useMutation({
    mutationFn: setSkillLearning,
    onSuccess: (snapshot) => {
      if (!snapshot || typeof snapshot !== "object") return;
      queryClient.setQueryData(PROVIDERS_CACHE_KEY, snapshot);
      setAuthoritativeSkillLearning(snapshot.skill_learning || null);
    },
  });

  // Once the shared providers cache carries the applied value, drop the pin.
  React.useEffect(() => {
    if (!authoritativeSkillLearning) return;
    if (
      JSON.stringify(providerState.skillLearning || null) ===
      JSON.stringify(authoritativeSkillLearning)
    ) {
      setAuthoritativeSkillLearning(null);
    }
  }, [providerState.skillLearning, authoritativeSkillLearning]);

  const handleToggle = (next) => {
    if (saveMutation.isPending) return;
    setLocalError(null);
    saveMutation.reset();
    if (!next) {
      // Disabling keeps the selected model for later re-enable; a disabled
      // backend must short-circuit before any transcript I/O or model call.
      saveMutation.mutate({
        enabled: false,
        model: draftModel.trim() || savedModel || null,
      });
      return;
    }
    // Mirrors the backend's validation: enabling requires a non-empty model
    // from the active provider's catalog. Surface it inline and accessible
    // instead of sending a request that can only fail.
    const model = draftModel.trim();
    if (!model) {
      setLocalError(t("llm.skillLearningModelRequired"));
      return;
    }
    saveMutation.mutate({ enabled: true, model });
  };

  const handleModelChange = (value) => {
    const next = String(value || "").trim();
    saveMutation.reset();
    setDraftModel(next);
    setLocalError(null);
    // While learning runs, the choice applies immediately as one coherent
    // gesture; while off it only updates the draft used by the next enable.
    if (enabled && !noActiveProvider && next) {
      saveMutation.mutate({ enabled: true, model: next });
    }
  };

  const reasonText = String(skillLearning?.reason || "").trim();

  let statusNode;
  if (saveMutation.isPending) {
    statusNode = (
      <p role="status" data-testid="settings-skill-learning-status" className="text-xs text-[var(--v2-text-muted)]">
        {t("llm.skillLearningSaving")}
      </p>
    );
  } else if (localError || saveMutation.error) {
    statusNode = (
      <p role="alert" data-testid="settings-skill-learning-error" className="text-xs text-[var(--v2-danger-text)]">
        {localError ||
          (saveMutation.error instanceof ApiError
            ? t("error.saveFailed", { message: saveMutation.error.message })
            : t("llm.skillLearningSaveFailed"))}
      </p>
    );
  } else if (invalid) {
    // An invalid saved configuration never claims learning is running: copy
    // plus reason, not color alone.
    statusNode = (
      <div role="status" data-testid="settings-skill-learning-status" className="space-y-1">
        <p className="text-xs text-[var(--v2-warning-text)]">{t("llm.skillLearningInvalidNotice")}</p>
        {reasonText ? (
          <code className="block break-all font-mono text-[11px] text-[var(--v2-warning-text)]">
            {reasonText}
          </code>
        ) : null}
      </div>
    );
  } else {
    statusNode = (
      <p role="status" data-testid="settings-skill-learning-status"
        className={enabled ? "text-xs text-[var(--v2-positive-text)]" : "text-xs text-[var(--v2-text-muted)]"}>
        {enabled
          ? t("llm.skillLearningEnabledStatus")
          : noActiveProvider
            ? t("llm.skillLearningNoActiveProvider")
            : t("llm.skillLearningDisabledStatus")}
      </p>
    );
  }

  return (
    <Card padding="none" className="p-4 sm:p-5" data-testid="settings-skill-learning">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <h3 className="font-mono text-[11px] uppercase tracking-[0.14em] text-[var(--v2-accent-text)]">
            {t("llm.skillLearningTitle")}
          </h3>
          <p className="mt-2 max-w-2xl text-sm text-[var(--v2-text-muted)]">
            {t("llm.skillLearningDesc")}
          </p>
        </div>
        <div className="w-full min-w-0 space-y-4 xl:w-80 xl:max-w-full xl:flex-none">
          <div className="flex items-center justify-between gap-3">
            <span id={toggleLabelId} className="text-sm font-medium text-[var(--v2-text-strong)]">
              {t("llm.skillLearningToggleLabel")}
            </span>
            <Switch
              checked={enabled}
              onChange={handleToggle}
              disabled={noActiveProvider || saveMutation.isPending}
              aria-labelledby={toggleLabelId}
              data-testid="settings-skill-learning-switch"
            />
          </div>
          <div>
            <div className="mb-2 text-xs font-medium text-[var(--v2-text-muted)]">
              {t("llm.skillLearningModelLabel")}
            </div>
            <SelectMenu
              value={draftModel}
              options={selectOptions}
              onChange={handleModelChange}
              disabled={noActiveProvider || saveMutation.isPending}
              ariaLabel={t("llm.skillLearningModelLabel")}
              align="left"
              className="block w-full"
              buttonClassName="w-full min-w-0 overflow-hidden"
              menuClassName="w-full max-w-[calc(100vw-2rem)]"
              data-testid="settings-skill-learning-model"
            />
          </div>
          {statusNode}
        </div>
      </div>
    </Card>
  );
}
