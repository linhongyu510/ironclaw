// @ts-nocheck
import React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card } from "../../../design-system/card";
import { SelectMenu } from "../../../design-system/select-menu";
import { Switch } from "../../../design-system/switch";
import { ApiError } from "../../../lib/api";
import { useT } from "../../../lib/i18n";
import { fetchUserModelCatalog, setLearning } from "../lib/settings-api";

// The learning settings live on the shared LLM config snapshot, so the
// mutation writes back into the same `["llm-providers"]` query cache the rest
// of the Inference tab reads — no extra fetch and no divergent state.
const PROVIDERS_CACHE_KEY = ["llm-providers"];
const MODEL_CATALOG_QUERY_KEY = ["user-model-catalog"];
const MEMORY_WRITE_POLICY_OPTIONS = [
  { value: "staged", labelKey: "llm.learningMemoryPolicyStaged" },
  { value: "automatic", labelKey: "llm.learningMemoryPolicyAutomatic" },
];

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
// uses the active provider's endpoint and credentials. One coherent PUT body
// carries the gate, model, and staged-or-automatic memory write policy.
export function LearningSection({ providerState }) {
  const t = useT();
  const queryClient = useQueryClient();
  const toggleLabelId = React.useId();
  // The PUT response is authoritative. Pin it locally until the shared
  // `["llm-providers"]` cache propagates the same value, so the control
  // reflects reality immediately and can never disagree with the backend.
  const [authoritativeLearning, setAuthoritativeLearning] = React.useState(null);
  const learning = authoritativeLearning || providerState.learning || null;
  const enabled = Boolean(learning?.enabled);
  const invalid = enabled && learning?.status === "invalid";
  const savedModel = String(learning?.model || "").trim();
  const memoryWritePolicy =
    learning?.memory_write_policy === "automatic" ? "automatic" : "staged";

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
  const memoryPolicyOptions = MEMORY_WRITE_POLICY_OPTIONS.map((option) => ({
    value: option.value,
    label: t(option.labelKey),
  }));

  // Retain the last selected model locally so toggling off does not force a
  // re-choice on re-enable; the authoritative snapshot wins whenever it lands.
  const [draftModel, setDraftModel] = React.useState("");
  const [localError, setLocalError] = React.useState(null);
  React.useEffect(() => {
    setDraftModel(savedModel);
    setLocalError(null);
  }, [savedModel, providerState.activeProviderId]);

  const saveMutation = useMutation({
    mutationFn: setLearning,
    onSuccess: (snapshot) => {
      if (!snapshot || typeof snapshot !== "object") return;
      queryClient.setQueryData(PROVIDERS_CACHE_KEY, snapshot);
      setAuthoritativeLearning(snapshot.learning || null);
    },
  });

  // Once the shared providers cache carries the applied value, drop the pin.
  React.useEffect(() => {
    if (!authoritativeLearning) return;
    if (
      JSON.stringify(providerState.learning || null) ===
      JSON.stringify(authoritativeLearning)
    ) {
      setAuthoritativeLearning(null);
    }
  }, [providerState.learning, authoritativeLearning]);

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
        memory_write_policy: memoryWritePolicy,
      });
      return;
    }
    // Mirrors the backend's validation: enabling requires a non-empty model
    // from the active provider's catalog. Surface it inline and accessible
    // instead of sending a request that can only fail.
    const model = draftModel.trim();
    if (!model) {
      setLocalError(t("llm.learningModelRequired"));
      return;
    }
    saveMutation.mutate({
      enabled: true,
      model,
      memory_write_policy: memoryWritePolicy,
    });
  };

  const handleModelChange = (value) => {
    const next = String(value || "").trim();
    saveMutation.reset();
    setDraftModel(next);
    setLocalError(null);
    // While learning runs, the choice applies immediately as one coherent
    // gesture; while off it only updates the draft used by the next enable.
    if (enabled && !noActiveProvider && next) {
      saveMutation.mutate({
        enabled: true,
        model: next,
        memory_write_policy: memoryWritePolicy,
      });
    }
  };

  const handleMemoryWritePolicyChange = (value) => {
    if (saveMutation.isPending) return;
    const next = value === "automatic" ? "automatic" : "staged";
    saveMutation.reset();
    setLocalError(null);
    saveMutation.mutate({
      enabled,
      model: draftModel.trim() || savedModel || null,
      memory_write_policy: next,
    });
  };

  const reasonText = String(learning?.reason || "").trim();

  let statusNode;
  if (saveMutation.isPending) {
    statusNode = (
      <p role="status" data-testid="settings-learning-status" className="text-xs text-[var(--v2-text-muted)]">
        {t("llm.learningSaving")}
      </p>
    );
  } else if (localError || saveMutation.error) {
    statusNode = (
      <p role="alert" data-testid="settings-learning-error" className="text-xs text-[var(--v2-danger-text)]">
        {localError ||
          (saveMutation.error instanceof ApiError
            ? t("error.saveFailed", { message: saveMutation.error.message })
            : t("llm.learningSaveFailed"))}
      </p>
    );
  } else if (invalid) {
    // An invalid saved configuration never claims learning is running: copy
    // plus reason, not color alone.
    statusNode = (
      <div role="status" data-testid="settings-learning-status" className="space-y-1">
        <p className="text-xs text-[var(--v2-warning-text)]">{t("llm.learningInvalidNotice")}</p>
        {reasonText ? (
          <code className="block break-all font-mono text-[11px] text-[var(--v2-warning-text)]">
            {reasonText}
          </code>
        ) : null}
      </div>
    );
  } else {
    statusNode = (
      <p role="status" data-testid="settings-learning-status"
        className={enabled ? "text-xs text-[var(--v2-positive-text)]" : "text-xs text-[var(--v2-text-muted)]"}>
        {enabled
          ? t("llm.learningEnabledStatus")
          : noActiveProvider
            ? t("llm.learningNoActiveProvider")
            : t("llm.learningDisabledStatus")}
      </p>
    );
  }

  return (
    <Card padding="none" className="p-4 sm:p-5" data-testid="settings-learning">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <h3 className="font-mono text-[11px] uppercase tracking-[0.14em] text-[var(--v2-accent-text)]">
            {t("llm.learningTitle")}
          </h3>
          <p className="mt-2 max-w-2xl text-sm text-[var(--v2-text-muted)]">
            {t("llm.learningDesc")}
          </p>
        </div>
        <div className="w-full min-w-0 space-y-4 xl:w-80 xl:max-w-full xl:flex-none">
          <div className="flex items-center justify-between gap-3">
            <span id={toggleLabelId} className="text-sm font-medium text-[var(--v2-text-strong)]">
              {t("llm.learningToggleLabel")}
            </span>
            <Switch
              checked={enabled}
              onChange={handleToggle}
              disabled={noActiveProvider || saveMutation.isPending}
              aria-labelledby={toggleLabelId}
              data-testid="settings-learning-switch"
            />
          </div>
          <div>
            <div className="mb-2 text-xs font-medium text-[var(--v2-text-muted)]">
              {t("llm.learningModelLabel")}
            </div>
            <SelectMenu
              value={draftModel}
              options={selectOptions}
              onChange={handleModelChange}
              disabled={noActiveProvider || saveMutation.isPending}
              ariaLabel={t("llm.learningModelLabel")}
              align="left"
              className="block w-full"
              buttonClassName="w-full min-w-0 overflow-hidden"
              menuClassName="w-full max-w-[calc(100vw-2rem)]"
              data-testid="settings-learning-model"
            />
          </div>
          <div>
            <div className="mb-2 text-xs font-medium text-[var(--v2-text-muted)]">
              {t("llm.learningMemoryPolicyLabel")}
            </div>
            <SelectMenu
              value={memoryWritePolicy}
              options={memoryPolicyOptions}
              onChange={handleMemoryWritePolicyChange}
              disabled={saveMutation.isPending}
              ariaLabel={t("llm.learningMemoryPolicyLabel")}
              align="left"
              className="block w-full"
              buttonClassName="w-full min-w-0 overflow-hidden"
              menuClassName="w-full max-w-[calc(100vw-2rem)]"
              data-testid="settings-learning-memory-policy"
            />
            <p className="mt-2 text-xs text-[var(--v2-text-muted)]">
              {t("llm.learningMemoryPolicyHelp")}
            </p>
          </div>
          {statusNode}
        </div>
      </div>
    </Card>
  );
}
