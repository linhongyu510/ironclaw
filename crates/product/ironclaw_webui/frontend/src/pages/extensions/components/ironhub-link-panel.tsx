// @ts-nocheck
import React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useT } from "../../../lib/i18n";
import { Card } from "../../../design-system/card";
import { Button } from "../../../design-system/button";
import { Icon } from "../../../design-system/icons";
import {
  clearIronhubSharedKey,
  getIronhubLink,
  setIronhubSharedKey,
} from "../../../lib/ironhub-link-api";

const IRONHUB_LINK_QUERY_KEY = ["ironhub", "link"];
const MIN_SHARED_KEY_LENGTH = 32;

export function IronhubLinkPanel() {
  const t = useT();
  const queryClient = useQueryClient();
  const [key, setKey] = React.useState("");

  const link = useQuery({
    queryKey: IRONHUB_LINK_QUERY_KEY,
    queryFn: getIronhubLink,
    retry: (_count, error) => error?.status !== 403,
  });

  const save = useMutation({
    mutationFn: () => setIronhubSharedKey(key),
    onSuccess: (next) => {
      queryClient.setQueryData(IRONHUB_LINK_QUERY_KEY, next);
      setKey("");
    },
  });

  const clear = useMutation({
    mutationFn: clearIronhubSharedKey,
    onSuccess: (next) => {
      queryClient.setQueryData(IRONHUB_LINK_QUERY_KEY, next);
    },
  });

  if (link.isPending || link.error?.status === 403) return null;

  if (link.error) {
    return (
      <Card padding="md">
        <p className="text-xs text-destructive">{t("ironhub.link.loadFailed")}</p>
      </Card>
    );
  }

  const status = link.data;
  const pendingRestart = status.key_stored && !status.key_active;
  const trimmedKey = key.trim();
  const tooShort = trimmedKey.length > 0 && trimmedKey.length < MIN_SHARED_KEY_LENGTH;

  return (
    <Card padding="md">
      <div className="space-y-4">
        <div>
          <h3 className="text-sm font-semibold">{t("ironhub.link.title")}</h3>
          <p className="mt-1 text-xs text-[var(--v2-text-muted)]">
            {t("ironhub.link.description")}
          </p>
        </div>

        <div className="space-y-1">
          <span className="text-xs font-medium text-[var(--v2-text-muted)]">
            {t("ironhub.link.agentUrl")}
          </span>
          {status.register_url
            ? (<code className="block break-all rounded-lg bg-[var(--v2-surface-muted)] px-3 py-2 text-xs">
                {status.register_url}
              </code>)
            : (<p className="text-xs text-[var(--v2-text-muted)]">
                {t("ironhub.link.agentUrlUnset")}
              </p>)}
        </div>

        <div className="space-y-2">
          <label
            className="text-xs font-medium text-[var(--v2-text-muted)]"
            htmlFor="ironhub-shared-key"
          >
            {t("ironhub.link.sharedKey")}
          </label>
          <input
            id="ironhub-shared-key"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={key}
            onChange={(event) => setKey(event.target.value)}
            placeholder="ihub_sk_..."
            className="w-full rounded-lg border border-[var(--v2-panel-border)] bg-transparent px-3 py-2 text-xs"
          />
          <div className="flex items-center gap-3">
            <Button
              onClick={() => save.mutate()}
              disabled={save.isPending || trimmedKey.length === 0 || tooShort}
            >
              {save.isPending ? t("common.saving") : t("common.save")}
            </Button>
            {status.key_stored
              ? (<Button
                  variant="ghost"
                  onClick={() => clear.mutate()}
                  disabled={clear.isPending}
                >
                  {t("ironhub.link.clearKey")}
                </Button>)
              : null}
            <span className="text-xs text-[var(--v2-text-muted)]">
              {status.key_active
                ? t("ironhub.link.stateActive")
                : status.key_stored
                  ? t("ironhub.link.stateStored")
                  : t("ironhub.link.stateAbsent")}
            </span>
          </div>
          {tooShort
            ? (<p className="text-xs text-destructive">{t("ironhub.link.keyTooShort")}</p>)
            : null}
          {save.error
            ? (<p className="text-xs text-destructive">{t("ironhub.link.saveFailed")}</p>)
            : null}
          {clear.error
            ? (<p className="text-xs text-destructive">{t("ironhub.link.clearFailed")}</p>)
            : null}
        </div>

        {pendingRestart
          ? (<div
              role="alert"
              className="flex items-start gap-3 rounded-xl border border-copper/30 bg-copper/10 px-4 py-3"
            >
              <Icon name="bolt" className="mt-0.5 h-4 w-4 shrink-0 text-copper" />
              <p className="text-xs text-copper">{t("settings.restartRequired")}</p>
            </div>)
          : null}
      </div>
    </Card>
  );
}
