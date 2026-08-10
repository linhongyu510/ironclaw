import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React from "react";

import {
  fetchThreadModelPreference,
  fetchUserModelCatalog,
  setThreadModelPreference,
} from "../../../lib/api";
import type {
  ThreadModelPreference,
  UserModelCatalog,
} from "../lib/model-picker-state";

const MODEL_CATALOG_QUERY_KEY = ["llm", "user-model-catalog"];

interface SaveModelVariables {
  targetThreadId: string;
  model: string | null;
}

function preferenceQueryKey(threadId: string | null) {
  return ["threads", threadId || "", "model-preference"];
}

export function useThreadModelPreference(threadId: string | null) {
  const queryClient = useQueryClient();
  const enabled = Boolean(threadId);
  const catalogQuery = useQuery<UserModelCatalog>({
    queryKey: MODEL_CATALOG_QUERY_KEY,
    queryFn: ({ signal }) => fetchUserModelCatalog({ signal }),
    enabled,
  });
  const preferenceQuery = useQuery<ThreadModelPreference>({
    queryKey: preferenceQueryKey(threadId),
    queryFn: ({ signal }) => fetchThreadModelPreference({ threadId, signal }),
    enabled,
  });
  const saveMutation = useMutation<
    ThreadModelPreference,
    Error,
    SaveModelVariables
  >({
    mutationFn: ({ targetThreadId, model }) =>
      setThreadModelPreference({ threadId: targetThreadId, model }),
    onSuccess: (response, variables) => {
      queryClient.setQueryData(
        preferenceQueryKey(variables.targetThreadId),
        response,
      );
    },
  });

  React.useEffect(() => {
    saveMutation.reset();
  }, [threadId]);

  return {
    catalog: catalogQuery.data || null,
    preference: preferenceQuery.data || null,
    isLoading:
      enabled &&
      (catalogQuery.isLoading || preferenceQuery.isLoading),
    loadError: catalogQuery.error || preferenceQuery.error || null,
    isSaving: saveMutation.isPending,
    saveError: saveMutation.error || null,
    selectModel(model: string | null) {
      if (!threadId) return Promise.resolve(null);
      saveMutation.reset();
      return saveMutation.mutateAsync({ targetThreadId: threadId, model });
    },
  };
}
