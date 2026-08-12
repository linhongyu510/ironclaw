// @ts-nocheck
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React from "react";
import { getNotificationSetupStatus } from "../../../lib/api";
import {
  enrollThisBrowser,
  getDevicePushState,
  unenrollThisBrowser,
} from "../../../lib/device-push";

const setupStatusQueryKey = (extensionId) => [
  "notification-setup",
  extensionId,
  "status",
];

/**
 * Derive the panel-facing device state from the raw browser probe plus the
 * account correlation:
 *   "checking" | "unsupported" | "permission-denied" | "not-enrolled"
 *   "enrolled"                — subscription verified to belong to THIS account
 *   "enrolled-other-account"  — a subscription exists but this account holds
 *                               no record for it (another account enrolled in
 *                               this browser profile)
 *   "enrolled-unverified"     — a subscription exists but correlation was
 *                               unavailable (e.g. the status query failed);
 *                               no disable action is offered from this state.
 */
function deriveDeviceState(probe) {
  if (!probe || probe.state !== "enrolled") return probe?.state || "checking";
  if (probe.accountMatch === true) return "enrolled";
  if (probe.accountMatch === false) return "enrolled-other-account";
  return "enrolled-unverified";
}

/**
 * Per-browser push-device state for the notification-channels panel's
 * session-channel row: the account-level enrollment summary (the generic
 * notification-setup status view, keyed by the session channel's
 * `extensionId`) plus this browser's own push state, with enroll/unenroll
 * actions.
 *
 * The status response's channel-opaque `detail` is interpreted HERE — this
 * hook is part of the session channel's own client — as
 * `{ bootstrap: { vapid_public_key }, registration_count,
 *    registrations[].registration_id }`.
 * The account-level toggle (whether the channel is a notification channel)
 * stays in the ordinary draft/save set — this hook only manages the device
 * dimension underneath it. The server never echoes endpoint capability URLs
 * (or endpoint-derived identifiers). The browser instead remembers the
 * opaque registration id returned by enrollment and intersects that local
 * association with this account's status ids.
 */
export function useDevicePush({ extensionId } = {}) {
  const queryClient = useQueryClient();
  const statusQuery = useQuery({
    queryKey: setupStatusQueryKey(extensionId),
    queryFn: () => getNotificationSetupStatus({ extensionId }),
    enabled: Boolean(extensionId),
  });

  const [probe, setProbe] = React.useState(null);
  // A post-action probe result is authoritative until the status refetch
  // settles; the effect below only overwrites it once fresh data arrives.
  const statusDetail = statusQuery.data?.detail;
  const statusSettled = !statusQuery.isLoading;
  React.useEffect(() => {
    if (!statusSettled) return undefined;
    let cancelled = false;
    const accountRegistrationIds = statusDetail
      ? (statusDetail.registrations || [])
          .map((registration) => registration.registration_id)
          .filter((registrationId) => typeof registrationId === "string" && registrationId)
      : null;
    getDevicePushState({ extensionId, accountRegistrationIds }).then(
      (state) => {
        if (!cancelled) setProbe(state);
      },
      () => {
        if (!cancelled) setProbe({ state: "unsupported" });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [extensionId, statusSettled, statusDetail]);

  const refreshAfterAction = async (nextState) => {
    setProbe(nextState);
    await queryClient.invalidateQueries({
      queryKey: setupStatusQueryKey(extensionId),
    });
    return nextState;
  };

  const enrollMutation = useMutation({
    mutationFn: () => {
      if (!extensionId) {
        throw new Error("session channel extension is unavailable");
      }
      const vapidPublicKey = statusQuery.data?.detail?.bootstrap?.vapid_public_key;
      if (!vapidPublicKey) {
        throw new Error("notification setup key is unavailable");
      }
      return enrollThisBrowser({ extensionId, vapidPublicKey });
    },
    onSuccess: (nextState) => refreshAfterAction(nextState),
  });
  const unenrollMutation = useMutation({
    mutationFn: () => {
      const accountRegistrationIds = (statusQuery.data?.detail?.registrations || [])
        .map((registration) => registration.registration_id)
        .filter((registrationId) => typeof registrationId === "string" && registrationId);
      return unenrollThisBrowser({ extensionId, accountRegistrationIds });
    },
    onSuccess: (nextState) => refreshAfterAction(nextState),
  });

  return {
    browser: { ...(probe || {}), state: deriveDeviceState(probe) },
    subscriptionCount: statusQuery.data?.detail?.registration_count ?? 0,
    vapidPublicKey: statusQuery.data?.detail?.bootstrap?.vapid_public_key || "",
    isStatusLoading: statusQuery.isLoading,
    statusError: statusQuery.error || null,
    isBusy: enrollMutation.isPending || unenrollMutation.isPending,
    actionError: enrollMutation.error || unenrollMutation.error || null,
    enroll: () => enrollMutation.mutateAsync(),
    unenroll: () => unenrollMutation.mutateAsync(),
  };
}
