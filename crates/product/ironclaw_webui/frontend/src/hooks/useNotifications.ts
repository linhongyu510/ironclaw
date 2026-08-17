// @ts-nocheck
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React from "react";
import {
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from "../lib/api";
import { useI18n } from "../lib/i18n";
import { notificationMessages } from "../lib/notifications";

const NOTIFICATION_LIMIT = 30;
const NOTIFICATION_REFETCH_MS = 10_000;

export function useNotifications({
  profile,
  enabled = true,
  activeThreadId = null,
} = {}) {
  const { t } = useI18n();
  const queryClient = useQueryClient();
  const tenantId = profile?.tenant_id || null;
  const userId = profile?.user_id || null;
  const queryKey = ["notifications", "inbox", tenantId, userId];
  const query = useQuery({
    queryKey,
    queryFn: () => listNotifications({ limit: NOTIFICATION_LIMIT }),
    enabled: enabled && Boolean(tenantId && userId),
    refetchInterval: NOTIFICATION_REFETCH_MS,
    refetchIntervalInBackground: false,
  });

  const messages = React.useMemo(
    () => notificationMessages(query.data?.notifications, t),
    [query.data, t],
  );
  const unreadIds = React.useMemo(
    () => new Set(messages.filter((message) => !message.read).map((message) => message.id)),
    [messages],
  );

  const markRead = useMutation({
    mutationFn: markNotificationRead,
    onMutate: async (notificationId) => {
      await queryClient.cancelQueries({ queryKey });
      const previous = queryClient.getQueryData(queryKey);
      queryClient.setQueryData(queryKey, (current) => ({
        ...current,
        unread_count: Math.max(0, Number(current?.unread_count || 0) - 1),
        notifications: (current?.notifications || []).map((notification) =>
          notification.id === notificationId && !notification.read_at
            ? { ...notification, read_at: new Date().toISOString() }
            : notification,
        ),
      }));
      return { previous };
    },
    onError: (_error, _notificationId, context) => {
      if (context?.previous) queryClient.setQueryData(queryKey, context.previous);
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey }),
  });

  const markAllRead = useMutation({
    mutationFn: markAllNotificationsRead,
    onSuccess: () => queryClient.invalidateQueries({ queryKey }),
  });

  React.useEffect(() => {
    if (!activeThreadId) return;
    for (const message of messages) {
      if (
        !message.read &&
        message.href === `/chat/${encodeURIComponent(activeThreadId)}` &&
        !markRead.isPending
      ) {
        markRead.mutate(message.id);
        break;
      }
    }
  }, [activeThreadId, markRead, messages]);

  const dismissMessage = React.useCallback(
    (messageId) => {
      if (unreadIds.has(messageId)) markRead.mutate(messageId);
    },
    [markRead, unreadIds],
  );

  return {
    messages,
    unreadIds,
    unreadCount: Number(query.data?.unread_count || 0),
    hasUnread: Number(query.data?.unread_count || 0) > 0,
    isLoading: query.isLoading,
    error: query.error || markRead.error || markAllRead.error || null,
    refetch: query.refetch,
    dismissMessage,
    markAllRead: () => markAllRead.mutate(),
    isMarkingAllRead: markAllRead.isPending,
  };
}
