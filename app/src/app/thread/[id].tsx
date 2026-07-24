import React from "react";
import {
  AppState,
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  View
} from "react-native";
import { useLocalSearchParams, useNavigation } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import * as DocumentPicker from "expo-document-picker";
import * as Haptics from "expo-haptics";
import * as Clipboard from "expo-clipboard";
import { readAsStringAsync, EncodingType } from "expo-file-system/legacy";
import { useSession } from "@/auth/session-context";
import { Button, Field, Screen, textStyles } from "@/components/ui";
import { CollapsibleAction, Markdown } from "@/components/markdown";
import { clientActionId, messageText } from "@/lib/ids";
import {
  cacheTimeline,
  cachedTimeline,
  loadDraft,
  saveDraft
} from "@/storage/database";
import type { DraftAttachment, TimelineMessage } from "@/types";
import { colors } from "@/theme";

function valueText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value == null) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function visibleTimeline(messages: TimelineMessage[]): TimelineMessage[] {
  return messages.filter((message) => {
    const raw = message as Record<string, unknown>;
    if (raw.kind === "tool_result_reference") return false;
    if (typeof raw.content === "string" && raw.content.trimStart().startsWith("{")) {
      try {
        const parsed: unknown = JSON.parse(raw.content);
        if (parsed && typeof parsed === "object" && "result_ref" in parsed && "safe_summary" in parsed) return false;
      } catch {
        // Keep malformed or ordinary message content visible.
      }
    }
    return true;
  });
}

function actionFor(item: TimelineMessage) {
  const raw = item as Record<string, unknown>;
  const role = String(raw.role ?? raw.kind ?? "");
  let envelope: Record<string, unknown> = raw;
  if (typeof raw.content === "string" && (raw.kind === "capability_display_preview" || raw.content.trimStart().startsWith("{"))) {
    try {
      const parsed: unknown = JSON.parse(raw.content);
      if (parsed && typeof parsed === "object" && (raw.kind === "capability_display_preview" || "invocation_id" in parsed || "capability_id" in parsed)) {
        envelope = parsed as Record<string, unknown>;
      }
    } catch {
      return null;
    }
  }
  const name = envelope.toolName ?? envelope.tool_name ?? envelope.capability_name ?? envelope.capability_id ?? envelope.title;
  const preview = envelope.capability_display_preview ?? envelope.tool_result_preview ?? envelope.toolResultPreview ?? envelope.output_preview ?? envelope.output_summary;
  const isAction = raw.kind === "capability_display_preview" || role === "tool_activity" || role === "tool" || role === "capability" || name != null || raw.capability_display_preview != null;
  if (!isAction) return null;
  const rawStatus = String(envelope.toolStatus ?? envelope.tool_status ?? envelope.status ?? (envelope.error ? "error" : "success"));
  const status = rawStatus === "completed" || rawStatus === "ok" ? "success" : rawStatus === "failed" || rawStatus === "killed" ? "error" : rawStatus;
  return {
    name: valueText(name || "Agent action"),
    status,
    detail: valueText(envelope.toolDetail ?? envelope.tool_detail ?? envelope.subtitle),
    parameters: valueText(envelope.toolParameters ?? envelope.tool_parameters ?? envelope.capability_parameters ?? envelope.input_summary),
    result: valueText(preview),
    error: valueText(envelope.toolError ?? envelope.tool_error ?? envelope.error ?? envelope.output_summary)
  };
}

export default function ThreadScreen() {
  const params = useLocalSearchParams<{ id: string }>();
  const id = Array.isArray(params.id) ? params.id[0] ?? "" : params.id;
  const { api, deployment, session } = useSession();
  const navigation = useNavigation();
  const scope = `${deployment.origin}|${session?.user_id ?? "cached"}`;
  const [messages, setMessages] = React.useState<TimelineMessage[]>([]);
  const [draft, setDraft] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);
  const [attachments, setAttachments] = React.useState<DraftAttachment[]>([]);
  const [showJump, setShowJump] = React.useState(false);
  const [copiedId, setCopiedId] = React.useState("");
  const listRef = React.useRef<FlatList<TimelineMessage>>(null);
  const [offline, setOffline] = React.useState(false);
  const [error, setError] = React.useState("");

  const activeRunId = React.useMemo(() => {
    const running = [...messages].reverse().find((message) => {
      const value = (message as Record<string, unknown>).status ?? (message as Record<string, unknown>).toolStatus;
      return value === "running" || value === "pending" || value === "in_progress";
    });
    const raw = running as Record<string, unknown> | undefined;
    return String(raw?.run_id ?? raw?.runId ?? raw?.turn_run_id ?? raw?.turnRunId ?? "") || null;
  }, [messages]);
  const latestRunId = React.useMemo(() => {
    const raw = [...messages].reverse().map((message) => message as Record<string, unknown>).find((message) => message.run_id || message.runId || message.turn_run_id || message.turnRunId);
    return String(raw?.run_id ?? raw?.runId ?? raw?.turn_run_id ?? raw?.turnRunId ?? "") || null;
  }, [messages]);

  const refresh = React.useCallback(async () => {
    setRefreshing(true);
    const local = visibleTimeline(await cachedTimeline(scope, id));
    if (local.length) setMessages(local);
    try {
      const response = await api.timeline(id);
      const visible = visibleTimeline(response.messages);
      setMessages(visible);
      await cacheTimeline(scope, id, visible);
      setOffline(false);
    } catch (reason) {
      setOffline(true);
      if (!local.length) setError(reason instanceof Error ? reason.message : "Could not load");
    } finally {
      setRefreshing(false);
    }
  }, [api, id, scope]);

  React.useEffect(() => {
    void Promise.all([refresh(), loadDraft(scope, id).then(setDraft)]);
  }, [id, refresh, scope]);

  React.useEffect(() => {
    const interval = setInterval(() => {
      if (AppState.currentState === "active") void refresh();
    }, 1000);
    return () => clearInterval(interval);
  }, [refresh]);

  React.useEffect(() => {
    const timeout = setTimeout(() => void saveDraft(scope, id, draft), 250);
    return () => clearTimeout(timeout);
  }, [draft, id, scope]);

  async function send() {
    const content = draft.trim();
    if (!content) return;
    setBusy(true);
    setError("");
    try {
      const wireAttachments = await Promise.all(
        attachments.map(async (attachment) => ({
          mime_type: attachment.mimeType || "application/octet-stream",
          filename: attachment.name,
          data_base64: await readAsStringAsync(attachment.uri, { encoding: EncodingType.Base64 })
        }))
      );
      await Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light).catch(() => undefined);
      await api.sendMessage(id, content, clientActionId(), wireAttachments);
      setDraft("");
      setAttachments([]);
      await saveDraft(scope, id, "");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not send");
    } finally {
      setBusy(false);
    }
  }

  async function pickAttachment() {
    const result = await DocumentPicker.getDocumentAsync({ multiple: true, copyToCacheDirectory: true });
    if (result.canceled) return;
    setAttachments((current) => [
      ...current,
      ...result.assets.map((asset) => ({ id: `${asset.name}-${asset.size ?? Date.now()}`, name: asset.name, mimeType: asset.mimeType ?? "application/octet-stream", uri: asset.uri, size: asset.size }))
    ].slice(0, 10));
  }

  async function cancel() {
    if (!activeRunId) return;
    try {
      await api.cancelRun(id, activeRunId);
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not stop run");
    }
  }

  async function retry() {
    if (!latestRunId) return;
    setError("");
    try {
      await api.retryRun(id, latestRunId, clientActionId());
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not retry run");
    }
  }

  async function copyMessage(item: TimelineMessage) {
    const content = messageText(item);
    if (!content) return;
    await Clipboard.setStringAsync(content);
    setCopiedId(item.message_id ?? item.id ?? "");
    await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => undefined);
    setTimeout(() => setCopiedId(""), 1400);
  }

  function retryableMessage(item: TimelineMessage, index: number) {
    const role = item.role ?? item.kind ?? "";
    const status = String((item as Record<string, unknown>).status ?? "");
    return !activeRunId && Boolean(latestRunId) && index === messages.length - 1 &&
      (role === "error" || status === "error" || status === "failed");
  }

  return (
    <KeyboardAvoidingView
      style={styles.root}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      keyboardVerticalOffset={88}
    >
      <Pressable accessibilityRole="button" accessibilityLabel="Open navigation" onPress={() => (navigation as unknown as { openDrawer: () => void }).openDrawer()} style={styles.drawerButton}>
        <Ionicons name="menu-outline" size={21} color={colors.text} />
      </Pressable>
      {offline ? (
        <View style={styles.offline}>
          <Text style={styles.offlineText}>Offline · saved conversation</Text>
        </View>
      ) : null}
      <FlatList
        ref={listRef}
        data={messages}
        keyExtractor={(item, index) => item.message_id ?? item.id ?? String(index)}
        contentContainerStyle={styles.list}
        onRefresh={() => void refresh()}
        refreshing={refreshing}
        onScroll={({ nativeEvent }) => {
          const distance = nativeEvent.contentSize.height - nativeEvent.contentOffset.y - nativeEvent.layoutMeasurement.height;
          setShowJump(distance > 240);
        }}
        scrollEventThrottle={100}
        renderItem={({ item, index }) => {
          const role = item.role ?? item.kind ?? "message";
          const action = actionFor(item);
          if (action) {
            return <CollapsibleAction {...action} onRetry={action.status === "error" && !activeRunId && latestRunId ? () => void retry() : undefined} />;
          }
          const content = messageText(item);
          return (
            <View style={role === "user" ? styles.userCard : styles.assistantMessage}>
              {role === "assistant" || role === "system" || role === "error" ? (
                <Markdown content={content} />
              ) : (
                <Text selectable style={textStyles.body}>{content}</Text>
              )}
              {role === "assistant" && content ? (
                <Pressable accessibilityRole="button" onPress={() => void copyMessage(item)} style={styles.copy}>
                  <Text style={styles.copyText}>{copiedId === (item.message_id ?? item.id ?? "") ? "Copied" : "Copy"}</Text>
                </Pressable>
              ) : null}
              {retryableMessage(item, index) ? (
                <Pressable accessibilityRole="button" onPress={() => void retry()} style={styles.retry}>
                  <Text style={styles.retryText}>Retry</Text>
                </Pressable>
              ) : null}
            </View>
          );
        }}
      />
      {showJump ? (
        <Button title="↓ Latest" tone="secondary" onPress={() => listRef.current?.scrollToEnd({ animated: true })} />
      ) : null}
      <View style={styles.composer}>
        {error ? <Text style={textStyles.error}>{error}</Text> : null}
        {attachments.length ? (
          <View style={styles.attachments}>
            {attachments.map((attachment) => <Text key={attachment.id} numberOfLines={1} style={styles.attachment}>📎 {attachment.name}</Text>)}
          </View>
        ) : null}
        <View style={styles.composerRow}>
          <View style={styles.composerInput}>
            <Field
              multiline
              onChangeText={setDraft}
              onKeyPress={(event) => {
                const keyEvent = event.nativeEvent as unknown as { key?: string; metaKey?: boolean; ctrlKey?: boolean };
                if (keyEvent.key === "Enter" && (keyEvent.metaKey || keyEvent.ctrlKey)) {
                  event.preventDefault();
                  void send();
                }
              }}
              placeholder="Ask your agent…"
              value={draft}
              style={styles.composerField}
            />
          </View>
          <View style={styles.attachButton}><Button compact title="＋" tone="secondary" disabled={busy || offline} onPress={() => void pickAttachment()} /></View>
          <Button compact title={activeRunId ? "■" : "↑"} tone={activeRunId ? "danger" : "primary"} disabled={busy || offline || (!activeRunId && !draft.trim())} onPress={() => void (activeRunId ? cancel() : send())} />
        </View>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  drawerButton: { position: "absolute", top: 10, left: 10, zIndex: 5, width: 38, height: 38, borderRadius: 19, alignItems: "center", justifyContent: "center", backgroundColor: colors.surfaceRaised, borderColor: colors.border, borderWidth: 1 },
  list: { padding: 16, gap: 10 },
  composer: {
    backgroundColor: colors.surface,
    borderTopColor: colors.border,
    borderTopWidth: 1,
    padding: 12,
    gap: 8
  },
  composerRow: { flexDirection: "row", gap: 8, alignItems: "flex-end" },
  composerInput: { flex: 1 },
  composerField: { maxHeight: 140, minHeight: 44, paddingRight: 12 },
  attachButton: { width: 40 },
  attachments: { flexDirection: "row", flexWrap: "wrap", gap: 6 },
  attachment: { color: colors.primaryText, backgroundColor: colors.primarySoft, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 5, maxWidth: "100%" },
  copy: { alignSelf: "flex-start", paddingVertical: 3, paddingHorizontal: 2 },
  copyText: { color: colors.muted, fontSize: 12 },
  retry: { alignSelf: "flex-start", marginTop: 8, paddingHorizontal: 10, paddingVertical: 6, borderRadius: 8, backgroundColor: colors.surfaceRaised },
  retryText: { color: colors.primaryText, fontSize: 13, fontWeight: "700" },
  assistantMessage: { width: "100%", paddingHorizontal: 4, paddingVertical: 8 },
  userCard: { marginLeft: 32, backgroundColor: colors.surfaceRaised },
  offline: { backgroundColor: colors.warning, padding: 8, alignItems: "center" },
  offlineText: { color: colors.background, fontWeight: "700" }
});
