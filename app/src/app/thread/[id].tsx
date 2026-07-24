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
import { useLocalSearchParams } from "expo-router";
import * as DocumentPicker from "expo-document-picker";
import * as Haptics from "expo-haptics";
import * as Clipboard from "expo-clipboard";
import { readAsStringAsync, EncodingType } from "expo-file-system/legacy";
import { useSession } from "@/auth/session-context";
import { Button, Card, Field, Screen, textStyles } from "@/components/ui";
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

function actionFor(item: TimelineMessage) {
  const raw = item as Record<string, unknown>;
  const role = String(raw.role ?? raw.kind ?? "");
  const name = raw.toolName ?? raw.tool_name ?? raw.capability_name ?? raw.capability_id;
  const preview = raw.capability_display_preview ?? raw.tool_result_preview ?? raw.toolResultPreview;
  const isAction = role === "tool_activity" || role === "tool" || role === "capability" || name != null || raw.capability_display_preview != null;
  if (!isAction) return null;
  const rawStatus = String(raw.toolStatus ?? raw.tool_status ?? raw.status ?? (raw.error ? "error" : "success"));
  const status = rawStatus === "completed" || rawStatus === "ok" ? "success" : rawStatus;
  return {
    name: valueText(name || "Agent action"),
    status,
    detail: valueText(raw.toolDetail ?? raw.tool_detail),
    parameters: valueText(raw.toolParameters ?? raw.tool_parameters ?? raw.capability_parameters),
    result: valueText(preview),
    error: valueText(raw.toolError ?? raw.tool_error ?? raw.error)
  };
}

export default function ThreadScreen() {
  const params = useLocalSearchParams<{ id: string }>();
  const id = Array.isArray(params.id) ? params.id[0] ?? "" : params.id;
  const { api, deployment, session } = useSession();
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
    const local = await cachedTimeline(scope, id);
    if (local.length) setMessages(local);
    try {
      const response = await api.timeline(id);
      setMessages(response.messages);
      await cacheTimeline(scope, id, response.messages);
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

  return (
    <KeyboardAvoidingView
      style={styles.root}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      keyboardVerticalOffset={88}
    >
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
        renderItem={({ item }) => {
          const role = item.role ?? item.kind ?? "message";
          const action = actionFor(item);
          if (action) {
            return <CollapsibleAction {...action} />;
          }
          const content = messageText(item);
          return (
            <Card style={role === "user" ? styles.userCard : undefined}>
              <Text style={styles.role}>{role}</Text>
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
            </Card>
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
        <Field
          multiline
          onChangeText={setDraft}
          placeholder="Ask your agent…"
          value={draft}
        />
        <View style={styles.composerRow}>
          <View style={styles.attachButton}><Button title="＋" tone="secondary" disabled={busy || offline} onPress={() => void pickAttachment()} /></View>
          <View style={styles.sendButton}>{activeRunId ? <Button title="Stop" tone="danger" onPress={() => void cancel()} /> : <Button title={busy ? "Sending…" : offline ? "Offline" : "Send"} disabled={busy || offline || !draft.trim()} onPress={() => void send()} />}</View>
        </View>
        {latestRunId && !activeRunId ? <Button title="Retry last run" tone="secondary" onPress={() => void retry()} /> : null}
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  list: { padding: 16, gap: 10 },
  composer: {
    backgroundColor: colors.surface,
    borderTopColor: colors.border,
    borderTopWidth: 1,
    padding: 12,
    gap: 8
  },
  composerRow: { flexDirection: "row", gap: 8 },
  attachButton: { width: 54 },
  sendButton: { flex: 1 },
  attachments: { flexDirection: "row", flexWrap: "wrap", gap: 6 },
  attachment: { color: colors.primaryText, backgroundColor: colors.primarySoft, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 5, maxWidth: "100%" },
  copy: { alignSelf: "flex-start", paddingVertical: 3, paddingHorizontal: 2 },
  copyText: { color: colors.muted, fontSize: 12 },
  userCard: { marginLeft: 32, backgroundColor: colors.surfaceRaised },
  role: { color: colors.primary, fontWeight: "700", textTransform: "capitalize" },
  offline: { backgroundColor: colors.warning, padding: 8, alignItems: "center" },
  offlineText: { color: colors.background, fontWeight: "700" }
});
