import React from "react";
import {
  FlatList,
  KeyboardAvoidingView,
  Platform,
  StyleSheet,
  Text,
  View
} from "react-native";
import { useLocalSearchParams } from "expo-router";
import { useSession } from "@/auth/session-context";
import { Button, Card, Field, Screen, textStyles } from "@/components/ui";
import { clientActionId, messageText } from "@/lib/ids";
import {
  cacheTimeline,
  cachedTimeline,
  loadDraft,
  saveDraft
} from "@/storage/database";
import type { TimelineMessage } from "@/types";
import { colors } from "@/theme";

export default function ThreadScreen() {
  const params = useLocalSearchParams<{ id: string }>();
  const id = Array.isArray(params.id) ? params.id[0] ?? "" : params.id;
  const { api, deployment, session } = useSession();
  const scope = `${deployment.origin}|${session?.user_id ?? "cached"}`;
  const [messages, setMessages] = React.useState<TimelineMessage[]>([]);
  const [draft, setDraft] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [offline, setOffline] = React.useState(false);
  const [error, setError] = React.useState("");

  const refresh = React.useCallback(async () => {
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
    }
  }, [api, id, scope]);

  React.useEffect(() => {
    void Promise.all([refresh(), loadDraft(scope, id).then(setDraft)]);
  }, [id, refresh, scope]);

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
      await api.sendMessage(id, content, clientActionId());
      setDraft("");
      await saveDraft(scope, id, "");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not send");
    } finally {
      setBusy(false);
    }
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
        data={messages}
        keyExtractor={(item, index) => item.message_id ?? item.id ?? String(index)}
        contentContainerStyle={styles.list}
        onRefresh={() => void refresh()}
        refreshing={false}
        renderItem={({ item }) => {
          const role = item.role ?? item.kind ?? "message";
          return (
            <Card style={role === "user" ? styles.userCard : undefined}>
              <Text style={styles.role}>{role}</Text>
              <Text selectable style={textStyles.body}>{messageText(item) || JSON.stringify(item)}</Text>
            </Card>
          );
        }}
      />
      <View style={styles.composer}>
        {error ? <Text style={textStyles.error}>{error}</Text> : null}
        <Field
          multiline
          onChangeText={setDraft}
          placeholder="Ask your agent…"
          value={draft}
        />
        <Button
          title={busy ? "Sending…" : offline ? "Send when online" : "Send"}
          disabled={busy || offline || !draft.trim()}
          onPress={() => void send()}
        />
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
  userCard: { marginLeft: 32, backgroundColor: colors.surfaceRaised },
  role: { color: colors.primary, fontWeight: "700", textTransform: "capitalize" },
  offline: { backgroundColor: colors.warning, padding: 8, alignItems: "center" },
  offlineText: { color: colors.background, fontWeight: "700" }
});
