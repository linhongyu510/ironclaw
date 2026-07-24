import React from "react";
import { FlatList, Pressable, RefreshControl, StyleSheet, Text, View } from "react-native";
import { router } from "expo-router";
import { useSession } from "@/auth/session-context";
import { Button, Card, Screen, textStyles } from "@/components/ui";
import { cacheThreads, cachedThreads } from "@/storage/database";
import { clientActionId, threadId } from "@/lib/ids";
import type { ThreadRecord } from "@/types";
import { colors } from "@/theme";

function title(thread: ThreadRecord): string {
  return thread.title ?? thread.name ?? threadId(thread) ?? "Untitled thread";
}

export default function ThreadsScreen() {
  const { api, deployment, session } = useSession();
  const scope = `${deployment.origin}|${session?.user_id ?? "cached"}`;
  const [threads, setThreads] = React.useState<ThreadRecord[]>([]);
  const [refreshing, setRefreshing] = React.useState(false);
  const [offline, setOffline] = React.useState(false);
  const [error, setError] = React.useState("");

  const refresh = React.useCallback(async () => {
    setRefreshing(true);
    setError("");
    const local = await cachedThreads(scope);
    if (local.length) setThreads(local);
    try {
      const response = await api.listThreads();
      setThreads(response.threads);
      await cacheThreads(scope, response.threads);
      setOffline(false);
    } catch (reason) {
      setOffline(true);
      if (!local.length) setError(reason instanceof Error ? reason.message : "Could not load threads");
    } finally {
      setRefreshing(false);
    }
  }, [api, scope]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  async function create() {
    setRefreshing(true);
    try {
      const response = await api.createThread(clientActionId());
      await refresh();
      const id = threadId(response.thread);
      if (id) router.push({ pathname: "/thread/[id]", params: { id } });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create thread");
      setRefreshing(false);
    }
  }

  return (
    <Screen style={styles.flush}>
      {offline ? (
        <View style={styles.offline}>
          <Text style={styles.offlineText}>Offline · showing saved threads</Text>
        </View>
      ) : null}
      <View style={styles.actions}>
        <Text style={textStyles.muted}>{deployment.name}</Text>
        <Button title="New thread" disabled={refreshing || offline} onPress={() => void create()} />
      </View>
      {error ? <Text style={[textStyles.error, styles.pad]}>{error}</Text> : null}
      <FlatList
        data={threads}
        keyExtractor={(item, index) => threadId(item) || String(index)}
        contentContainerStyle={styles.list}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void refresh()} />}
        ListEmptyComponent={
          !refreshing ? (
            <Card>
              <Text style={textStyles.heading}>No threads yet</Text>
              <Text style={textStyles.muted}>Start a conversation with your agent.</Text>
            </Card>
          ) : null
        }
        renderItem={({ item }) => (
          <Pressable
            onPress={() =>
              router.push({ pathname: "/thread/[id]", params: { id: threadId(item) } })
            }
          >
            <Card>
              <Text numberOfLines={2} style={textStyles.heading}>{title(item)}</Text>
              <Text numberOfLines={1} style={textStyles.muted}>{threadId(item)}</Text>
            </Card>
          </Pressable>
        )}
      />
    </Screen>
  );
}

const styles = StyleSheet.create({
  flush: { padding: 0, gap: 0 },
  actions: { padding: 16, gap: 10 },
  list: { padding: 16, paddingTop: 4, gap: 10 },
  pad: { paddingHorizontal: 16 },
  offline: { backgroundColor: colors.warning, padding: 8, alignItems: "center" },
  offlineText: { color: colors.background, fontWeight: "700" }
});
