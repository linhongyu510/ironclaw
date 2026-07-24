import React from "react";
import { ScrollView, StyleSheet, Switch, Text, View } from "react-native";
import { useSession } from "@/auth/session-context";
import { Button, Card, Screen, textStyles } from "@/components/ui";
import type { ToolSetting } from "@/types";
import { colors } from "@/theme";

export default function SettingsScreen() {
  const { api, deployment, session, signOut } = useSession();
  const [tools, setTools] = React.useState<ToolSetting[]>([]);
  const [autoApprove, setAutoApprove] = React.useState(false);
  const [error, setError] = React.useState("");

  const refresh = React.useCallback(async () => {
    try {
      const entries = await api.toolSettings();
      setTools(entries);
      const global = entries.find((entry) => entry.key === "tools.auto_approve");
      setAutoApprove(Boolean(global?.value));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load settings");
    }
  }, [api]);

  React.useEffect(() => void refresh(), [refresh]);

  async function updateAutoApprove(enabled: boolean) {
    setAutoApprove(enabled);
    try {
      await api.setGlobalAutoApprove(enabled);
      await refresh();
    } catch (reason) {
      setAutoApprove(!enabled);
      setError(reason instanceof Error ? reason.message : "Could not update setting");
    }
  }

  return (
    <Screen style={styles.flush}>
      <ScrollView contentContainerStyle={styles.content}>
        <Card>
          <Text style={textStyles.heading}>Agent connection</Text>
          <Text style={textStyles.body}>{deployment.name}</Text>
          <Text selectable style={textStyles.muted}>{deployment.origin}</Text>
          <Text style={textStyles.muted}>
            {session?.user_id ?? "Cached session"} · {session?.tenant_id ?? "offline"}
          </Text>
        </Card>
        <Card>
          <View style={styles.row}>
            <View style={styles.grow}>
              <Text style={textStyles.heading}>Auto-approve tools</Text>
              <Text style={textStyles.muted}>
                Allow tools without asking each time. Use only on trusted deployments.
              </Text>
            </View>
            <Switch
              value={autoApprove}
              onValueChange={(value) => void updateAutoApprove(value)}
              trackColor={{ false: colors.border, true: colors.primaryPressed }}
            />
          </View>
        </Card>
        <Card>
          <Text style={textStyles.heading}>Tools</Text>
          {tools.length ? tools.map((tool, index) => (
            <View key={tool.key ?? tool.name ?? index} style={styles.tool}>
              <Text style={textStyles.body}>{tool.name ?? tool.key ?? "Tool setting"}</Text>
              <Text style={textStyles.muted}>
                {typeof tool.state === "string" ? tool.state : JSON.stringify(tool.value)}
              </Text>
            </View>
          )) : <Text style={textStyles.muted}>No tool settings reported.</Text>}
        </Card>
        {error ? <Text style={textStyles.error}>{error}</Text> : null}
        <Button title="Refresh settings" tone="secondary" onPress={() => void refresh()} />
        <Button title="Sign out" tone="danger" onPress={() => void signOut()} />
      </ScrollView>
    </Screen>
  );
}

const styles = StyleSheet.create({
  flush: { padding: 0 },
  content: { padding: 16, gap: 12 },
  row: { flexDirection: "row", alignItems: "center", gap: 12 },
  grow: { flex: 1 },
  tool: { borderTopColor: colors.border, borderTopWidth: 1, paddingTop: 10, gap: 2 }
});
