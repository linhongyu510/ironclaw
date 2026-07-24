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
  const [updatingTool, setUpdatingTool] = React.useState("");
  const [checking, setChecking] = React.useState(false);
  const [checkedAt, setCheckedAt] = React.useState("");

  const refresh = React.useCallback(async () => {
    try {
      const entries = await api.toolSettings();
      setTools(entries);
      const global = entries.find((entry) => entry.key === "agent.auto_approve_tools");
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

  async function updateTool(
    tool: ToolSetting,
    state: "ask" | "always_allow" | "always_deny"
  ) {
    const capabilityId = tool.key?.startsWith("tool.") ? tool.key.slice(5) : "";
    if (!capabilityId) return;
    setUpdatingTool(capabilityId);
    try {
      await api.setToolPermission(capabilityId, state);
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update tool permission");
    } finally {
      setUpdatingTool("");
    }
  }

  async function checkConnection() {
    setChecking(true);
    try {
      await api.session();
      setCheckedAt(new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Connection check failed");
    } finally {
      setChecking(false);
    }
  }

  const capabilityTools = tools.filter((tool) => tool.key?.startsWith("tool."));

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
          <Button title={checking ? "Checking…" : "Test connection"} tone="secondary" onPress={() => void checkConnection()} disabled={checking} />
          {checkedAt ? <Text style={textStyles.muted}>Connected at {checkedAt}</Text> : null}
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
          {capabilityTools.length ? capabilityTools.map((tool, index) => {
            const value = tool.value && typeof tool.value === "object"
              ? (tool.value as { state?: string }).state
              : tool.state;
            const capabilityId = tool.key?.slice(5) ?? "";
            return (
            <View key={tool.key ?? tool.name ?? index} style={styles.tool}>
              <Text style={textStyles.body}>{tool.name ?? tool.key ?? "Tool setting"}</Text>
              <Text style={textStyles.muted}>{value ?? "ask"}</Text>
              <View style={styles.permissions}>
                {([
                  ["Ask", "ask"],
                  ["Allow", "always_allow"],
                  ["Deny", "always_deny"]
                ] as const).map(([label, state]) => (
                  <View key={state} style={styles.grow}>
                    <Button
                      title={updatingTool === capabilityId ? "Saving…" : label}
                      tone={value === state ? "primary" : state === "always_deny" ? "danger" : "secondary"}
                      disabled={Boolean(updatingTool)}
                      onPress={() => void updateTool(tool, state)}
                    />
                  </View>
                ))}
              </View>
            </View>
            );
          }) : <Text style={textStyles.muted}>No tool permissions reported.</Text>}
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
  tool: { borderTopColor: colors.border, borderTopWidth: 1, paddingTop: 10, gap: 8 },
  permissions: { flexDirection: "row", gap: 6 }
});
