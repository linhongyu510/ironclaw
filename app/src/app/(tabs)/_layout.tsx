import { Ionicons } from "@expo/vector-icons";
import { Redirect, Tabs } from "expo-router";
import { useSession } from "@/auth/session-context";
import { colors } from "@/theme";

export default function TabsLayout() {
  const { token } = useSession();
  if (!token) return <Redirect href="/login" />;
  return (
    <Tabs
      screenOptions={{
        headerStyle: { backgroundColor: colors.surface },
        headerTintColor: colors.text,
        tabBarStyle: { backgroundColor: colors.surface, borderTopColor: colors.border },
        tabBarActiveTintColor: colors.primary,
        tabBarInactiveTintColor: colors.muted
      }}
    >
      <Tabs.Screen
        name="threads"
        options={{
          title: "Threads",
          tabBarIcon: ({ color, size }) => <Ionicons name="chatbubbles" color={color} size={size} />
        }}
      />
      <Tabs.Screen
        name="automations"
        options={{
          title: "Automations",
          tabBarIcon: ({ color, size }) => <Ionicons name="timer" color={color} size={size} />
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: "Settings",
          tabBarIcon: ({ color, size }) => <Ionicons name="settings" color={color} size={size} />
        }}
      />
    </Tabs>
  );
}
