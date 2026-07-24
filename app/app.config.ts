import type { ExpoConfig } from "expo/config";

const buildProfile = process.env.IRONCLAW_APP_ENV ?? "development";
const production = buildProfile === "production";

const config: ExpoConfig = {
  name: production ? "IronClaw" : `IronClaw ${buildProfile}`,
  slug: "ironclaw",
  scheme: production ? "ironclaw" : `ironclaw-${buildProfile}`,
  version: "0.1.0",
  orientation: "portrait",
  userInterfaceStyle: "automatic",
  newArchEnabled: true,
  ios: {
    bundleIdentifier: production ? "ai.near.ironclaw" : `ai.near.ironclaw.${buildProfile}`,
    deploymentTarget: "16.4",
    supportsTablet: true
  },
  android: {
    package: production ? "ai.near.ironclaw" : `ai.near.ironclaw.${buildProfile}`,
    minSdkVersion: 33,
    compileSdkVersion: 36,
    targetSdkVersion: 36,
    adaptiveIcon: {
      backgroundColor: "#0b1020"
    }
  },
  web: {
    bundler: "metro"
  },
  plugins: [
    "expo-router",
    [
      "expo-secure-store",
      {
        configureAndroidBackup: true,
        faceIDPermission: "Allow IronClaw to unlock your agent session."
      }
    ],
    [
      "expo-sqlite",
      {
        useSQLCipher: true
      }
    ]
  ],
  experiments: {
    typedRoutes: true
  },
  extra: {
    buildProfile,
    hostedOrigin: production ? "https://agent.near.ai" : "https://agent-stg.near.ai"
  }
};

export default config;
