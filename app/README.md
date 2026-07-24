# IronClaw Mobile

Expo/React Native companion app for IronClaw.

## Run

```bash
cd app
npm install
npm run start
```

Use a development build for native SQLCipher:

```bash
npx expo prebuild
npm run ios
# or
npm run android
```

Development builds connect to `https://agent-stg.near.ai`. Set
`IRONCLAW_APP_ENV=production` when producing a production build for
`https://agent.near.ai`.

Hosted OAuth requires the backend to allow the app callback URL and return its
existing single-use `login_ticket`. Until that is deployed, use **Pair a
dedicated deployment** with a scoped bearer to connect to any compatible
WebChat v2 backend.
