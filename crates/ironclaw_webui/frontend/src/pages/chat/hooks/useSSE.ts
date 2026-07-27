import React from "react";
import { clientActionId, openEventStream } from "../../../lib/api";
import {
  CONNECTION_STATUS,
  type ConnectionStatus,
} from "../lib/connection-status";

// v2 SSE emits `WebChatV2EventFrame` JSON, tagged with a typed
// event name (`event: accepted`, `event: final_reply`, etc.) so
// each frame routes to its `addEventListener("<name>", …)` handler.
// `onmessage` would only catch frames without an `event:` field,
// which the Rust handler never emits — so the SPA must register a
// listener for every event name it cares about. The names below
// mirror `WebChatV2Event::event_name()` in
// `crates/ironclaw_webui/src/webui_v2/schema.rs`.
const V2_EVENT_NAMES = [
  "accepted",
  "running",
  "capability_progress",
  "capability_activity",
  "capability_display_preview",
  "gate",
  "auth_required",
  "final_reply",
  "cancelled",
  "failed",
  "projection_snapshot",
  "projection_update",
  "keep_alive",
  "stream_error",
];

const EVENT_SOURCE_OPEN = 1;
const SSE_CONNECTION_STORAGE_KEY = "ironclaw:v2-sse-connection";

type SseConnectionState = {
  connectionId: string;
  generation: number;
};

function newConnectionState(): SseConnectionState {
  return { connectionId: clientActionId(), generation: 0 };
}

function isDocumentReload(): boolean {
  try {
    const navigation =
      globalThis.performance?.getEntriesByType?.("navigation")[0];
    return Boolean(
      navigation &&
        "type" in navigation &&
        navigation.type === "reload",
    );
  } catch (_) {
    return false;
  }
}

function loadConnectionState(): SseConnectionState {
  // sessionStorage can be copied into a newly opened or duplicated tab. Only
  // an actual reload may reuse the predecessor document's stream identity;
  // every fresh top-level navigation must get an independent server slot.
  if (!isDocumentReload()) return newConnectionState();
  try {
    const raw = globalThis.sessionStorage?.getItem(SSE_CONNECTION_STORAGE_KEY);
    if (!raw) return newConnectionState();
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return newConnectionState();
    const candidate = parsed as Record<string, unknown>;
    const connectionId = candidate.connectionId;
    const generation = candidate.generation;
    const validConnectionId =
      typeof connectionId === "string" &&
      /^[A-Za-z0-9_-]{1,64}$/.test(connectionId);
    const validGeneration =
      typeof generation === "number" &&
      Number.isSafeInteger(generation) &&
      generation >= 0;
    if (validConnectionId && validGeneration) {
      return { connectionId, generation };
    }
  } catch (_) {
    // Storage may be unavailable or contain stale data. A fresh identity still
    // gives this document a usable stream; the server's max lifetime bounds
    // any proxy-held stream that cannot be superseded.
  }
  return newConnectionState();
}

// Persisting both values lets a reloaded document supersede the proxy-held
// stream from its predecessor without allowing an older generation to cancel
// the replacement. Fresh documents intentionally ignore copied storage above.
const sseConnectionState = loadConnectionState();

function nextConnectionState(): SseConnectionState {
  if (sseConnectionState.generation >= Number.MAX_SAFE_INTEGER) {
    sseConnectionState.connectionId = clientActionId();
    sseConnectionState.generation = 0;
  }
  sseConnectionState.generation += 1;
  try {
    globalThis.sessionStorage?.setItem(
      SSE_CONNECTION_STORAGE_KEY,
      JSON.stringify(sseConnectionState),
    );
  } catch (_) {
    // Best effort. The in-memory identity still covers SPA route switches.
  }
  return { ...sseConnectionState };
}

function eventSourceReadyStateConstant(staticValue: unknown, fallback: number) {
  return typeof staticValue === "number" ? staticValue : fallback;
}

function isEventSourceOpen(source) {
  const openState = typeof EventSource === "function"
    ? eventSourceReadyStateConstant(EventSource.OPEN, EVENT_SOURCE_OPEN)
    : EVENT_SOURCE_OPEN;
  return source?.readyState === openState;
}

function isBrowserOffline() {
  return typeof navigator !== "undefined" && navigator.onLine === false;
}

export function useSSE({ threadId, onEvent, enabled }) {
  const [status, setStatus] = React.useState<ConnectionStatus>(
    CONNECTION_STATUS.IDLE,
  );
  const onEventRef = React.useRef(onEvent);
  onEventRef.current = onEvent;
  React.useEffect(() => {
    if (!enabled || !threadId) {
      setStatus(CONNECTION_STATUS.IDLE);
      return;
    }
    let es = null;
    let reconnectTimer = null;
    let openWatchdog = null;
    let reconnectAttempts = 0;
    let disposed = false;
    let terminalErrorReceived = false;
    let readySource = null;
    // This cursor belongs to this mounted route only. A route remount must
    // hydrate current state from the projection origin because the composite
    // cursor contains a process-local live rail. Controlled retries within this
    // effect resume from the latest frame observed here.
    let lastEventId = null;
    const maxReconnectDelay = 30_000;
    const reconnectOpenDeadline = 10_000;

    function clearOpenWatchdog() {
      if (openWatchdog) {
        clearTimeout(openWatchdog);
        openWatchdog = null;
      }
    }

    function markConnected(source) {
      if (disposed || terminalErrorReceived || es !== source) return;
      clearOpenWatchdog();
      readySource = source;
      reconnectAttempts = 0;
      setStatus(CONNECTION_STATUS.CONNECTED);
    }

    function scheduleOpenWatchdog(source) {
      if (openWatchdog) return;
      openWatchdog = setTimeout(() => {
        openWatchdog = null;
        if (disposed || terminalErrorReceived || es !== source) return;
        reconnectWithTimer(CONNECTION_STATUS.RECONNECTING);
      }, reconnectOpenDeadline);
    }

    function reconnectWithTimer(
      status: ConnectionStatus = CONNECTION_STATUS.DISCONNECTED,
    ) {
      if (disposed || terminalErrorReceived) return;
      if (es) {
        readySource = null;
        es.close();
        es = null;
      }
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      clearOpenWatchdog();
      setStatus(status);
      reconnectAttempts++;
      const delay = Math.min(1000 * 2 ** reconnectAttempts, maxReconnectDelay);
      reconnectTimer = setTimeout(connect, delay);
    }

    function connect() {
      reconnectTimer = null;
      if (disposed || terminalErrorReceived) return;
      if (document.visibilityState === "hidden") {
        setStatus(CONNECTION_STATUS.PAUSED);
        return;
      }
      setStatus(
        isBrowserOffline() || reconnectAttempts > 0
          ? CONNECTION_STATUS.RECONNECTING
          : CONNECTION_STATUS.CONNECTING,
      );

      const connectionState = nextConnectionState();
      es = openEventStream({
        threadId,
        afterCursor: lastEventId || undefined,
        connectionId: connectionState.connectionId,
        connectionGeneration: connectionState.generation,
      });
      const source = es;

      // A replacement EventSource can remain in CONNECTING forever without
      // firing either callback when a proxy accepts the HTTP request but does
      // not establish the event stream. Bound every recovery attempt
      // explicitly; the initial attempt still reports its native failure
      // through `onerror`.
      if (reconnectAttempts > 0) scheduleOpenWatchdog(source);

      source.onopen = () => {
        // HTTP headers alone do not prove the server-side subscription is
        // usable. A proxy can open the response and immediately EOF before the
        // server's ready frame. Keep the watchdog and retry streak until a
        // valid application frame reaches dispatchFrame().
        scheduleOpenWatchdog(source);
      };

      const dispatchFrame = (event, fallbackType) => {
        if (disposed || es !== source) return;
        let frame = null;
        try {
          frame = JSON.parse(event.data);
        } catch (_) {
          return;
        }
        if (!frame || typeof frame !== "object") return;
        if (event.lastEventId) {
          lastEventId = event.lastEventId;
        }
        const rawType = frame.type || fallbackType;
        const type = rawType === "stream_error" ? "error" : rawType;
        // Any valid non-error application frame proves the active replacement
        // transport is live and must clear a stale reconnecting badge, even if
        // its `open` callback was delayed. Classified stream errors keep their
        // own terminal/retry state below.
        if (type !== "error") markConnected(source);
        onEventRef.current?.({
          // The frame's own `type` field is the canonical source;
          // `event.type` (from the SSE `event:` line) is the
          // fallback for forwards-compatibility if Rust adds an
          // event without setting `type` in the body.
          type,
          frame,
          lastEventId: event.lastEventId || null,
        });
        // The server has already classified this failure as permanent for
        // this subscription (for example, a thread that no longer exists).
        // EventSource reports the subsequent clean server close through
        // `onerror`; remember the terminal frame and close locally so that
        // callback cannot turn a non-retryable response into an infinite
        // reconnect loop.
        if (type === "error" && frame.retryable === false && es === source) {
          terminalErrorReceived = true;
          if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
          }
          readySource = null;
          es = null;
          source.close();
          setStatus(CONNECTION_STATUS.DISCONNECTED);
          return;
        }
        // A replay-unavailable response means retrying the same cursor can
        // never make progress. Replace this EventSource so the browser drops
        // its internal Last-Event-ID, and reconnect from the projection origin
        // where durable run/final-reply state can be rebuilt.
        if (
          type === "error" &&
          frame.kind === "replay_unavailable" &&
          frame.retryable === true &&
          es === source
        ) {
          lastEventId = null;
          reconnectWithTimer(CONNECTION_STATUS.RECONNECTING);
        }
      };

      source.onerror = (event) => {
        if (disposed || terminalErrorReceived || es !== source) return;
        // Compatibility with servers that emitted application failures on
        // the reserved `event: error` channel. Those arrive as MessageEvents
        // with data; a native EventSource transport failure has no data.
        // Parsing the former here prevents one browser event from also
        // entering the transport reconnect state machine.
        if (typeof event?.data === "string") {
          dispatchFrame(event, "error");
          return;
        }
        // Native EventSource retries reuse the original URL and therefore the
        // same connection generation. A proxy can deliver one of those retries
        // late, allowing equal-generation requests to supersede each other and
        // repeatedly end as short 200 responses. Close the native retry state
        // machine and schedule exactly one app-owned replacement; `connect()`
        // gives it a newer generation that stale requests cannot cancel.
        reconnectWithTimer(CONNECTION_STATUS.RECONNECTING);
      };

      // Cover anything emitted without an `event:` field — defensive
      // only; the Rust handler always tags its frames today.
      es.onmessage = (event) => dispatchFrame(event, "message");

      // The Rust handler tags each frame with `event: <name>` so the
      // browser routes it through the named listener below.
      for (const name of V2_EVENT_NAMES) {
        es.addEventListener(name, (event) => dispatchFrame(event, name));
      }
    }

    function disconnectForHiddenTab() {
      if (disposed || terminalErrorReceived) return;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      clearOpenWatchdog();
      if (es) {
        readySource = null;
        es.close();
        es = null;
      }
      setStatus(CONNECTION_STATUS.PAUSED);
    }

    function handleVisibilityChange() {
      if (disposed || terminalErrorReceived) return;
      if (document.visibilityState === "hidden") {
        disconnectForHiddenTab();
      } else if (!es) {
        connect();
      }
    }

    function handleNetworkOffline() {
      if (disposed || terminalErrorReceived) return;
      setStatus(CONNECTION_STATUS.RECONNECTING);
    }

    function handleNetworkOnline() {
      if (disposed || terminalErrorReceived) return;
      if (es && readySource === es && isEventSourceOpen(es)) {
        setStatus(CONNECTION_STATUS.CONNECTED);
        return;
      }
      setStatus(CONNECTION_STATUS.RECONNECTING);
      if (es) {
        scheduleOpenWatchdog(es);
        return;
      }
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      connect();
    }

    connect();
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("offline", handleNetworkOffline);
    window.addEventListener("online", handleNetworkOnline);

    return () => {
      disposed = true;
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("offline", handleNetworkOffline);
      window.removeEventListener("online", handleNetworkOnline);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearOpenWatchdog();
      const source = es;
      readySource = null;
      es = null;
      source?.close();
    };
  }, [enabled, threadId]);

  return { status };
}
