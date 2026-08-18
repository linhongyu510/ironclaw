// The recording engine — loaded on demand, never on the initial /chat route.
//
// `useVoiceInput` pulls this module in with a dynamic `import()` the first time
// someone presses the microphone. Everything here is reachable only after that
// click: container selection, the `MediaRecorder` lifecycle, the WAV
// re-encode, and the upload. Keeping it out of the eager composer closure is what lets a
// session that never dictates pay nothing for the feature
// (`scripts/check-bundle-budgets.ts`).
//
// The engine owns no React state. It reports progress and outcome through
// callbacks, so the hook stays a thin state wrapper that is safe to call
// unconditionally (hook rules) while the weight lives here.

import { transcribeAudio } from "../../../lib/api";

/**
 * Containers we ask `MediaRecorder` for, best first.
 *
 * This is a *recording* preference, not an upload contract: whatever the
 * browser records is decoded and re-encoded to WAV before it is sent (see
 * `voice-encode.ts`), because the transcription endpoint decodes neither of
 * the two containers browsers actually produce. So the only thing that matters
 * here is that the browser can record it and can decode it back.
 */
const RECORDER_CONTAINERS = [
  "audio/webm;codecs=opus",
  "audio/webm",
  "audio/ogg;codecs=opus",
  "audio/ogg",
  "audio/mp4",
];

/**
 * Pick the first container this browser can actually record.
 *
 * Chrome and Firefox land on `audio/webm`, Safari on `audio/mp4`; asking
 * `MediaRecorder` means neither browser needs a branch. Returns `""` when
 * nothing matches, which the caller treats as "voice unavailable".
 *
 * `isTypeSupported` is missing on some older implementations; there, we fall
 * back to the first candidate and let the recorder's own constructor reject it
 * (surfaced as a recording error, not a silent bad upload).
 */
export function pickRecorderMimeType(
  candidates = RECORDER_CONTAINERS,
  recorder = globalThis.MediaRecorder,
) {
  const usable = (candidates || []).filter(
    (token) => typeof token === "string" && token.includes("/"),
  );
  if (usable.length === 0) return "";
  if (typeof recorder?.isTypeSupported !== "function") {
    return usable[0];
  }
  for (const candidate of usable) {
    if (recorder.isTypeSupported(candidate)) return candidate;
  }
  return "";
}

/**
 * Read a recorded Blob to base64 (no `data:` prefix).
 *
 * Rejects when the reader yields a non-string result, so a broken read
 * surfaces as a retryable recording error instead of an empty upload the
 * server then rejects as blank.
 */
export function blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result !== "string") {
        reject(new Error("voice clip read produced no data URL"));
        return;
      }
      const comma = reader.result.indexOf(",");
      if (comma < 0) {
        reject(new Error("voice clip read produced no base64 payload"));
        return;
      }
      resolve(reader.result.slice(comma + 1));
    };
    reader.onerror = () => reject(reader.error || new Error("voice clip read failed"));
    reader.readAsDataURL(blob);
  });
}


// ---------------------------------------------------------------------------
// Re-encoding
//
// `MediaRecorder` writes `audio/webm` (Chrome/Firefox) or `audio/mp4` (Safari)
// and the transcription endpoint decodes neither — measured 2026-08-17 against
// NEAR AI's `/v1/audio/transcriptions`, which takes wav/ogg/mp3/flac and
// answers HTTP 400 "supported format" for webm and mp4. No container both
// browsers record is accepted, so the clip is converted here.
//
// This is cheap because the browser already owns a decoder for the container
// it just wrote: `decodeAudioData` handles webm/opus and mp4/aac natively. All
// we add is a downmix, a resample, and a WAV header. 16 kHz mono is not a
// quality compromise for speech — it is the rate Whisper models work at.
// ---------------------------------------------------------------------------

/** Sample rate every clip is resampled to. Whisper's own working rate. */
export const TARGET_SAMPLE_RATE = 16000;

/**
 * Downmix an AudioBuffer's channels to a single mono track.
 *
 * Averaging (rather than taking channel 0) keeps a speaker who happens to sit
 * on one side of a stereo capture from being halved in level.
 */
export function downmixToMono(channels, length) {
  if (channels.length === 1) return channels[0];
  const mono = new Float32Array(length);
  for (let i = 0; i < length; i += 1) {
    let sum = 0;
    for (let c = 0; c < channels.length; c += 1) sum += channels[c][i] || 0;
    mono[i] = sum / channels.length;
  }
  return mono;
}

/**
 * Linear-interpolation resample to `targetRate`.
 *
 * Deliberately not an `OfflineAudioContext` render: Safari restricted
 * OfflineAudioContext to a few sample rates for years, and silently getting a
 * 44.1 kHz buffer back when you asked for 16 kHz would ship a subtly wrong
 * upload. Linear interpolation is more than adequate for speech headed to a
 * transcription model, and it behaves identically everywhere.
 */
export function resampleTo(samples, sourceRate, targetRate = TARGET_SAMPLE_RATE) {
  if (!(sourceRate > 0) || sourceRate === targetRate) return samples;
  const ratio = sourceRate / targetRate;
  const outLength = Math.max(1, Math.floor(samples.length / ratio));
  const out = new Float32Array(outLength);
  for (let i = 0; i < outLength; i += 1) {
    const position = i * ratio;
    const left = Math.floor(position);
    const right = Math.min(left + 1, samples.length - 1);
    const weight = position - left;
    out[i] = samples[left] * (1 - weight) + samples[right] * weight;
  }
  return out;
}

/**
 * Write mono float samples as a 16-bit PCM WAV file.
 *
 * Standard 44-byte canonical header; samples are clamped before scaling so a
 * decoder that hands back values slightly outside [-1, 1] cannot wrap around
 * into loud noise.
 */
export function encodeWav(samples, sampleRate = TARGET_SAMPLE_RATE) {
  const bytesPerSample = 2;
  const buffer = new ArrayBuffer(44 + samples.length * bytesPerSample);
  const view = new DataView(buffer);

  const writeAscii = (offset, text) => {
    for (let i = 0; i < text.length; i += 1) view.setUint8(offset + i, text.charCodeAt(i));
  };

  const dataBytes = samples.length * bytesPerSample;
  writeAscii(0, "RIFF");
  view.setUint32(4, 36 + dataBytes, true);
  writeAscii(8, "WAVE");
  writeAscii(12, "fmt ");
  view.setUint32(16, 16, true); // PCM chunk size
  view.setUint16(20, 1, true); // format: PCM
  view.setUint16(22, 1, true); // channels: mono
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * bytesPerSample, true); // byte rate
  view.setUint16(32, bytesPerSample, true); // block align
  view.setUint16(34, 16, true); // bits per sample
  writeAscii(36, "data");
  view.setUint32(40, dataBytes, true);

  let offset = 44;
  for (let i = 0; i < samples.length; i += 1) {
    const clamped = Math.max(-1, Math.min(1, samples[i]));
    // Asymmetric scaling matches the 16-bit range: -32768..32767.
    view.setInt16(offset, clamped < 0 ? clamped * 0x8000 : clamped * 0x7fff, true);
    offset += 2;
  }
  return new Blob([buffer], { type: "audio/wav" });
}

/**
 * Decode a recorded clip and re-encode it as 16 kHz mono WAV.
 *
 * Throws if the browser cannot decode its own recording, which the caller
 * surfaces as a retryable recording error rather than uploading something the
 * endpoint would reject anyway.
 */
export async function clipToWav(blob) {
  const AudioContextCtor = globalThis.AudioContext || globalThis.webkitAudioContext;
  if (typeof AudioContextCtor !== "function") {
    throw new Error("this browser cannot decode recorded audio");
  }
  const context = new AudioContextCtor();
  try {
    const arrayBuffer = await blob.arrayBuffer();
    // Promise form; Safari also supports it (the callback form is only needed
    // for very old WebKit, which fails the capability probe already).
    const decoded = await context.decodeAudioData(arrayBuffer);
    const channels = [];
    for (let c = 0; c < decoded.numberOfChannels; c += 1) {
      channels.push(decoded.getChannelData(c));
    }
    const mono = downmixToMono(channels, decoded.length);
    const resampled = resampleTo(mono, decoded.sampleRate, TARGET_SAMPLE_RATE);
    return encodeWav(resampled, TARGET_SAMPLE_RATE);
  } finally {
    // Release the hardware context; leaking one per recording eventually trips
    // the browser's per-page AudioContext cap.
    if (typeof context.close === "function") await context.close().catch(() => {});
  }
}

/**
 * Start recording, and drive the whole clip through to a transcript.
 *
 * Returns a handle with `stop()` (transcribe what was captured) and `cancel()`
 * (discard without uploading). Every exit path — success, cancel, error,
 * caller teardown — releases the microphone tracks, because browsers keep the
 * tab's recording indicator lit until each track is stopped.
 *
 * Outcomes are reported through `onSettled` as a tagged result rather than
 * thrown, so the caller has one place to handle them:
 *   { ok: true, text }              — transcript ready
 *   { ok: false, reason, detail? }  — a named failure the UI maps to a message
 *
 * `onTick(seconds)` fires once a second while recording; the engine stops
 * itself at `maxDurationSecs` and still transcribes what it captured, so a
 * user who talks too long gets their words rather than an error.
 */
export async function startVoiceRecording({
  limits,
  onTick,
  onTranscribing,
  onSettled,
}) {
  const mimeType = pickRecorderMimeType();
  if (!mimeType) {
    onSettled({ ok: false, reason: "unsupported" });
    return null;
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (error) {
    // A denied permission and a missing device both land here; the browser
    // distinguishes them by `name`, and only the denial is actionable.
    onSettled({
      ok: false,
      reason: error?.name === "NotAllowedError" ? "permissionDenied" : "noMicrophone",
    });
    return null;
  }

  let recorder;
  try {
    recorder = new MediaRecorder(stream, { mimeType });
  } catch {
    for (const track of stream.getTracks()) track.stop();
    onSettled({ ok: false, reason: "unsupported" });
    return null;
  }

  let chunks = [];
  let cancelled = false;
  let timer = null;

  const release = () => {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    for (const track of stream.getTracks()) track.stop();
  };

  recorder.ondataavailable = (event) => {
    if (event.data && event.data.size > 0) chunks.push(event.data);
  };

  recorder.onstop = async () => {
    const captured = chunks;
    chunks = [];
    release();
    if (cancelled) {
      onSettled({ ok: false, reason: "cancelled" });
      return;
    }

    const blob = new Blob(captured, { type: mimeType });
    if (blob.size === 0) {
      onSettled({ ok: false, reason: "empty" });
      return;
    }
    // The recorded blob is compressed; the WAV that actually gets uploaded is
    // larger, so the meaningful ceiling check happens after encoding below.
    // This one only catches an absurdly long capture before we spend the
    // decode on it.

    onTranscribing();
    try {
      // Always upload WAV, whatever was recorded: the endpoint decodes
      // wav/ogg/mp3/flac and rejects the webm and mp4 the browsers produce.
      // Converting here (rather than sending the raw container and hoping)
      // is what makes Chrome and Safari behave identically.
      let wav;
      try {
        wav = await clipToWav(blob);
      } catch {
        // The browser could not decode its own recording. Distinct from a
        // service failure: retrying the same way will not help.
        onSettled({ ok: false, reason: "encodeFailed" });
        return;
      }
      if (wav.size > limits.maxBytes) {
        onSettled({ ok: false, reason: "tooLarge" });
        return;
      }
      const audioBase64 = await blobToBase64(wav);
      const response = await transcribeAudio({
        mimeType: "audio/wav",
        audioBase64,
      });
      const text = typeof response?.text === "string" ? response.text.trim() : "";
      onSettled(text ? { ok: true, text } : { ok: false, reason: "noSpeech" });
    } catch (error) {
      // A 400 means the service looked at this clip and refused it — that is a
      // property of the recording, not something the user can fix by reading a
      // field name, so it gets its own message. Everything else (5xx, offline,
      // rate limit) keeps the server's own redacted reason, because those ARE
      // actionable and swallowing them is the mistake this feature was
      // explicitly told not to repeat.
      if (error?.status === 400) {
        onSettled({ ok: false, reason: "rejected" });
        return;
      }
      onSettled({ ok: false, reason: "failed", detail: error?.message || "" });
    }
  };

  recorder.start();
  const startedAt = Date.now();
  timer = setInterval(() => {
    const seconds = Math.floor((Date.now() - startedAt) / 1000);
    onTick(seconds);
    if (seconds >= limits.maxDurationSecs && recorder.state !== "inactive") {
      recorder.stop();
    }
  }, 1000);

  return {
    stop() {
      if (recorder.state === "inactive") return;
      cancelled = false;
      recorder.stop();
    },
    cancel() {
      if (recorder.state === "inactive") {
        release();
        onSettled({ ok: false, reason: "cancelled" });
        return;
      }
      cancelled = true;
      recorder.stop();
    },
  };
}
