import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { colors } from "@/theme";

type Segment = { text: string; kind?: "bold" | "code" | "link" };

function inlineSegments(value: string): Segment[] {
  const segments: Segment[] = [];
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^\)]+\))/g;
  let cursor = 0;
  for (const match of value.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (index > cursor) segments.push({ text: value.slice(cursor, index) });
    const token = match[0];
    if (token.startsWith("`")) segments.push({ text: token.slice(1, -1), kind: "code" });
    else if (token.startsWith("**")) segments.push({ text: token.slice(2, -2), kind: "bold" });
    else segments.push({ text: token.slice(1, token.indexOf("](")), kind: "link" });
    cursor = index + token.length;
  }
  if (cursor < value.length) segments.push({ text: value.slice(cursor) });
  return segments;
}

function InlineText({ value }: { value: string }) {
  return (
    <Text style={styles.paragraph}>
      {inlineSegments(value).map((segment, index) => (
        <Text
          key={`${segment.text}-${index}`}
          style={segment.kind === "bold" ? styles.bold : segment.kind === "code" ? styles.inlineCode : segment.kind === "link" ? styles.link : undefined}
        >
          {segment.text}
        </Text>
      ))}
    </Text>
  );
}

export function Markdown({ content }: { content: string }) {
  const lines = content.replace(/\r\n?/g, "\n").split("\n");
  const blocks: React.ReactNode[] = [];
  let code: string[] = [];
  let language = "";
  const flushCode = () => {
    if (!code.length) return;
    blocks.push(
      <View key={`code-${blocks.length}`} style={styles.codeBlock}>
        {language ? <Text style={styles.language}>{language}</Text> : null}
        <Text selectable style={styles.code}>{code.join("\n")}</Text>
      </View>
    );
    code = [];
    language = "";
  };

  lines.forEach((line, index) => {
    if (line.trimStart().startsWith("```")) {
      if (code.length) flushCode();
      else language = line.trim().slice(3).trim();
      return;
    }
    if (code.length || (index > 0 && lines[index - 1]?.trimStart().startsWith("```"))) {
      code.push(line);
      return;
    }
    if (!line.trim()) return;
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      const headingLevel = heading[1] ?? "#";
      blocks.push(<Text key={`heading-${index}`} style={headingLevel.length === 1 ? styles.h1 : styles.h2}>{heading[2] ?? ""}</Text>);
      return;
    }
    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet) {
      blocks.push(<View key={`bullet-${index}`} style={styles.bullet}><Text style={styles.bulletMark}>•</Text><InlineText value={bullet[1] ?? ""} /></View>);
      return;
    }
    blocks.push(<InlineText key={`line-${index}`} value={line} />);
  });
  flushCode();
  return <View style={styles.markdown}>{blocks}</View>;
}

export function CollapsibleAction({
  name,
  status,
  detail,
  parameters,
  result,
  error
}: {
  name: string;
  status: string;
  detail?: string;
  parameters?: string;
  result?: string;
  error?: string;
}) {
  const [expanded, setExpanded] = React.useState(status === "error" || status === "declined");
  const failed = status === "error" || status === "declined";
  const label = status === "running" ? "Working" : status === "success" ? "Done" : status === "declined" ? "Declined" : status === "error" ? "Failed" : status;
  return (
    <View style={styles.action}>
      <Pressable accessibilityRole="button" onPress={() => setExpanded((value) => !value)} style={styles.actionHeader}>
        <View style={[styles.dot, { backgroundColor: failed ? colors.danger : status === "success" ? colors.success : colors.primary }]} />
        <Text style={styles.actionStatus}>{label}</Text>
        <Text numberOfLines={1} style={styles.actionName}>{name}</Text>
        <Text style={styles.chevron}>{expanded ? "⌃" : "⌄"}</Text>
      </Pressable>
      {expanded ? (
        <View style={styles.actionBody}>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          {detail ? <Text style={styles.detail}>{detail}</Text> : null}
          {parameters ? <Text selectable style={styles.payload}>{parameters}</Text> : null}
          {result ? <Text selectable style={styles.payload}>{result}</Text> : null}
          {!error && !detail && !parameters && !result ? <Text style={styles.detail}>No additional details</Text> : null}
        </View>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  markdown: { gap: 8, width: "100%" },
  paragraph: { color: colors.body, fontSize: 16, lineHeight: 25 },
  bold: { color: colors.text, fontWeight: "700" },
  inlineCode: { color: colors.primaryText, backgroundColor: colors.surfaceRaised, fontFamily: "Menlo" },
  link: { color: colors.primaryText, textDecorationLine: "underline" },
  h1: { color: colors.text, fontSize: 24, lineHeight: 31, fontWeight: "700" },
  h2: { color: colors.text, fontSize: 19, lineHeight: 26, fontWeight: "700" },
  bullet: { flexDirection: "row", gap: 8, alignItems: "flex-start" },
  bulletMark: { color: colors.primaryText, fontSize: 20, lineHeight: 23 },
  codeBlock: { backgroundColor: colors.backgroundStrong, borderColor: colors.border, borderWidth: 1, borderRadius: 10, padding: 12, gap: 6 },
  language: { color: colors.faint, fontSize: 11, textTransform: "uppercase", fontFamily: "Menlo" },
  code: { color: colors.body, fontSize: 13, lineHeight: 19, fontFamily: "Menlo" },
  action: { borderBottomColor: colors.border, borderBottomWidth: 1, width: "100%" },
  actionHeader: { minHeight: 42, flexDirection: "row", alignItems: "center", gap: 9, paddingHorizontal: 4 },
  dot: { width: 8, height: 8, borderRadius: 4 },
  actionStatus: { color: colors.muted, fontFamily: "Menlo", fontSize: 11, textTransform: "uppercase" },
  actionName: { color: colors.body, flex: 1, fontFamily: "Menlo", fontSize: 13 },
  chevron: { color: colors.muted, fontSize: 17 },
  actionBody: { backgroundColor: colors.backgroundStrong, borderColor: colors.border, borderLeftWidth: 1, borderRightWidth: 1, borderTopWidth: 1, borderTopLeftRadius: 8, borderTopRightRadius: 8, padding: 12, gap: 8 },
  detail: { color: colors.body, fontSize: 13, lineHeight: 19 },
  payload: { color: colors.body, fontFamily: "Menlo", fontSize: 12, lineHeight: 18 },
  error: { color: colors.danger, fontSize: 13, lineHeight: 19 }
});
