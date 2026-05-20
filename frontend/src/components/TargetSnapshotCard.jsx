import { Descriptions, Grid, Tag, Typography } from "antd";

import { AppCard } from "./ui";

const { Text } = Typography;

function TruncatedCode({ value, fallback }) {
  const text = value?.trim() || fallback;

  return (
    <Text
      code
      title={text}
      style={{
        display: "block",
        maxWidth: "100%",
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}
    >
      {text}
    </Text>
  );
}

export function TargetSnapshotCard({
  selectedWorkspace,
  customPath,
  workspacePath,
  analysisMode,
  dynamicMode,
  dynamicToolPreference,
  dynamicBinaryPath,
}) {
  const screens = Grid.useBreakpoint();
  const workspaceLabel =
    selectedWorkspace?.name || customPath.trim() || "Not selected";
  const mountedPath = customPath.trim() || workspacePath || "n/a";

  return (
    <AppCard
      title="Summary"
      extra={<Tag color="processing">Ready</Tag>}
      bodyGap={8}
    >
      <Descriptions
        column={1}
        colon={false}
        size="small"
        styles={{
          label: { width: 120, color: "rgba(64, 71, 84, 0.7)" },
          content: { color: "rgba(64, 71, 84, 0.9)" },
        }}
        items={[
          {
            key: "workspace",
            label: "Workspace",
            children: (
              <Text strong title={workspaceLabel} style={{ display: "block" }}>
                {workspaceLabel}
              </Text>
            ),
          },
          {
            key: "files",
            label: "C/C++ files",
            children: selectedWorkspace?.c_cpp_file_count ?? "-",
          },
          {
            key: "judge",
            label: "Judge mode",
            children: analysisMode,
          },
          {
            key: "dynamic",
            label: "Dynamic mode",
            children: dynamicMode,
          },
          {
            key: "runner",
            label: "Runner",
            children: dynamicToolPreference,
          },
          {
            key: "hint",
            label: "Binary hint",
            children: (
              <TruncatedCode
                value={dynamicBinaryPath}
                fallback="auto-discovery"
              />
            ),
          },
          {
            key: "path",
            label: "Mounted path",
            children: <TruncatedCode value={mountedPath} fallback="n/a" />,
          },
        ]}
      />
    </AppCard>
  );
}
