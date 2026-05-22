import { ChevronDown, ChevronUp, GripHorizontal } from "lucide-react";
import { Button, Empty, Space, Typography, theme } from "antd";

const { Text } = Typography;

function lineColor(eventType, token) {
  if (eventType === "completed") {
    return token.colorSuccessText;
  }
  if (["failed", "error"].includes(eventType)) {
    return token.colorErrorText;
  }
  if (
    ["cancelled", "cancel_requested", "worker_termination_requested"].includes(
      eventType,
    )
  ) {
    return token.colorWarningText;
  }
  return token.colorText;
}

export function TerminalLogCard({
  selectedScan,
  loadingScan,
  deferredEvents,
  terminalRef,
  onReload,
  onExport,
  formatEvent,
  collapsed = false,
  onToggleCollapse,
  onResizeStart,
}) {
  const { token } = theme.useToken();

  return (
    <div style={{ position: "relative", height: "100%" }}>
      <div
        style={{
          position: "absolute",
          left: "50%",
          top: 0,
          transform: "translate(-50%, -50%)",
          zIndex: 2,
          width: 120,
          height: 24,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          cursor: "ns-resize",
        }}
        onPointerDown={onResizeStart}
      >
        <Button
          size="small"
          shape="round"
          onPointerDown={(event) => event.stopPropagation()}
          onClick={onToggleCollapse}
          icon={
            <span
              style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
            >
              <GripHorizontal size={12} />
              {collapsed ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </span>
          }
          style={{
            height: 28,
            paddingInline: 10,
            borderColor: token.colorBorder,
            background: token.colorBgContainer,
            boxShadow: token.boxShadowTertiary,
          }}
        >
          {collapsed ? "Open Logs" : "Hide Logs"}
        </Button>
      </div>

      <div
        style={{
          height: "100%",
          display: "flex",
          flexDirection: "column",
          border: `1px solid ${token.colorBorderSecondary}`,
          borderRadius: token.borderRadiusLG,
          background: token.colorBgContainer,
          boxShadow: token.boxShadowTertiary,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            minHeight: collapsed ? 46 : 42,
            paddingInline: 14,
            background: token.colorBgContainer,
            borderBottom: collapsed
              ? "none"
              : `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          <Space size={10} style={{ minWidth: 0 }}>
            <Text strong style={{ fontSize: 13 }}>
              Terminal Log
            </Text>
            <Text
              type="primary"
              ellipsis
              style={{
                minWidth: 0,
                maxWidth: collapsed ? 220 : 320,
                fontSize: 12,
                color: token.colorPrimary,
              }}
            >
              {selectedScan ? `${selectedScan.scan_id}` : ""}
            </Text>
          </Space>

          {!collapsed ? (
            <Space wrap>
              <Button size="small" onClick={onReload} disabled={!selectedScan}>
                Reload
              </Button>
              <Button
                type="primary"
                size="small"
                onClick={onExport}
                disabled={!selectedScan}
              >
                Export
              </Button>
            </Space>
          ) : null}
        </div>

        {!collapsed ? (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              flex: 1,
              minHeight: 0,
              background: token.colorBgContainer,
              overflow: "hidden",
            }}
          >
            <div
              ref={terminalRef}
              style={{
                flex: 1,
                minHeight: 0,
                overflow: "auto",
                padding: 14,
                background: token.colorBgContainer,
                fontFamily: "SFMono-Regular, Consolas, Menlo, monospace",
                fontSize: 13,
                lineHeight: 1.65,
              }}
            >
              {loadingScan ? (
                <pre style={{ margin: 0, color: token.colorInfoText }}>
                  {"> loading selected scan..."}
                </pre>
              ) : null}

              {deferredEvents.length ? (
                deferredEvents.map((event) => (
                  <div key={event.event_id} style={{ marginBottom: 8 }}>
                    {formatEvent(event).map((line, index) => (
                      <pre
                        key={`${event.event_id}-${index}`}
                        style={{
                          margin: 0,
                          color: lineColor(event.type, token),
                          whiteSpace: "pre-wrap",
                          overflowWrap: "anywhere",
                        }}
                      >
                        {`${index === 0 ? ">" : "."} ${line}`}
                      </pre>
                    ))}
                  </div>
                ))
              ) : (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description={
                    selectedScan
                      ? "Waiting for scan events..."
                      : "No scan selected."
                  }
                />
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
