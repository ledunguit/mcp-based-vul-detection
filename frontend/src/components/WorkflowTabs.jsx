import { ApartmentOutlined } from "@ant-design/icons";
import { FileSearch2, FolderGit2, History, Terminal } from "lucide-react";
import { Flex, Menu } from "antd";
import { useLocation, useNavigate } from "react-router-dom";

export const WORKFLOW_TABS = [
  {
    to: "/setup",
    label: "Setup",
    icon: <FolderGit2 size={16} strokeWidth={2.1} />,
  },
  {
    to: "/investigations",
    label: "Investigations",
    icon: <History size={16} strokeWidth={2.1} />,
  },
  {
    to: "/activity",
    label: "Execution Graph",
    icon: <ApartmentOutlined size={16} strokeWidth={2.1} />,
  },
  {
    to: "/report",
    label: "Report",
    icon: <FileSearch2 size={16} strokeWidth={2.1} />,
  },
  {
    to: "/logs",
    label: "Logs",
    icon: <Terminal size={16} strokeWidth={2.1} />,
  },
];

function extractScanId(pathname) {
  const match = pathname.match(/^\/(?:activity|report)\/([^/]+)$/);
  return match ? match[1] : null;
}

function resolveTabPath(tab, scanId) {
  if (!tab) {
    return "/setup";
  }
  if (!scanId) {
    return tab.to;
  }
  if (tab.to === "/activity" || tab.to === "/report") {
    return `${tab.to}/${scanId}`;
  }
  return tab.to;
}

function buildMenuLabel(tab, compact, collapsed) {
  if (compact) {
    return tab.label;
  }

  if (collapsed) {
    return null;
  }

  return (
    <Flex align="center" style={{ minHeight: 22 }}>
      <span>{tab.label}</span>
    </Flex>
  );
}

export function WorkflowTabs({ compact = false, collapsed = false, activeScanId = null }) {
  const navigate = useNavigate();
  const location = useLocation();
  const scanId = activeScanId || extractScanId(location.pathname);
  const selectedKey =
    WORKFLOW_TABS.find((tab) => location.pathname.startsWith(tab.to))?.to ||
    "/setup";

  return (
    <Menu
      mode={compact ? "horizontal" : "inline"}
      selectedKeys={[selectedKey]}
      {...(!compact && { inlineCollapsed: collapsed })}
      onClick={({ key }) => navigate(resolveTabPath(WORKFLOW_TABS.find((tab) => tab.to === key), scanId))}
      items={WORKFLOW_TABS.map((tab) => ({
        key: tab.to,
        icon: <span className="app-shell-menu-icon">{tab.icon}</span>,
        label: buildMenuLabel(tab, compact, collapsed),
        title: tab.label,
      }))}
      style={{
        borderInlineEnd: 0,
        background: "transparent",
      }}
      className="app-shell-menu"
    />
  );
}
