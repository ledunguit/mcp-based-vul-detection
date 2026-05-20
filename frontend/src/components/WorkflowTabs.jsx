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

export function WorkflowTabs({ compact = false, collapsed = false }) {
  const navigate = useNavigate();
  const location = useLocation();
  const selectedKey =
    WORKFLOW_TABS.find((tab) => location.pathname.startsWith(tab.to))?.to ||
    "/setup";

  return (
    <Menu
      mode={compact ? "horizontal" : "inline"}
      selectedKeys={[selectedKey]}
      inlineCollapsed={!compact && collapsed}
      onClick={({ key }) => navigate(key)}
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
