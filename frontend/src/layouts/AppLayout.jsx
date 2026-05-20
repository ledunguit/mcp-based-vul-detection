import { useMemo, useState } from 'react';
import { MenuFoldOutlined, MenuUnfoldOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { Link, Outlet, useLocation, useOutletContext } from 'react-router-dom';
import { Radar } from 'lucide-react';
import { Breadcrumb, Button, Card, Flex, Grid, Layout, Tag, Typography, theme } from 'antd';

import { AppHeader } from '../components/AppHeader';
import { ErrorBanner } from '../components/ErrorBanner';
import { WORKFLOW_TABS, WorkflowTabs } from '../components/WorkflowTabs';
import { useMemoryLeakConsole } from '../hooks/useMemoryLeakConsole';
import { tagColor } from '../utils/ui';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;
const ROUTE_LABELS = Object.fromEntries(WORKFLOW_TABS.map((tab) => [tab.to, tab.label]));

function titleizeSegment(segment) {
  return segment
    .split('-')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

export function AppLayout() {
  const consoleState = useMemoryLeakConsole();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const { token } = theme.useToken();
  const screens = Grid.useBreakpoint();
  const location = useLocation();
  const showSider = Boolean(screens.lg);
  const breadcrumbItems = useMemo(() => {
    const segments = location.pathname.split('/').filter(Boolean);

    if (!segments.length) {
      return [{ title: 'Console' }];
    }

    const items = [{ title: <Link to="/setup">Console</Link> }];
    let currentPath = '';

    segments.forEach((segment, index) => {
      currentPath = `${currentPath}/${segment}`;
      const label = ROUTE_LABELS[currentPath] || titleizeSegment(segment);
      items.push({
        title: index === segments.length - 1 ? label : <Link to={currentPath}>{label}</Link>,
      });
    });

    return items;
  }, [location.pathname]);

  return (
    <Layout hasSider={showSider} style={{ minHeight: '100vh', background: token.colorBgLayout }}>
      {showSider ? (
        <Sider
          width={280}
          collapsedWidth={96}
          collapsible
          collapsed={sidebarCollapsed}
          trigger={null}
          theme="light"
          style={{
            background: token.colorBgContainer,
            borderInlineEnd: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          <Flex vertical gap={16} style={{ height: '100%', padding: 16 }}>
            <Flex justify="center" style={{ paddingTop: 4 }}>
              <Flex
                align="center"
                justify="center"
                style={{
                  width: 40,
                  height: 40,
                  borderRadius: token.borderRadius,
                  background: token.colorPrimaryBg,
                }}
              >
                <Radar size={18} color={token.colorPrimary} />
              </Flex>
            </Flex>

            <WorkflowTabs collapsed={sidebarCollapsed} />

            {!sidebarCollapsed ? (
              <>
                <Card
                  size="small"
                  title="Selection"
                  styles={{ body: { display: 'flex', flexDirection: 'column', gap: 8 } }}
                >
                  <Flex justify="space-between" align="center" gap={8}>
                    <Text strong ellipsis>
                      {consoleState.selectedScan?.scan_id || 'No scan selected'}
                    </Text>
                    <Tag color={tagColor(consoleState.selectedScan?.status)}>
                      {consoleState.selectedScan?.status || 'idle'}
                    </Tag>
                  </Flex>
                  <Text type="secondary">
                    {consoleState.selectedScan?.workspace_path || 'Pick a workspace and launch a scan to populate the console.'}
                  </Text>
                </Card>

                <Card size="small">
                  <Flex align="center" gap={8}>
                    <SafetyCertificateOutlined style={{ color: token.colorPrimary }} />
                    <Text type="secondary">Workspace-scoped analysis only</Text>
                  </Flex>
                </Card>
              </>
            ) : null}
          </Flex>
        </Sider>
      ) : null}

      <Layout style={{ background: token.colorBgLayout }}>
        <Header
          style={{
            background: token.colorBgContainer,
            padding: '0 16px',
            height: 'auto',
            lineHeight: 'normal',
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          <Flex vertical gap={16} style={{ paddingBlock: 16 }}>
            <Flex align="center" gap={12}>
              {showSider ? (
                <Button
                  type="text"
                  icon={sidebarCollapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
                  onClick={() => setSidebarCollapsed((current) => !current)}
                />
              ) : null}
              <div style={{ flex: 1, minWidth: 0 }}>
                <AppHeader selectedScan={consoleState.selectedScan} />
              </div>
            </Flex>
            <Breadcrumb items={breadcrumbItems} />
            {!showSider ? (
              <Card size="small" bodyStyle={{ paddingBlock: 8, paddingInline: 12 }}>
                <WorkflowTabs compact />
              </Card>
            ) : null}
            <ErrorBanner errorBanner={consoleState.errorBanner} />
          </Flex>
        </Header>

        <Content
          style={{
            flex: 1,
            minHeight: 0,
            overflow: 'auto',
            padding: '16px',
            background: token.colorBgLayout,
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            <Outlet context={consoleState} />
          </div>
        </Content>
      </Layout>
    </Layout>
  );
}

export function useConsoleContext() {
  return useOutletContext();
}
