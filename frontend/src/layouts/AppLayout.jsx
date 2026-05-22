import { useMemo, useState } from 'react';
import { MenuFoldOutlined, MenuUnfoldOutlined } from '@ant-design/icons';
import { Link, Outlet, useLocation, useOutletContext } from 'react-router-dom';
import { Radar } from 'lucide-react';
import { Breadcrumb, Button, Card, Flex, Grid, Layout, theme } from 'antd';

import { AppHeader } from '../components/AppHeader';
import { ErrorBanner } from '../components/ErrorBanner';
import { WORKFLOW_TABS, WorkflowTabs } from '../components/WorkflowTabs';
import { useMemoryLeakConsole } from '../hooks/useMemoryLeakConsole';

const { Header, Sider, Content } = Layout;
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
      const previousSegment = segments[index - 1];
      if ((previousSegment === 'activity' || previousSegment === 'report') && segment) {
        return;
      }
      const label = ROUTE_LABELS[currentPath] || titleizeSegment(segment);
      items.push({
        title: index === segments.length - 1 ? label : <Link to={currentPath}>{label}</Link>,
      });
    });

    return items;
  }, [location.pathname]);

  const isFullViewportPage = location.pathname.includes('/report') || location.pathname.includes('/activity');

  return (
    <Layout
      hasSider={showSider}
      style={{
        height: isFullViewportPage ? '100vh' : undefined,
        minHeight: isFullViewportPage ? undefined : '100vh',
        maxHeight: isFullViewportPage ? '100vh' : undefined,
        overflow: isFullViewportPage ? 'hidden' : undefined,
        background: token.colorBgLayout,
      }}
    >
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

            <WorkflowTabs collapsed={sidebarCollapsed} activeScanId={consoleState.selectedScan?.scan_id} />
          </Flex>
        </Sider>
      ) : null}

      <Layout
        style={{
          background: token.colorBgLayout,
          height: isFullViewportPage ? '100%' : undefined,
          maxHeight: isFullViewportPage ? '100%' : undefined,
          overflow: isFullViewportPage ? 'hidden' : undefined,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
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
                <AppHeader selectedScan={consoleState.selectedScan} reportData={consoleState.reportData} />
              </div>
            </Flex>
            <Breadcrumb items={breadcrumbItems} />
            {!showSider ? (
              <Card size="small" styles={{ body: { paddingBlock: 8, paddingInline: 12 } }}>
                <WorkflowTabs compact activeScanId={consoleState.selectedScan?.scan_id} />
              </Card>
            ) : null}
            <ErrorBanner errorBanner={consoleState.errorBanner} />
          </Flex>
        </Header>

        <Content
          style={{
            flex: 1,
            minHeight: 0,
            overflow: (location.pathname.includes('/report') || location.pathname.includes('/activity')) ? 'hidden' : 'auto',
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
