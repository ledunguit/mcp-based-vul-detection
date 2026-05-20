import { FolderCode, History, RefreshCw, Trash2 } from 'lucide-react';
import { Button, Flex, List, Space, Tag, Typography, theme } from 'antd';

import { tagColor, formatClock, formatRelativeTime } from '../utils/ui';
import { AppCard } from './ui';

const { Text } = Typography;
const TERMINAL_STATES = new Set(['completed', 'failed', 'cancelled']);

export function ScanHistoryList({
  recentScans,
  selectedScanId,
  terminalScanCount,
  deletingScans,
  onRefresh,
  onSelectScan,
  onRequestDeleteScan,
  onRequestDeleteTerminalScans,
  standalone = false,
}) {
  const { token } = theme.useToken();

  return (
    <AppCard
      title="Recent Investigations"
      extra={
        <Space wrap>
          <Button type="text" size="small" icon={<RefreshCw size={14} />} onClick={onRefresh}>
            Refresh
          </Button>
          <Button
            danger
            size="small"
            icon={<Trash2 size={14} />}
            onClick={onRequestDeleteTerminalScans}
            disabled={deletingScans || !terminalScanCount}
          >
            Delete Old
          </Button>
        </Space>
      }
    >
      <Space direction="vertical" size={4}>
        <Tag>
          <Flex align="center" gap={6}>
            <History size={14} />
            <span>Scan history</span>
          </Flex>
        </Tag>
        <Text type="secondary">Open a running or completed scan, compare statuses, and clean up terminal entries.</Text>
      </Space>

      <List
        dataSource={recentScans}
        locale={{ emptyText: 'No persisted scans yet.' }}
        split={false}
        grid={
          standalone
            ? { gutter: 16, xs: 1, md: 2, xxl: 3 }
            : undefined
        }
        style={{ maxHeight: standalone ? 'none' : '70vh', overflow: standalone ? 'visible' : 'auto' }}
        renderItem={(scan) => {
          const selected = selectedScanId === scan.scan_id;

          return (
            <List.Item style={{ paddingBlock: 0, paddingInline: 0, border: 0, marginBottom: 12 }}>
              <AppCard
                hoverable
                size="small"
                onClick={() => onSelectScan(scan)}
                bodyGap={12}
                style={{
                  width: '100%',
                  cursor: 'pointer',
                  borderColor: selected ? token.colorPrimary : token.colorBorderSecondary,
                  background: selected ? token.colorPrimaryBg : token.colorBgContainer,
                  boxShadow: selected ? `0 0 0 1px ${token.colorPrimaryBorder}` : undefined,
                }}
              >
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Space wrap align="center" style={{ justifyContent: 'space-between', width: '100%' }}>
                    <Text strong>{scan.scan_id}</Text>
                    <Space size={8} wrap>
                      <Tag color={tagColor(scan.status)}>{scan.status}</Tag>
                      <Tag>{scan.analysis_mode || 'no_llm'}</Tag>
                    </Space>
                  </Space>

                  <Space size={8} align="start">
                    <FolderCode size={14} color={token.colorPrimary} style={{ marginTop: 2 }} />
                    <Text type="secondary">{scan.workspace_path}</Text>
                  </Space>

                  <Space size={24} wrap>
                    <div>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        Created
                      </Text>
                      <div>{formatClock(scan.created_at)}</div>
                    </div>
                    <div>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        Age
                      </Text>
                      <div>{formatRelativeTime(scan.created_at)}</div>
                    </div>
                  </Space>
                </Space>

                <Space wrap style={{ justifyContent: 'space-between', width: '100%' }}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    Tap to inspect on the canvas
                  </Text>
                  <Button
                    danger
                    type="link"
                    size="small"
                    onClick={(event) => {
                      event.stopPropagation();
                      onRequestDeleteScan(scan);
                    }}
                    disabled={deletingScans || !TERMINAL_STATES.has(scan.status)}
                  >
                    Delete
                  </Button>
                </Space>
              </AppCard>
            </List.Item>
          );
        }}
      />
    </AppCard>
  );
}
