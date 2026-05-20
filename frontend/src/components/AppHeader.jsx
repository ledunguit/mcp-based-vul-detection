import { Radar } from 'lucide-react';
import { Flex, Space, Tag, Typography, theme } from 'antd';

import { tagColor } from '../utils/ui';

const { Text, Title } = Typography;

export function AppHeader({ selectedScan }) {
  const { token } = theme.useToken();

  return (
    <Flex justify="space-between" align="center" gap={16} wrap>
      <Space size={12} align="center">
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
          <Radar size={20} color={token.colorPrimary} />
        </Flex>
        <Flex vertical gap={2} style={{ textAlign: 'left' }}>
          <Title level={4} style={{ margin: 0 }}>
            MCP-VUL
          </Title>
          <Text type="secondary">Memory Leak Console</Text>
        </Flex>
      </Space>

      <Flex gap={8} wrap align="center" justify="flex-end">
        <Tag color={tagColor(selectedScan?.status)}>{selectedScan?.status || 'idle'}</Tag>
        {selectedScan ? <Tag>{selectedScan.scan_id}</Tag> : <Tag>no active scan</Tag>}
        <Text type="secondary" style={{ textAlign: 'right' }}>
          {selectedScan?.workspace_path || 'Select a workspace and start a scan to populate the console.'}
        </Text>
      </Flex>
    </Flex>
  );
}
