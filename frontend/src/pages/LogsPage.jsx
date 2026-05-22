import { useEffect, useMemo, useRef } from 'react';
import { Download, Pause, Play, Trash2 } from 'lucide-react';
import { Button, Checkbox, Empty, Flex, Input, Select, Space, Tag, Typography, theme } from 'antd';

import { AppCard } from '../components/ui';
import { useLogsStore } from '../stores/logsStore';

const { Text } = Typography;

function getLevelTagColor(level) {
  switch (level) {
    case 'ERROR':
    case 'CRITICAL':
      return 'red';
    case 'WARNING':
      return 'orange';
    case 'INFO':
      return 'blue';
    case 'DEBUG':
      return 'default';
    default:
      return 'default';
  }
}

function getLevelTextColor(level) {
  switch (level) {
    case 'ERROR':
    case 'CRITICAL':
      return '#d93737';
    case 'WARNING':
      return '#e68a00';
    case 'INFO':
      return '#2e5bff';
    default:
      return undefined;
  }
}

export function LogsPage() {
  const logsEndRef = useRef(null);
  const eventSourceRef = useRef(null);
  const { token } = theme.useToken();
  const logs = useLogsStore((state) => state.logs);
  const isPaused = useLogsStore((state) => state.isPaused);
  const autoScroll = useLogsStore((state) => state.autoScroll);
  const filter = useLogsStore((state) => state.filter);
  const levelFilter = useLogsStore((state) => state.levelFilter);
  const setPaused = useLogsStore((state) => state.setPaused);
  const setAutoScroll = useLogsStore((state) => state.setAutoScroll);
  const setFilter = useLogsStore((state) => state.setFilter);
  const setLevelFilter = useLogsStore((state) => state.setLevelFilter);
  const clearLogs = useLogsStore((state) => state.clearLogs);
  const appendLog = useLogsStore((state) => state.appendLog);
  const loadInitialLogs = useLogsStore((state) => state.loadInitialLogs);
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchesText = filter === '' || log.message.toLowerCase().includes(filter.toLowerCase());
      const matchesLevel = levelFilter === 'ALL' || log.level === levelFilter;
      return matchesText && matchesLevel;
    });
  }, [filter, levelFilter, logs]);

  useEffect(() => {
    loadInitialLogs().catch((error) => console.error('Failed to fetch initial logs:', error));

    if (!isPaused) {
      const eventSource = new EventSource('/api/logs?format=sse');
      eventSourceRef.current = eventSource;

      eventSource.onmessage = (event) => {
        try {
          const logEntry = JSON.parse(event.data);
          appendLog(logEntry);
        } catch (error) {
          console.error('Failed to parse log entry:', error);
        }
      };

      eventSource.onerror = (error) => {
        console.error('SSE connection error:', error);
        eventSource.close();
      };

      return () => {
        eventSource.close();
      };
    }

    return undefined;
  }, [appendLog, isPaused, loadInitialLogs]);

  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  function downloadLogs() {
    const logText = logs
      .map((log) => {
        const timestamp = new Date(log.timestamp * 1000).toISOString();
        return `[${timestamp}] [${log.level}] [${log.logger_name}] ${log.message}`;
      })
      .join('\n');

    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `server-logs-${Date.now()}.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }

  return (
    <AppCard
      style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
      bodyStyle={{ flex: 1, minHeight: 0, overflow: 'hidden' }}
      styles={{ header: { display: 'none' } }}
    >
      <Flex justify="space-between" gap={12} wrap align="center">
        <Text type="secondary">Live stream of backend activity with filter and download controls.</Text>
        <Space wrap>
          <Button
            size="small"
            icon={isPaused ? <Play size={16} /> : <Pause size={16} />}
            onClick={() => setPaused(!isPaused)}
          >
            {isPaused ? 'Resume' : 'Pause'}
          </Button>
          <Button size="small" icon={<Download size={16} />} onClick={downloadLogs}>
            Download
          </Button>
          <Button size="small" danger type="primary" icon={<Trash2 size={16} />} onClick={clearLogs}>
            Clear
          </Button>
        </Space>
      </Flex>

      <Flex gap={12} wrap align="center">
        <Input
          placeholder="Filter logs..."
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          style={{ flex: '1 1 280px' }}
        />
        <Select
          value={levelFilter}
          onChange={setLevelFilter}
          style={{ width: 160 }}
          options={[
            { value: 'ALL', label: 'All Levels' },
            { value: 'DEBUG', label: 'Debug' },
            { value: 'INFO', label: 'Info' },
            { value: 'WARNING', label: 'Warning' },
            { value: 'ERROR', label: 'Error' },
            { value: 'CRITICAL', label: 'Critical' },
          ]}
        />
        <Checkbox checked={autoScroll} onChange={(event) => setAutoScroll(event.target.checked)}>
          Auto-scroll
        </Checkbox>
        <Text type="secondary">
          {filteredLogs.length} / {logs.length} logs
        </Text>
      </Flex>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflow: 'auto',
          borderRadius: token.borderRadiusLG,
          border: `1px solid ${token.colorBorderSecondary}`,
          background: token.colorBgContainer,
          padding: 16,
          fontFamily: 'SFMono-Regular, Consolas, Menlo, monospace',
          fontSize: 13,
        }}
      >
        {filteredLogs.length === 0 ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No logs to display" />
        ) : (
          filteredLogs.map((log, index) => (
            <Flex
              key={`${log.timestamp}-${log.logger_name}-${index}`}
              gap={12}
              align="start"
              style={{
                padding: '8px 10px',
                borderRadius: token.borderRadiusSM,
                marginBottom: 6,
                background: index % 2 === 0 ? token.colorBgLayout : token.colorBgContainer,
              }}
            >
              <Text type="secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                {new Date(log.timestamp * 1000).toLocaleTimeString('en-US', {
                  hour12: false,
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                })}
              </Text>
              <Tag color={getLevelTagColor(log.level)}>{log.level}</Tag>
              <Text type="secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                {log.logger_name}
              </Text>
              <span style={{ color: getLevelTextColor(log.level), overflowWrap: 'anywhere' }}>{log.message}</span>
            </Flex>
          ))
        )}
        <div ref={logsEndRef} />
      </div>
    </AppCard>
  );
}
