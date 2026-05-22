import { Play } from 'lucide-react';
import { Button, Col, Collapse, Divider, Flex, Form, Input, InputNumber, Row, Select, Space, Tag, Typography } from 'antd';

import { AppCard } from './ui';

const { Text } = Typography;

function SectionHeader({ title, subtitle }) {
  return (
    <Flex vertical gap={2}>
      <Text strong>{title}</Text>
      {subtitle ? <Text type="secondary">{subtitle}</Text> : null}
    </Flex>
  );
}

export function SetupForm({
  loadingWorkspaces,
  workspaces,
  workspacePath,
  setWorkspacePath,
  allowedRoots,
  customPath,
  setCustomPath,
  analysisMode,
  setAnalysisMode,
  fileLimit,
  setFileLimit,
  buildCommand,
  setBuildCommand,
  dynamicRunIds,
  setDynamicRunIds,
  dynamicMode,
  setDynamicMode,
  dynamicBinaryPath,
  setDynamicBinaryPath,
  dynamicArgs,
  setDynamicArgs,
  dynamicTimeoutSec,
  setDynamicTimeoutSec,
  dynamicToolPreference,
  setDynamicToolPreference,
  activeScan,
  onStartScan,
  onGoActivity,
}) {
  const canStartScan = !activeScan && Boolean(customPath.trim() || workspacePath);
  const allowedRootsSummary = allowedRoots.length ? `Allowed roots: ${allowedRoots.length}` : 'No allowed roots configured';

  const workspaceOptions = workspaces.map((workspace) => ({
    value: workspace.path,
    label: `${workspace.name} (${workspace.c_cpp_file_count} files)`,
  }));

  return (
    <AppCard
      bodyGap={20}
      styles={{ header: { display: 'none' } }}
    >
      <Flex align="center" justify="space-between" gap={12} wrap>
        <Text type="secondary">Choose workspace and mode. Open advanced only if needed.</Text>
        <Tag color="processing">{loadingWorkspaces ? 'Loading' : `${workspaces.length} mounted`}</Tag>
      </Flex>

      <Form layout="vertical">
        <Flex vertical gap={20}>
          <Flex vertical gap={12}>
            <SectionHeader title="Target" />
            <Row gutter={[16, 0]}>
              <Col xs={24} md={12}>
                <Form.Item label="Workspace" extra={allowedRootsSummary} style={{ marginBottom: 16 }}>
                  <Select
                    value={workspacePath || undefined}
                    onChange={setWorkspacePath}
                    options={workspaceOptions}
                    placeholder="Select workspace"
                  />
                </Form.Item>
              </Col>
              <Col xs={24} md={12}>
                <Form.Item label="Path override" style={{ marginBottom: 16 }}>
                  <Input
                    placeholder="/workspace/project"
                    value={customPath}
                    onChange={(event) => setCustomPath(event.target.value)}
                  />
                </Form.Item>
              </Col>
            </Row>
          </Flex>

          <Divider style={{ margin: 0 }} />

          <Flex vertical gap={12}>
            <SectionHeader title="Scan mode" />
            <Row gutter={[16, 0]}>
              <Col xs={24} md={12}>
                <Form.Item label="Analysis mode" style={{ marginBottom: 16 }}>
                  <Select
                    value={analysisMode}
                    onChange={setAnalysisMode}
                    options={[
                      { value: 'no_llm', label: 'No LLM' },
                      { value: 'llm_assisted', label: 'LLM-assisted' },
                    ]}
                  />
                </Form.Item>
              </Col>
              <Col xs={24} md={12}>
                <Form.Item label="Dynamic mode" style={{ marginBottom: 16 }}>
                  <Select
                    value={dynamicMode}
                    onChange={setDynamicMode}
                    options={[
                      { value: 'off', label: 'Off' },
                      { value: 'selective', label: 'Selective' },
                      { value: 'aggressive', label: 'Aggressive' },
                    ]}
                  />
                </Form.Item>
              </Col>
            </Row>
          </Flex>

          <Collapse
            items={[
              {
                key: 'advanced',
                label: 'Advanced options',
                children: (
                  <Flex vertical gap={16}>
                    <Row gutter={[16, 0]}>
                      <Col xs={24} md={12}>
                        <Form.Item label="File limit" style={{ marginBottom: 16 }}>
                          <InputNumber
                            min={1}
                            max={200000}
                            value={Number(fileLimit)}
                            onChange={(value) => setFileLimit(String(value ?? 500))}
                            style={{ width: '100%' }}
                          />
                        </Form.Item>
                      </Col>
                      <Col xs={24} md={12}>
                        <Form.Item label="Runner" style={{ marginBottom: 16 }}>
                          <Select
                            value={dynamicToolPreference}
                            onChange={setDynamicToolPreference}
                            options={[
                              { value: 'auto', label: 'Auto' },
                              { value: 'valgrind', label: 'Valgrind' },
                              { value: 'lsan', label: 'LSan' },
                              { value: 'asan', label: 'ASan' },
                            ]}
                          />
                        </Form.Item>
                      </Col>
                      <Col xs={24} md={12}>
                        <Form.Item label="Timeout (sec)" style={{ marginBottom: 16 }}>
                          <InputNumber
                            min={1}
                            max={7200}
                            value={Number(dynamicTimeoutSec)}
                            onChange={(value) => setDynamicTimeoutSec(String(value ?? 120))}
                            style={{ width: '100%' }}
                          />
                        </Form.Item>
                      </Col>
                      <Col xs={24} md={12}>
                        <Form.Item label="Build command" style={{ marginBottom: 16 }}>
                          <Input
                            placeholder="make CC=clang"
                            value={buildCommand}
                            onChange={(event) => setBuildCommand(event.target.value)}
                          />
                        </Form.Item>
                      </Col>
                      <Col xs={24} md={12}>
                        <Form.Item label="Executable hint" style={{ marginBottom: 16 }}>
                          <Input
                            placeholder="/workspace/targets/my-project/build/bin/app"
                            value={dynamicBinaryPath}
                            onChange={(event) => setDynamicBinaryPath(event.target.value)}
                          />
                        </Form.Item>
                      </Col>
                      <Col xs={24} md={12}>
                        <Form.Item label="Executable args" style={{ marginBottom: 16 }}>
                          <Input
                            placeholder="--input corpus.txt --mode smoke"
                            value={dynamicArgs}
                            onChange={(event) => setDynamicArgs(event.target.value)}
                          />
                        </Form.Item>
                      </Col>
                      <Col span={24}>
                        <Form.Item label="External run IDs" extra="Comma-separated IDs." style={{ marginBottom: 0 }}>
                          <Input
                            placeholder="run-1, run-2"
                            value={dynamicRunIds}
                            onChange={(event) => setDynamicRunIds(event.target.value)}
                          />
                        </Form.Item>
                      </Col>
                    </Row>
                  </Flex>
                ),
              },
            ]}
          />
        </Flex>
      </Form>

      <Flex
        justify="space-between"
        align="center"
        gap={16}
        wrap
        style={{
          paddingTop: 16,
          borderTop: '1px solid rgba(64, 71, 84, 0.08)',
        }}
      >
        <Text type="secondary">Only workspace and mode are required to start.</Text>
        <Space wrap>
          <Button onClick={onGoActivity}>Open Activity</Button>
          <Button type="primary" icon={<Play size={16} />} onClick={onStartScan} disabled={!canStartScan}>
            Start Scan
          </Button>
        </Space>
      </Flex>
    </AppCard>
  );
}
