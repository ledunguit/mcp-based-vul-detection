import { Col, Descriptions, Empty, Row, Table, Typography } from 'antd';

import { buildVerdictCounts } from './reportFormat';
import { AppCard, AppMetricCard } from '../ui';

const { Text } = Typography;

const performanceColumns = [
  {
    title: 'Tool',
    dataIndex: 'tool',
    key: 'tool',
    render: (text) => <span style={{ overflowWrap: 'anywhere' }}>{text}</span>,
  },
  { title: 'Calls', dataIndex: 'calls', key: 'calls' },
  { title: 'Total ms', dataIndex: 'total_duration_ms', key: 'total_duration_ms' },
  { title: 'Avg ms', dataIndex: 'avg_duration_ms', key: 'avg_duration_ms' },
  { title: 'Max ms', dataIndex: 'max_duration_ms', key: 'max_duration_ms' },
];

export function OverviewView({ selectedScan, reportData }) {
  const bundles = reportData?.bundles || [];
  const counts = buildVerdictCounts(bundles);
  const performance = reportData?.performance_summary || {};
  const perTool = Object.entries(performance.per_tool || {})
    .sort((a, b) => b[1].total_duration_ms - a[1].total_duration_ms)
    .slice(0, 5)
    .map(([tool, stats]) => ({ key: tool, tool, ...stats }));
  const judgeSummary = reportData?.judge_summary || selectedScan?.judge_summary || {};

  return (
    <Row gutter={[16, 16]}>
      <Col span={24}>
        <Descriptions bordered size="small" column={{ xs: 1, sm: 2, xl: 4 }}>
          <Descriptions.Item label="Repository">
            <span style={{ overflowWrap: 'anywhere' }}>{reportData?.repo_path || selectedScan?.workspace_path || 'n/a'}</span>
          </Descriptions.Item>
          <Descriptions.Item label="Bundles">{reportData?.bundle_count ?? '-'}</Descriptions.Item>
          <Descriptions.Item label="Evidence">{reportData?.evidence_count ?? '-'}</Descriptions.Item>
          <Descriptions.Item label="Mode">
            <span style={{ overflowWrap: 'anywhere' }}>{reportData?.analysis_mode || selectedScan?.analysis_mode || 'n/a'}</span>
          </Descriptions.Item>
        </Descriptions>
      </Col>

      <Col xs={24} xl={12}>
        <AppCard size="small" title="Verdict Distribution">
          {Object.entries(counts).length ? (
            <Row gutter={[12, 12]}>
              {Object.entries(counts).map(([verdict, count]) => (
                <Col xs={24} sm={12} key={verdict}>
                  <AppMetricCard metric={verdict} value={count} />
                </Col>
              ))}
            </Row>
          ) : (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No findings loaded." />
          )}
        </AppCard>
      </Col>

      <Col xs={24} xl={12}>
        <AppCard size="small" title="Judge Summary">
          <Row gutter={[12, 12]}>
            <Col xs={24} sm={12}>
              <AppMetricCard metric="Effective mode" value={judgeSummary.effective_mode || 'n/a'} valueStyle={{ fontSize: 18 }} />
            </Col>
            <Col xs={24} sm={12}>
              <AppMetricCard metric="Provider" value={judgeSummary.provider || 'heuristic'} valueStyle={{ fontSize: 18 }} />
            </Col>
            <Col xs={24} sm={12}>
              <AppMetricCard metric="LLM success" value={judgeSummary.llm_success_count ?? 0} />
            </Col>
            <Col xs={24} sm={12}>
              <AppMetricCard metric="LLM skipped" value={judgeSummary.llm_skipped_count ?? 0} />
            </Col>
          </Row>
        </AppCard>
      </Col>

      <Col span={24}>
        <AppCard size="small" title="Performance Hotspots">
          {perTool.length ? (
            <Table columns={performanceColumns} dataSource={perTool} size="small" pagination={false} />
          ) : (
            <Text type="secondary">Performance data will appear after loading a completed report.</Text>
          )}
        </AppCard>
      </Col>
    </Row>
  );
}
