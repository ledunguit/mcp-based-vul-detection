import { useEffect, useState } from 'react';
import { Col, Descriptions, Empty, Flex, List, Row, Segmented, Space, Tag, Typography, theme } from 'antd';

import { SuggestionDiffCard } from './SuggestionDiffCard';
import { formatLocation, verdictTagColor } from './reportFormat';
import { AppCard } from '../ui';

const { Paragraph, Text, Title } = Typography;

function EvidenceCard({ evidence, index }) {
  return (
    <AppCard size="small" bodyGap={12}>
      <Space wrap>
        <Tag>#{index}</Tag>
        <Tag color="blue">{evidence.tool || 'unknown-tool'}</Tag>
        <Tag>{evidence.kind || 'evidence'}</Tag>
        <Tag>{evidence.confidence || 'unknown'} confidence</Tag>
        <Tag>{evidence.severity || 'unknown'} severity</Tag>
      </Space>
      <Paragraph style={{ marginBottom: 0 }}>{evidence.message || 'No evidence message.'}</Paragraph>
      {evidence.location ? (
        <Paragraph code style={{ marginBottom: 0 }}>
          {formatLocation(evidence.location)}
        </Paragraph>
      ) : null}
    </AppCard>
  );
}

function FindingDetail({ bundle }) {
  if (!bundle) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Select a finding to inspect evidence and suggested patch." />;
  }

  const candidate = bundle.candidate || {};
  const verdict = bundle.verdict || {};
  const evidence = candidate.evidence || [];
  const suggestions = verdict.fix_suggestions || [];

  return (
    <AppCard bodyGap={16}>
      <Flex justify="space-between" align="start" gap={16} wrap>
        <div>
          <Space wrap>
            <Title level={4} style={{ margin: 0 }}>
              {candidate.summary || bundle.bundle_id}
            </Title>
            <Tag color={verdictTagColor(verdict.verdict)}>{verdict.verdict || 'unjudged'}</Tag>
            <Tag>{verdict.confidence || candidate.confidence || 'n/a'} confidence</Tag>
            <Tag>{candidate.primary_tool || 'n/a'}</Tag>
          </Space>
          <Paragraph style={{ marginTop: 12, marginBottom: 0 }}>
            {verdict.human_explanation || verdict.why || 'No explanation was produced.'}
          </Paragraph>
        </div>
      </Flex>

      <Descriptions bordered size="small" column={{ xs: 1, xl: 3 }}>
        <Descriptions.Item label="Candidate">
          <Paragraph code style={{ marginBottom: 0 }}>
            {formatLocation(candidate)}
          </Paragraph>
        </Descriptions.Item>
        <Descriptions.Item label="Allocation Site">
          <Paragraph code style={{ marginBottom: 0 }}>
            {formatLocation(candidate.allocation_site)}
          </Paragraph>
        </Descriptions.Item>
        <Descriptions.Item label="Missing Cleanup Site">
          <Paragraph code style={{ marginBottom: 0 }}>
            {formatLocation(candidate.missing_free_site)}
          </Paragraph>
        </Descriptions.Item>
      </Descriptions>

      <Row gutter={[16, 16]}>
        <Col xs={24} xxl={15}>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <AppCard size="small" title="Supporting Evidence">
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                {evidence.length ? (
                  evidence.map((item, index) => <EvidenceCard key={`${bundle.bundle_id}-evidence-${index}`} evidence={item} index={index} />)
                ) : (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No evidence attached." />
                )}
              </Space>
            </AppCard>

            {bundle.orchestrator_notes?.length ? (
              <AppCard size="small" title="Orchestrator Notes" bodyGap={8}>
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  {bundle.orchestrator_notes.map((note, index) => (
                    <AppCard key={`${bundle.bundle_id}-note-${index}`} size="small" bodyGap={0}>
                      {note}
                    </AppCard>
                  ))}
                </Space>
              </AppCard>
            ) : null}
          </Space>
        </Col>

        <Col xs={24} xxl={9}>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <AppCard size="small" title="Missing Evidence">
              <Space wrap>
                {(verdict.missing_evidence || []).length ? (
                  verdict.missing_evidence.map((item) => (
                    <Tag key={`${bundle.bundle_id}-${item}`} color="orange">
                      {item}
                    </Tag>
                  ))
                ) : (
                  <Tag color="green">None</Tag>
                )}
              </Space>
            </AppCard>

            <AppCard size="small" title="Path Constraints">
              <Space wrap>
                {(candidate.path_constraints || []).length ? (
                  candidate.path_constraints.map((item) => <Tag key={`${bundle.bundle_id}-${item}`}>{item}</Tag>)
                ) : (
                  <Text type="secondary">No path constraints recorded.</Text>
                )}
              </Space>
            </AppCard>
          </Space>
        </Col>
      </Row>

      <AppCard size="small" title="Suggested Fix">
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          {suggestions.length ? (
            suggestions.map((suggestion, index) => (
              <SuggestionDiffCard key={`${bundle.bundle_id}-suggestion-${index}`} suggestion={suggestion} />
            ))
          ) : (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No concrete fix suggestion was produced." />
          )}
        </Space>
      </AppCard>
    </AppCard>
  );
}

export function FindingsView({ reportData }) {
  const bundles = reportData?.bundles || [];
  const [filter, setFilter] = useState('all');
  const [selectedBundleId, setSelectedBundleId] = useState(bundles[0]?.bundle_id || null);
  const { token } = theme.useToken();

  useEffect(() => {
    if (!bundles.length) {
      setSelectedBundleId(null);
      return;
    }
    if (!bundles.some((bundle) => bundle.bundle_id === selectedBundleId)) {
      setSelectedBundleId(bundles[0].bundle_id);
    }
  }, [bundles, selectedBundleId]);

  const filteredBundles = filter === 'all' ? bundles : bundles.filter((bundle) => (bundle.verdict?.verdict || 'unjudged') === filter);
  const selectedBundle = filteredBundles.find((bundle) => bundle.bundle_id === selectedBundleId) || filteredBundles[0] || null;

  if (!bundles.length) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No findings available for the selected scan." />;
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Segmented
        value={filter}
        onChange={setFilter}
        options={[
          { value: 'all', label: 'All findings' },
          { value: 'confirmed_leak', label: 'Confirmed' },
          { value: 'likely_leak', label: 'Likely' },
          { value: 'inconclusive', label: 'Inconclusive' },
          { value: 'false_positive', label: 'False positive' },
        ]}
      />

      <Row gutter={[16, 16]}>
        <Col xs={24} xxl={7}>
          <AppCard size="small" title="Findings">
            <List
              dataSource={filteredBundles}
              locale={{ emptyText: 'No findings match the current filter.' }}
              split={false}
              style={{ maxHeight: '72vh', overflow: 'auto' }}
              renderItem={(bundle) => {
                const candidate = bundle.candidate || {};
                const verdict = bundle.verdict || {};
                const active = selectedBundle?.bundle_id === bundle.bundle_id;

                return (
                  <List.Item style={{ paddingBlock: 0, paddingInline: 0, border: 0, marginBottom: 12 }}>
                    <AppCard
                      hoverable
                      size="small"
                      bodyGap={8}
                      onClick={() => setSelectedBundleId(bundle.bundle_id)}
                      style={{
                        width: '100%',
                        cursor: 'pointer',
                        borderColor: active ? token.colorPrimary : token.colorBorderSecondary,
                        background: active ? token.colorPrimaryBg : token.colorBgContainer,
                        boxShadow: active ? `0 0 0 1px ${token.colorPrimaryBorder}` : undefined,
                      }}
                    >
                      <Space direction="vertical" size={8} style={{ width: '100%' }}>
                        <Space wrap>
                          <Tag color={verdictTagColor(verdict.verdict)}>{verdict.verdict || 'unjudged'}</Tag>
                          <Tag>{verdict.confidence || candidate.confidence || 'n/a'}</Tag>
                        </Space>
                        <Text strong>{candidate.summary || bundle.bundle_id}</Text>
                        <Paragraph code style={{ marginBottom: 0 }}>
                          {formatLocation(candidate)}
                        </Paragraph>
                      </Space>
                    </AppCard>
                  </List.Item>
                );
              }}
            />
          </AppCard>
        </Col>

        <Col xs={24} xxl={17}>
          <FindingDetail bundle={selectedBundle} />
        </Col>
      </Row>
    </Space>
  );
}
