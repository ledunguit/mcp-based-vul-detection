import { useEffect, useMemo, useState } from 'react';
import { Empty, Flex, Input, Space, Tabs, Tag, Tree, Typography, theme } from 'antd';
import { Search, FileText, Code, Layers, Folder, FileCode } from 'lucide-react';

import { SuggestionDiffCard } from './SuggestionDiffCard';
import { formatLocation, verdictTagColor } from './reportFormat';
import { AppCard } from '../ui';

const { Paragraph, Text } = Typography;

function getVerdictColor(verdict, token) {
  if (verdict === 'confirmed_leak') return token.colorError;
  if (verdict === 'likely_leak') return token.colorWarning;
  if (verdict === 'false_positive') return token.colorSuccess;
  return token.colorPrimary;
}

function EvidenceCard({ evidence, index, token }) {
  return (
    <div
      style={{
        padding: '12px',
        borderRadius: token.borderRadiusSM,
        background: token.colorBgLayout,
        border: `1px solid ${token.colorBorderSecondary}`,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      <Space wrap size={4}>
        <Tag style={{ margin: 0 }}>#{index}</Tag>
        <Tag color="blue" style={{ margin: 0 }}>{evidence.tool || 'unknown-tool'}</Tag>
        <Tag style={{ margin: 0 }}>{evidence.kind || 'evidence'}</Tag>
        <Tag style={{ margin: 0 }}>{evidence.confidence || 'unknown'} confidence</Tag>
        <Tag color="warning" style={{ margin: 0 }}>{evidence.severity || 'unknown'} severity</Tag>
      </Space>
      <Paragraph style={{ marginBottom: 0, fontSize: 13 }}>{evidence.message || 'No evidence message.'}</Paragraph>
      {evidence.location ? (
        <Paragraph code style={{ marginBottom: 0, fontSize: 11 }}>
          {formatLocation(evidence.location)}
        </Paragraph>
      ) : null}
    </div>
  );
}

function getFindingId(finding) {
  return finding?.finding_id || finding?.bundle_id || null;
}

function FindingDetail({ finding }) {
  const { token } = theme.useToken();

  if (!finding) {
    return (
      <AppCard
        style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
        styles={{
          body: {
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }
        }}
      >
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Select a finding to inspect evidence and suggested patch." />
      </AppCard>
    );
  }

  const candidate = finding.candidate || {};
  const verdict = finding.verdict || {};
  const evidence = candidate.evidence || [];
  const suggestions = verdict.fix_suggestions || [];

  const tabItems = [
    {
      key: 'fix',
      label: (
        <Space size={6}>
          <Code size={14} />
          <span>Suggested Fix</span>
        </Space>
      ),
      style: { flex: 1, minHeight: 0, minWidth: 0, overflowY: 'auto', paddingRight: 8, paddingTop: 12 },
      children: (
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          {suggestions.length ? (
            suggestions.map((suggestion, index) => (
              <SuggestionDiffCard key={`${getFindingId(finding)}-suggestion-${index}`} suggestion={suggestion} />
            ))
          ) : (
            <div
              style={{
                padding: '32px 16px',
                borderRadius: token.borderRadius,
                background: token.colorBgContainer,
                border: `1px dashed ${token.colorBorder}`,
                textAlign: 'center',
              }}
            >
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No concrete fix suggestion was produced." />
            </div>
          )}
        </Space>
      ),
    },
    {
      key: 'explanation',
      label: (
        <Space size={6}>
          <FileText size={14} />
          <span>Analysis & Explanation</span>
        </Space>
      ),
      style: { flex: 1, minHeight: 0, minWidth: 0, overflowY: 'auto', paddingRight: 8, paddingTop: 12 },
      children: (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <div
            style={{
              padding: '16px',
              borderRadius: token.borderRadius,
              background: token.colorPrimaryBg,
              borderLeft: `4px solid ${token.colorPrimary}`,
            }}
          >
            <Text strong style={{ display: 'block', marginBottom: 6, color: token.colorPrimary, fontSize: 14 }}>
              Analysis Explanation
            </Text>
            <Paragraph style={{ marginBottom: 0, fontSize: 13, lineHeight: '1.6', color: token.colorText }}>
              {verdict.human_explanation || verdict.why || 'No explanation was produced.'}
            </Paragraph>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
            <div>
              <Text strong style={{ fontSize: 13, display: 'block', marginBottom: 8 }}>Path Constraints</Text>
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: token.borderRadiusSM,
                  background: token.colorBgContainer,
                  border: `1px solid ${token.colorBorderSecondary}`,
                }}
              >
                <Space wrap>
                  {(candidate.path_constraints || []).length ? (
                    candidate.path_constraints.map((item) => (
                      <Tag key={`${getFindingId(finding)}-${item}`} style={{ margin: 0 }}>
                        {item}
                      </Tag>
                    ))
                  ) : (
                    <Text type="secondary" style={{ fontSize: 13 }}>No path constraints recorded.</Text>
                  )}
                </Space>
              </div>
            </div>

            <div>
              <Text strong style={{ fontSize: 13, display: 'block', marginBottom: 8 }}>Missing Evidence</Text>
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: token.borderRadiusSM,
                  background: token.colorBgContainer,
                  border: `1px solid ${token.colorBorderSecondary}`,
                }}
              >
                <Space wrap>
                  {(verdict.missing_evidence || []).length ? (
                    verdict.missing_evidence.map((item) => (
                      <Tag key={`${getFindingId(finding)}-${item}`} color="orange" style={{ margin: 0 }}>
                        {item}
                      </Tag>
                    ))
                  ) : (
                    <Tag color="green" style={{ margin: 0 }}>None</Tag>
                  )}
                </Space>
              </div>
            </div>
          </div>
        </Space>
      ),
    },
    {
      key: 'evidence',
      label: (
        <Space size={6}>
          <Layers size={14} />
          <span>Supporting Evidence ({evidence.length})</span>
        </Space>
      ),
      style: { flex: 1, minHeight: 0, minWidth: 0, overflowY: 'auto', paddingRight: 8, paddingTop: 12 },
      children: (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <div>
            <Space direction="vertical" size={10} style={{ width: '100%' }}>
              {evidence.length ? (
                evidence.map((item, index) => (
                  <EvidenceCard key={`${getFindingId(finding)}-evidence-${index}`} evidence={item} index={index} token={token} />
                ))
              ) : (
                <div style={{ padding: 16, background: token.colorBgLayout, borderRadius: token.borderRadiusSM, textAlign: 'center', border: `1px dashed ${token.colorBorder}` }}>
                  <Text type="secondary">No evidence attached.</Text>
                </div>
              )}
            </Space>
          </div>

          {finding.orchestrator_notes?.length ? (
            <div>
              <Text strong style={{ fontSize: 13, display: 'block', marginBottom: 8 }}>Orchestrator Notes</Text>
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                {finding.orchestrator_notes.map((note, index) => (
                  <div
                    key={`${getFindingId(finding)}-note-${index}`}
                    style={{
                      padding: '10px 12px',
                      background: token.colorBgLayout,
                      border: `1px solid ${token.colorBorderSecondary}`,
                      borderRadius: token.borderRadiusSM,
                      fontSize: 13,
                    }}
                  >
                    {note}
                  </div>
                ))}
              </Space>
            </div>
          ) : null}
        </Space>
      ),
    },
  ];

  return (
    <AppCard
      title={
        <Space wrap size={8} style={{ paddingBlock: 4 }}>
          <Text strong style={{ fontSize: 16 }}>
            {candidate.summary || getFindingId(finding)}
          </Text>
          <Tag color={verdictTagColor(verdict.verdict)} style={{ margin: 0 }}>{verdict.verdict || 'unjudged'}</Tag>
          <Tag style={{ margin: 0 }}>{verdict.confidence || candidate.confidence || 'n/a'} confidence</Tag>
          <Tag color="blue" style={{ margin: 0 }}>{candidate.primary_tool || 'n/a'}</Tag>
        </Space>
      }
      style={{ height: '100%', display: 'flex', flexDirection: 'column', minWidth: 0 }}
      styles={{
        body: {
          flex: 1,
          minHeight: 0,
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
          paddingTop: 12,
        }
      }}
    >
      <Tabs
        defaultActiveKey="fix"
        className="detail-tabs"
        style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        items={tabItems}
      />
    </AppCard>
  );
}

function makeLeafNode(finding, selectedFindingId, token, label) {
  const candidate = finding.candidate || {};
  const findingId = getFindingId(finding);
  const isSelected = selectedFindingId === findingId;
  const color = getVerdictColor(finding.verdict?.verdict, token);
  const nodeLabel = label || `L${candidate.line || '?'}`;
  return {
    title: (
      <div className="report-findings-tree-label">
        <Text strong={isSelected} style={{ fontSize: 12, color: isSelected ? token.colorPrimary : token.colorText }}>
          {nodeLabel}
        </Text>
      </div>
    ),
    icon: <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />,
    key: findingId,
    isLeaf: true,
  };
}

function buildTreeData(findings, selectedFindingId, token, repoPath) {
  // Normalise repoPath: strip trailing slash
  const prefix = (repoPath || '').replace(/\/+$/, '');

  // Strip the host repo prefix so we show paths relative to the scanned workspace
  function relativise(absPath) {
    if (prefix && absPath.startsWith(prefix)) {
      return absPath.slice(prefix.length).replace(/^\/+/, '');
    }
    return absPath;
  }

  const root = { children: {}, files: {} };

  findings.forEach((finding) => {
    const candidate = finding.candidate || {};
    const absPath = candidate.file || 'unknown_file';
    const relPath = relativise(absPath);
    const parts = relPath.split('/').filter(Boolean);

    let current = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!current.children[part]) {
        current.children[part] = { children: {}, files: {} };
      }
      current = current.children[part];
    }

    const fileName = parts[parts.length - 1] || relPath;
    if (!current.files[fileName]) {
      current.files[fileName] = { path: relPath, actualPath: absPath, findings: [] };
    }
    current.files[fileName].findings.push(finding);
  });

  function buildFileNode(fileName, fileObj) {
    if (fileObj.findings.length === 1) {
      return {
        ...makeLeafNode(fileObj.findings[0], selectedFindingId, token, fileName),
        icon: <FileCode size={13} style={{ color: token.colorPrimary, flexShrink: 0 }} />,
      };
    }

    return {
      title: (
        <div className="report-findings-tree-label" style={{ gap: 8 }}>
          <Text style={{ fontSize: 13, fontWeight: 500 }}>{fileName}</Text>
          <Tag style={{ margin: 0, fontSize: 10, lineHeight: '16px', height: 18 }}>
            {fileObj.findings.length}
          </Tag>
        </div>
      ),
      icon: <FileCode size={13} style={{ color: token.colorPrimary, flexShrink: 0 }} />,
      key: fileObj.path,
      children: fileObj.findings.map((item) => makeLeafNode(item, selectedFindingId, token)),
      selectable: false,
    };
  }

  function convertNode(name, node, pathPrefix = '') {
    const currentPath = pathPrefix ? `${pathPrefix}/${name}` : name;

    const folderNodes = Object.keys(node.children).sort()
      .map((key) => convertNode(key, node.children[key], currentPath));

    const fileNodes = Object.keys(node.files).sort().map((key) => buildFileNode(key, node.files[key]));

    return {
      title: <Text style={{ fontSize: 13 }}>{name}</Text>,
      icon: <Folder size={13} style={{ color: '#fa8c16', flexShrink: 0 }} />,
      key: currentPath,
      children: [...folderNodes, ...fileNodes],
      selectable: false,
    };
  }

  const rootFolders = Object.keys(root.children).sort()
    .map((key) => convertNode(key, root.children[key]));

  const rootFiles = Object.keys(root.files).sort().map((key) => buildFileNode(key, root.files[key]));

  const children = [...rootFolders, ...rootFiles];
  if (!prefix) {
    return children;
  }

  return [
    {
      title: <div className="report-findings-tree-label"><Text style={{ fontSize: 13, fontWeight: 600 }}>{prefix.split('/').filter(Boolean).slice(-1)[0] || prefix}</Text></div>,
      icon: <Folder size={13} style={{ color: '#fa8c16', flexShrink: 0 }} />,
      key: prefix,
      children,
      selectable: false,
    },
  ];
}

export function FindingsView({ reportData }) {
  const repoPath = reportData?.repo_path || '';
  const findings = reportData?.findings || reportData?.bundles || [];
  const [filter, setFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState(getFindingId(findings[0]));
  const [expandedKeys, setExpandedKeys] = useState([]);
  const { token } = theme.useToken();

  const counts = {
    all: findings.length,
    confirmed_leak: findings.filter((item) => (item.verdict?.verdict || 'unjudged') === 'confirmed_leak').length,
    likely_leak: findings.filter((item) => (item.verdict?.verdict || 'unjudged') === 'likely_leak').length,
    inconclusive: findings.filter((item) => (item.verdict?.verdict || 'unjudged') === 'inconclusive').length,
    false_positive: findings.filter((item) => (item.verdict?.verdict || 'unjudged') === 'false_positive').length,
  };

  const filterOptions = [
    { value: 'all', label: 'All findings', color: token.colorPrimary, bg: token.colorPrimaryBg, count: counts.all },
    { value: 'confirmed_leak', label: 'Confirmed', color: token.colorError, bg: token.colorErrorBg, count: counts.confirmed_leak },
    { value: 'likely_leak', label: 'Likely', color: token.colorWarning, bg: token.colorWarningBg, count: counts.likely_leak },
    { value: 'inconclusive', label: 'Inconclusive', color: token.colorInfo, bg: token.colorInfoBg, count: counts.inconclusive },
    { value: 'false_positive', label: 'False positive', color: token.colorSuccess, bg: token.colorSuccessBg, count: counts.false_positive },
  ];

  const filteredFindings = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    return findings
      .filter((finding) => filter === 'all' || (finding.verdict?.verdict || 'unjudged') === filter)
      .filter((finding) => {
        const candidate = finding.candidate || {};
        const summary = (candidate.summary || '').toLowerCase();
        const file = (candidate.file || '').toLowerCase();
        return summary.includes(query) || file.includes(query);
      });
  }, [findings, filter, searchQuery]);

  const selectedFinding = filteredFindings.find((finding) => getFindingId(finding) === selectedFindingId) || filteredFindings[0] || null;

  useEffect(() => {
    if (!findings.length) {
      setSelectedFindingId(null);
      return;
    }
    if (filteredFindings.length && !filteredFindings.some((finding) => getFindingId(finding) === selectedFindingId)) {
      setSelectedFindingId(getFindingId(filteredFindings[0]));
      return;
    }
    if (!findings.some((finding) => getFindingId(finding) === selectedFindingId)) {
      setSelectedFindingId(getFindingId(findings[0]));
    }
  }, [findings, filteredFindings, selectedFindingId]);

  const treeData = useMemo(() => {
    return buildTreeData(filteredFindings, selectedFindingId, token, repoPath);
  }, [filteredFindings, selectedFindingId, token, repoPath]);

  function getAllKeys(nodes) {
    let keys = [];
    nodes.forEach((node) => {
      if (node.children) {
        keys.push(node.key);
        keys = keys.concat(getAllKeys(node.children));
      }
    });
    return keys;
  }

  const defaultExpandedKeys = useMemo(() => getAllKeys(treeData), [treeData]);

  useEffect(() => {
    setExpandedKeys((current) => {
      if (
        current.length === defaultExpandedKeys.length
        && current.every((key, index) => key === defaultExpandedKeys[index])
      ) {
        return current;
      }
      return defaultExpandedKeys;
    });
  }, [defaultExpandedKeys]);

  if (!findings.length) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No findings available for the selected scan." />;
  }

  return (
    <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ flexShrink: 0 }}>
        <Flex gap={8} wrap="wrap">
          {filterOptions.map((opt) => {
            const active = filter === opt.value;
            return (
              <div
                key={opt.value}
                onClick={() => setFilter(opt.value)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  padding: '6px 12px',
                  borderRadius: 999,
                  border: `1px solid ${active ? opt.color : token.colorBorderSecondary}`,
                  background: active ? opt.bg : token.colorBgContainer,
                  color: active ? opt.color : token.colorTextSecondary,
                  cursor: 'pointer',
                  fontWeight: active ? 600 : 400,
                  fontSize: 13,
                  transition: 'all 0.2s ease',
                  userSelect: 'none',
                }}
                onMouseEnter={(e) => {
                  if (!active) {
                    e.currentTarget.style.borderColor = opt.color;
                    e.currentTarget.style.color = opt.color;
                  }
                }}
                onMouseLeave={(e) => {
                  if (!active) {
                    e.currentTarget.style.borderColor = token.colorBorderSecondary;
                    e.currentTarget.style.color = token.colorTextSecondary;
                  }
                }}
              >
                <span>{opt.label}</span>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    minWidth: 20,
                    height: 20,
                    borderRadius: '50%',
                    fontSize: 10,
                    padding: '0 5px',
                    background: active ? opt.color : token.colorBgLayout,
                    color: active ? '#fff' : token.colorTextSecondary,
                    marginLeft: 6,
                    fontWeight: 'bold',
                    transition: 'all 0.2s ease',
                  }}
                >
                  {opt.count}
                </span>
              </div>
            );
          })}
        </Flex>
      </div>


      <div style={{ flex: 1, minHeight: 0, display: 'flex', gap: 16 }}>
        {/* Left Side: Findings Explorer (Tree) */}
        <div style={{ width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', height: '100%' }}>
          <AppCard
            size="small"
            title={`Findings Explorer`}
            style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
            styles={{
              body: {
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
                paddingTop: 12,
              }
            }}
          >
            {/* Quick Search */}
            <Input
              prefix={<Search size={14} style={{ opacity: 0.5, marginRight: 4 }} />}
              placeholder="Search by file or summary..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              allowClear
              style={{ marginBottom: 12 }}
            />

            {/* Tree Explorer */}
            <div style={{ flex: 1, overflowY: 'auto', paddingRight: 4 }}>
              <Tree
                className="report-findings-tree"
                treeData={treeData}
                selectedKeys={selectedFindingId ? [selectedFindingId] : []}
                expandedKeys={expandedKeys}
                onExpand={setExpandedKeys}
                onSelect={(selectedKeys, info) => {
                  if (selectedKeys.length > 0 && info.node.isLeaf) {
                    setSelectedFindingId(selectedKeys[0]);
                  }
                }}
                showIcon
                blockNode
                style={{ background: 'transparent' }}
              />
            </div>
          </AppCard>
        </div>

        {/* Right Side: Diagnostic Workspace */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', height: '100%' }}>
          <FindingDetail finding={selectedFinding} />
        </div>
      </div>
    </div>
  );
}
