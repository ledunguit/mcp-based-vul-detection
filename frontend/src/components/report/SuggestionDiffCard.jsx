import { Collapse, Space, Tag, Typography, theme } from 'antd';

import { formatLocation } from './reportFormat';
import { AppCard } from '../ui';

const { Paragraph, Text } = Typography;

function buildSnippetRows(snippet, startLine) {
  if (!snippet) {
    return [];
  }

  return snippet.split('\n').map((content, index) => ({
    number: (startLine || 1) + index,
    content,
  }));
}

function SnippetPanel({ title, tone, snippet, startLine }) {
  const rows = buildSnippetRows(snippet, startLine);

  return (
    <div
      style={{
        border: `1px solid ${tone.border}`,
        background: tone.background,
        borderRadius: 12,
        overflow: 'hidden',
      }}
    >
      <div style={{ borderBottom: `1px solid ${tone.border}`, padding: '10px 14px' }}>
        <Text strong>{title}</Text>
      </div>
      {rows.length ? (
        <div style={{ overflow: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'SFMono-Regular, Consolas, Menlo, monospace', fontSize: 13 }}>
            <tbody>
              {rows.map((row) => (
                <tr key={`${title}-${row.number}-${row.content}`}>
                  <td style={{ width: 56, padding: '8px 12px', verticalAlign: 'top', opacity: 0.6 }}>{row.number}</td>
                  <td style={{ padding: '8px 12px', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{row.content || ' '}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ padding: '14px 16px' }}>
          <Text type="secondary">No code preview available.</Text>
        </div>
      )}
    </div>
  );
}

export function SuggestionDiffCard({ suggestion }) {
  const { token } = theme.useToken();

  return (
    <AppCard size="small" bodyGap={16}>
      <Space align="start" justify="space-between" style={{ width: '100%' }} wrap>
        <Space direction="vertical" size={8} style={{ maxWidth: '100%' }}>
          <Text strong>{suggestion.summary}</Text>
          <Text type="secondary">{suggestion.rationale}</Text>
        </Space>

        {suggestion.target_location ? (
          <AppCard
            size="small"
            bodyGap={4}
            style={{
              background: token.colorPrimaryBg,
              borderColor: token.colorPrimaryBorder,
              minWidth: 180,
            }}
          >
            <Space direction="vertical" size={4}>
              <Tag color="processing">Patch Target</Tag>
              <Paragraph code style={{ marginBottom: 0 }}>
                {formatLocation(suggestion.target_location)}
              </Paragraph>
            </Space>
          </AppCard>
        ) : null}
      </Space>

      {suggestion.code_change_hint ? (
        <AppCard size="small" bodyGap={0}>
          <Text>{suggestion.code_change_hint}</Text>
        </AppCard>
      ) : null}

      {suggestion.before_snippet || suggestion.after_snippet ? (
        <div style={{ display: 'grid', gap: 12, gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
          <SnippetPanel
            title="Current"
            tone={{ border: token.colorErrorBorder, background: token.colorErrorBg }}
            snippet={suggestion.before_snippet}
            startLine={suggestion.before_start_line || suggestion.target_location?.line || 1}
          />
          <SnippetPanel
            title="Proposed"
            tone={{ border: token.colorSuccessBorder, background: token.colorSuccessBg }}
            snippet={suggestion.after_snippet}
            startLine={suggestion.after_start_line || suggestion.target_location?.line || 1}
          />
        </div>
      ) : null}

      {suggestion.unified_diff ? (
        <Collapse
          ghost
          items={[
            {
              key: 'diff',
              label: 'Unified diff',
              children: (
                <AppCard size="small" bodyGap={0} style={{ background: token.colorBgLayout }}>
                  {suggestion.unified_diff.split('\n').map((line, index) => (
                    <pre
                      key={`${suggestion.summary}-${index}`}
                      style={{
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                        overflowWrap: 'anywhere',
                        fontFamily: 'SFMono-Regular, Consolas, Menlo, monospace',
                        color: line.startsWith('+')
                          ? token.colorSuccessText
                          : line.startsWith('-')
                            ? token.colorErrorText
                            : token.colorTextSecondary,
                      }}
                    >
                      {line}
                    </pre>
                  ))}
                </AppCard>
              ),
            },
          ]}
        />
      ) : null}
    </AppCard>
  );
}
