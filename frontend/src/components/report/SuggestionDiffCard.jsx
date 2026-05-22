import { Collapse, Typography, theme } from 'antd';

const { Text } = Typography;

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
        minWidth: 0,
      }}
    >
      <div style={{ borderBottom: `1px solid ${tone.border}`, padding: '10px 14px' }}>
        <Text strong>{title}</Text>
      </div>
      {rows.length ? (
        <div style={{ overflow: 'auto', maxHeight: 280 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed', fontFamily: 'SFMono-Regular, Consolas, Menlo, monospace', fontSize: 13 }}>
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
    <div
      style={{
        padding: '16px',
        borderRadius: token.borderRadius,
        border: `1px solid ${token.colorBorderSecondary}`,
        background: token.colorBgContainer,
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
        minWidth: 0,
      }}
    >
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
        }}
      >
        <Text strong style={{ fontSize: 14, lineHeight: 1.5 }}>{suggestion.summary}</Text>
        <div
          style={{
            padding: '12px 14px',
            borderRadius: token.borderRadiusSM,
            background: token.colorBgLayout,
            border: `1px solid ${token.colorBorderSecondary}`,
            minWidth: 0,
          }}
        >
          <Text strong style={{ display: 'block', fontSize: 12, marginBottom: 6 }}>
            Why this change
          </Text>
          <Text style={{ fontSize: 13, lineHeight: 1.7, color: token.colorText }}>
            {suggestion.rationale}
          </Text>
        </div>
      </div>

      {suggestion.code_change_hint ? (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: token.borderRadiusSM,
            background: token.colorBgLayout,
            border: `1px solid ${token.colorBorderSecondary}`,
            minWidth: 0,
          }}
        >
          <Text strong style={{ display: 'block', fontSize: 12, marginBottom: 6 }}>Recommended change</Text>
          <Text style={{ fontSize: 13 }}>{suggestion.code_change_hint}</Text>
        </div>
      ) : null}

      {suggestion.before_snippet || suggestion.after_snippet ? (
        <div style={{ display: 'grid', gap: 12, gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', minWidth: 0 }}>
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
                <div
                  style={{
                    padding: '12px',
                    borderRadius: token.borderRadiusSM,
                    background: token.colorBgLayout,
                    border: `1px solid ${token.colorBorderSecondary}`,
                    overflow: 'auto',
                    maxHeight: 320,
                    minWidth: 0,
                  }}
                >
                  {suggestion.unified_diff.split('\n').map((line, index) => (
                    <pre
                      key={`${suggestion.summary}-${index}`}
                      style={{
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                        overflowWrap: 'anywhere',
                        fontFamily: 'SFMono-Regular, Consolas, Menlo, monospace',
                        fontSize: 12,
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
                </div>
              ),
            },
          ]}
        />
      ) : null}
    </div>
  );
}
