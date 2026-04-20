import { formatLocation } from './reportFormat';

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
    <div className={`rounded-box border p-0 ${tone}`}>
      <div className="border-b border-current/20 px-4 py-3">
        <p className="text-xs font-bold uppercase tracking-[0.2em]">{title}</p>
      </div>
      {rows.length ? (
        <div className="overflow-auto">
          <table className="table table-pin-rows table-sm">
            <tbody>
              {rows.map((row) => (
                <tr key={`${title}-${row.number}-${row.content}`} className="border-none">
                  <td className="w-16 align-top font-mono text-xs opacity-60">{row.number}</td>
                  <td className="whitespace-pre-wrap break-words font-mono text-sm leading-6">{row.content || ' '}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="px-4 py-5 text-sm opacity-70">No code preview available.</div>
      )}
    </div>
  );
}

export function SuggestionDiffCard({ suggestion }) {
  return (
    <div className="rounded-box border border-base-300 bg-base-200/50 p-4">
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-2 xl:flex-row xl:items-start xl:justify-between">
          <div className="space-y-2">
            <p className="font-semibold">{suggestion.summary}</p>
            <p className="text-sm text-base-content/70">{suggestion.rationale}</p>
          </div>
          {suggestion.target_location ? (
            <div className="rounded-box border border-primary/20 bg-primary/8 px-3 py-2 text-right">
              <p className="text-xs font-bold uppercase tracking-[0.2em] text-primary">Patch Target</p>
              <p className="mt-1 font-mono text-xs">{formatLocation(suggestion.target_location)}</p>
            </div>
          ) : null}
        </div>

        {suggestion.code_change_hint ? (
          <div className="rounded-box border border-base-300 bg-base-100/70 px-4 py-3 text-sm text-base-content/75">
            {suggestion.code_change_hint}
          </div>
        ) : null}

        {suggestion.before_snippet || suggestion.after_snippet ? (
          <div className="grid gap-3 xl:grid-cols-2">
            <SnippetPanel
              title="Current"
              tone="border-error/25 bg-error/6 text-base-content"
              snippet={suggestion.before_snippet}
              startLine={suggestion.before_start_line || suggestion.target_location?.line || 1}
            />
            <SnippetPanel
              title="Proposed"
              tone="border-success/25 bg-success/6 text-base-content"
              snippet={suggestion.after_snippet}
              startLine={suggestion.after_start_line || suggestion.target_location?.line || 1}
            />
          </div>
        ) : null}

        {suggestion.unified_diff ? (
          <details className="collapse collapse-arrow border border-base-300 bg-base-100/70">
            <summary className="collapse-title text-sm font-semibold">Unified diff</summary>
            <div className="collapse-content">
              <div className="mockup-code bg-base-300/70 shadow-inner">
                {suggestion.unified_diff.split('\n').map((line, index) => (
                  <pre
                    key={`${suggestion.summary}-${index}`}
                    data-prefix={line.startsWith('+') ? '+' : line.startsWith('-') ? '-' : ' '}
                    className={
                      line.startsWith('+')
                        ? 'text-success'
                        : line.startsWith('-')
                          ? 'text-error'
                          : 'text-base-content/70'
                    }
                  >
                    <code>{line}</code>
                  </pre>
                ))}
              </div>
            </div>
          </details>
        ) : null}
      </div>
    </div>
  );
}
