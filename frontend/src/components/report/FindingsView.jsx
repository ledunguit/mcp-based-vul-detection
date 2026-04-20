import { useEffect, useState } from 'react';

import { SuggestionDiffCard } from './SuggestionDiffCard';
import { formatLocation, verdictBadgeClass } from './reportFormat';

function EvidenceCard({ evidence, index }) {
  return (
    <div className="rounded-box border border-base-300 bg-base-100/80 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="badge badge-outline">#{index}</span>
        <span className="badge badge-primary badge-soft">{evidence.tool || 'unknown-tool'}</span>
        <span className="badge badge-outline">{evidence.kind || 'evidence'}</span>
        <span className="badge badge-outline">{evidence.confidence || 'unknown'} confidence</span>
        <span className="badge badge-outline">{evidence.severity || 'unknown'} severity</span>
      </div>
      <p className="mt-3 text-sm leading-7 text-base-content/80">{evidence.message || 'No evidence message.'}</p>
      {evidence.location ? <p className="mt-2 font-mono text-xs text-base-content/60">{formatLocation(evidence.location)}</p> : null}
    </div>
  );
}

function FindingDetail({ bundle }) {
  if (!bundle) {
    return (
      <div className="rounded-box border border-dashed border-base-300 p-6 text-sm text-base-content/60">
        Select a finding to inspect evidence and suggested patch.
      </div>
    );
  }

  const candidate = bundle.candidate || {};
  const verdict = bundle.verdict || {};
  const evidence = candidate.evidence || [];
  const suggestions = verdict.fix_suggestions || [];

  return (
    <div className="card border border-base-300 bg-base-100 shadow-lg">
      <div className="card-body gap-5">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-2xl font-bold">{candidate.summary || bundle.bundle_id}</h3>
              <span className={verdictBadgeClass(verdict.verdict)}>{verdict.verdict || 'unjudged'}</span>
              <span className="badge badge-outline">{verdict.confidence || candidate.confidence || 'n/a'} confidence</span>
              <span className="badge badge-outline">{candidate.primary_tool || 'n/a'}</span>
            </div>
            <p className="text-sm leading-7 text-base-content/80">
              {verdict.human_explanation || verdict.why || 'No explanation was produced.'}
            </p>
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <div className="rounded-box border border-base-300 bg-base-200/50 p-4">
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Candidate</p>
            <p className="mt-2 font-mono text-xs">{formatLocation(candidate)}</p>
          </div>
          <div className="rounded-box border border-base-300 bg-base-200/50 p-4">
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Allocation Site</p>
            <p className="mt-2 font-mono text-xs">{formatLocation(candidate.allocation_site)}</p>
          </div>
          <div className="rounded-box border border-base-300 bg-base-200/50 p-4">
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Missing Cleanup Site</p>
            <p className="mt-2 font-mono text-xs">{formatLocation(candidate.missing_free_site)}</p>
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr),minmax(20rem,0.9fr)]">
          <div className="space-y-3">
            <div>
              <p className="mb-2 text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Supporting Evidence</p>
              <div className="grid gap-3">
                {evidence.length ? (
                  evidence.map((item, index) => <EvidenceCard key={`${bundle.bundle_id}-evidence-${index}`} evidence={item} index={index} />)
                ) : (
                  <div className="rounded-box border border-dashed border-base-300 p-4 text-sm text-base-content/60">
                    No evidence attached.
                  </div>
                )}
              </div>
            </div>

            {bundle.orchestrator_notes?.length ? (
              <div>
                <p className="mb-2 text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Orchestrator Notes</p>
                <div className="space-y-2">
                  {bundle.orchestrator_notes.map((note, index) => (
                    <div key={`${bundle.bundle_id}-note-${index}`} className="rounded-box border border-base-300 bg-base-100/70 px-4 py-3 text-sm">
                      {note}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>

          <div className="space-y-4">
            <div className="rounded-box border border-base-300 bg-base-200/40 p-4">
              <p className="text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Missing Evidence</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {(verdict.missing_evidence || []).length ? (
                  verdict.missing_evidence.map((item) => (
                    <span key={`${bundle.bundle_id}-${item}`} className="badge badge-warning badge-outline">
                      {item}
                    </span>
                  ))
                ) : (
                  <span className="badge badge-success badge-outline">None</span>
                )}
              </div>
            </div>

            <div className="rounded-box border border-base-300 bg-base-200/40 p-4">
              <p className="text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Path Constraints</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {(candidate.path_constraints || []).length ? (
                  candidate.path_constraints.map((item) => (
                    <span key={`${bundle.bundle_id}-${item}`} className="badge badge-outline">
                      {item}
                    </span>
                  ))
                ) : (
                  <span className="text-sm text-base-content/60">No path constraints recorded.</span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-3">
          <p className="text-xs font-bold uppercase tracking-[0.2em] text-base-content/45">Suggested Fix</p>
          {suggestions.length ? (
            suggestions.map((suggestion, index) => (
              <SuggestionDiffCard key={`${bundle.bundle_id}-suggestion-${index}`} suggestion={suggestion} />
            ))
          ) : (
            <div className="rounded-box border border-dashed border-base-300 p-4 text-sm text-base-content/60">
              No concrete fix suggestion was produced.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function FindingsView({ reportData }) {
  const bundles = reportData?.bundles || [];
  const [filter, setFilter] = useState('all');
  const [selectedBundleId, setSelectedBundleId] = useState(bundles[0]?.bundle_id || null);

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
    return (
      <div className="rounded-box border border-dashed border-base-300 p-6 text-sm text-base-content/60">
        No findings available for the selected scan.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2">
        {[
          ['all', 'All findings'],
          ['confirmed_leak', 'Confirmed'],
          ['likely_leak', 'Likely'],
          ['inconclusive', 'Inconclusive'],
          ['false_positive', 'False positive'],
        ].map(([value, label]) => (
          <button
            key={value}
            type="button"
            className={`btn btn-sm ${filter === value ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setFilter(value)}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-[22rem,minmax(0,1fr)]">
        <div className="card border border-base-300 bg-base-100 shadow-sm">
          <div className="card-body gap-3">
            <div>
              <h3 className="card-title text-lg">Findings</h3>
              <p className="text-sm text-base-content/60">Chọn một finding để xem evidence và gợi ý sửa ở dạng patch.</p>
            </div>
            <div className="flex max-h-[72vh] flex-col gap-3 overflow-auto pr-1">
              {filteredBundles.length ? (
                filteredBundles.map((bundle) => {
                  const candidate = bundle.candidate || {};
                  const verdict = bundle.verdict || {};
                  const active = selectedBundle?.bundle_id === bundle.bundle_id;
                  return (
                    <button
                      key={bundle.bundle_id}
                      type="button"
                      className={`rounded-box border p-4 text-left transition ${
                        active
                          ? 'border-primary bg-primary/10 shadow-sm'
                          : 'border-base-300 bg-base-200/40 hover:border-primary/40 hover:bg-base-200/70'
                      }`}
                      onClick={() => setSelectedBundleId(bundle.bundle_id)}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={verdictBadgeClass(verdict.verdict)}>{verdict.verdict || 'unjudged'}</span>
                        <span className="badge badge-outline">{verdict.confidence || candidate.confidence || 'n/a'}</span>
                      </div>
                      <p className="mt-3 font-semibold">{candidate.summary || bundle.bundle_id}</p>
                      <p className="mt-2 font-mono text-xs text-base-content/60">{formatLocation(candidate)}</p>
                    </button>
                  );
                })
              ) : (
                <div className="rounded-box border border-dashed border-base-300 p-4 text-sm text-base-content/60">
                  No findings match the current filter.
                </div>
              )}
            </div>
          </div>
        </div>

        <FindingDetail bundle={selectedBundle} />
      </div>
    </div>
  );
}
