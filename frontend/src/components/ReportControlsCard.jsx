import { useState } from 'react';

import { FindingsView } from './report/FindingsView';
import { OverviewView } from './report/OverviewView';

export function ReportControlsCard({ selectedScan, reportData, reportText, onReloadStructured, onLoadReport, onOpenHtml }) {
  const [activeTab, setActiveTab] = useState('findings');

  return (
    <div className="card border border-base-300 bg-base-100 shadow-xl">
      <div className="card-body gap-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h2 className="card-title text-2xl">Report</h2>
            <p className="text-sm text-base-content/65">Structured findings first, raw report formats only when you need them.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn btn-outline" onClick={onReloadStructured} disabled={!selectedScan}>
              Refresh Structured
            </button>
            <button
              type="button"
              className="btn btn-outline"
              onClick={() => {
                setActiveTab('raw');
                onLoadReport('markdown');
              }}
              disabled={!selectedScan}
            >
              Markdown
            </button>
            <button
              type="button"
              className="btn btn-outline"
              onClick={() => {
                setActiveTab('raw');
                onLoadReport('json');
              }}
              disabled={!selectedScan}
            >
              JSON
            </button>
            <button
              type="button"
              className="btn btn-outline"
              onClick={() => {
                setActiveTab('raw');
                onLoadReport('snapshot');
              }}
              disabled={!selectedScan}
            >
              Snapshot
            </button>
            <button type="button" className="btn btn-outline" onClick={onOpenHtml} disabled={!selectedScan}>
              HTML
            </button>
          </div>
        </div>

        <div className="tabs tabs-boxed w-full bg-base-200/60 p-1">
          <button type="button" className={`tab flex-1 ${activeTab === 'overview' ? 'tab-active' : ''}`} onClick={() => setActiveTab('overview')}>
            Overview
          </button>
          <button type="button" className={`tab flex-1 ${activeTab === 'findings' ? 'tab-active' : ''}`} onClick={() => setActiveTab('findings')}>
            Findings
          </button>
          <button type="button" className={`tab flex-1 ${activeTab === 'raw' ? 'tab-active' : ''}`} onClick={() => setActiveTab('raw')}>
            Raw Output
          </button>
        </div>

        {activeTab === 'overview' ? <OverviewView selectedScan={selectedScan} reportData={reportData} /> : null}
        {activeTab === 'findings' ? <FindingsView reportData={reportData} /> : null}
        {activeTab === 'raw' ? (
          <div className="mockup-window border border-base-300 bg-base-200/50 shadow-inner">
            <div className="min-h-[28rem] overflow-auto p-5">
              <pre className="whitespace-pre-wrap break-words text-sm leading-7 text-base-content">{reportText}</pre>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
