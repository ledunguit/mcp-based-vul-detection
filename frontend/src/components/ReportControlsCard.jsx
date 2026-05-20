import { useState } from 'react';
import { Button, Empty, Space, Tabs, Typography } from 'antd';

import { FindingsView } from './report/FindingsView';
import { OverviewView } from './report/OverviewView';
import { AppCard } from './ui';

const { Paragraph } = Typography;

export function ReportControlsCard({ selectedScan, reportData, reportText, onReloadStructured, onLoadReport, onOpenHtml }) {
  const [activeTab, setActiveTab] = useState('findings');

  return (
    <AppCard
      title="Report"
      extra={
        <Space wrap>
          <Button onClick={onReloadStructured} disabled={!selectedScan}>
            Refresh Structured
          </Button>
          <Button
            onClick={() => {
              setActiveTab('raw');
              onLoadReport('markdown');
            }}
            disabled={!selectedScan}
          >
            Markdown
          </Button>
          <Button
            onClick={() => {
              setActiveTab('raw');
              onLoadReport('json');
            }}
            disabled={!selectedScan}
          >
            JSON
          </Button>
          <Button
            onClick={() => {
              setActiveTab('raw');
              onLoadReport('snapshot');
            }}
            disabled={!selectedScan}
          >
            Snapshot
          </Button>
          <Button onClick={onOpenHtml} disabled={!selectedScan}>
            HTML
          </Button>
        </Space>
      }
    >
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'overview',
            label: 'Overview',
            children: <OverviewView selectedScan={selectedScan} reportData={reportData} />,
          },
          {
            key: 'findings',
            label: 'Findings',
            children: <FindingsView reportData={reportData} />,
          },
          {
            key: 'raw',
            label: 'Raw Output',
            children: selectedScan ? (
              <AppCard size="small" bodyGap={0}>
                <Paragraph
                  style={{
                    marginBottom: 0,
                    whiteSpace: 'pre-wrap',
                    overflowWrap: 'anywhere',
                    fontFamily: 'SFMono-Regular, Consolas, Menlo, monospace',
                  }}
                >
                  {reportText}
                </Paragraph>
              </AppCard>
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Select a scan to load raw report output." />
            ),
          },
        ]}
      />
    </AppCard>
  );
}
