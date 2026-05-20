import { ReportControlsCard } from '../components/ReportControlsCard';
import { useReportPageActions } from '../handlers/useReportPageActions';

export function ReportPage() {
  const { consoleState, handleReloadStructured, handleLoadReport, handleOpenHtml } = useReportPageActions();

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <ReportControlsCard
        selectedScan={consoleState.selectedScan}
        reportData={consoleState.reportData}
        reportText={consoleState.reportText}
        onReloadStructured={handleReloadStructured}
        onLoadReport={handleLoadReport}
        onOpenHtml={handleOpenHtml}
      />
    </div>
  );
}
