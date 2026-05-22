import { useNavigate, useParams } from 'react-router-dom';

import { useConsoleContext } from '../layouts/AppLayout';

export function useReportPageActions() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const consoleState = useConsoleContext();
  const activeScanId = scanId || consoleState.selectedScan?.scan_id;

  return {
    consoleState,
    handleReloadStructured: () =>
      activeScanId
        ? consoleState.loadStructuredReport(activeScanId).catch(() => undefined)
        : undefined,
    handleLoadReport: (format) =>
      activeScanId
        ? consoleState.loadReport(activeScanId, format).catch(() => undefined)
        : undefined,
    handleOpenHtml: () =>
      activeScanId
        ? window.open(`/api/scans/${activeScanId}/report?format=html`, '_blank', 'noopener,noreferrer')
        : undefined,
    handleOpenActivity: () => navigate(activeScanId ? `/activity/${activeScanId}` : '/activity'),
  };
}
