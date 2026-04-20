import { useConsoleContext } from '../layouts/AppLayout';

export function useReportPageActions() {
  const consoleState = useConsoleContext();

  return {
    consoleState,
    handleReloadStructured: () =>
      consoleState.selectedScan
        ? consoleState.loadStructuredReport(consoleState.selectedScan.scan_id).catch(() => undefined)
        : undefined,
    handleLoadReport: (format) =>
      consoleState.selectedScan
        ? consoleState.loadReport(consoleState.selectedScan.scan_id, format).catch(() => undefined)
        : undefined,
    handleOpenHtml: () =>
      consoleState.selectedScan
        ? window.open(`/api/scans/${consoleState.selectedScan.scan_id}/report?format=html`, '_blank', 'noopener,noreferrer')
        : undefined,
  };
}
