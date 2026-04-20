import { useNavigate } from 'react-router-dom';

import { useConsoleContext } from '../layouts/AppLayout';
import { describeEvent } from '../utils/ui';

export function useActivityPageActions() {
  const navigate = useNavigate();
  const consoleState = useConsoleContext();

  async function handleSelectScan(scan) {
    const result = await consoleState.openScan(scan.scan_id, scan);
    if (result) {
      navigate('/activity');
    }
  }

  return {
    consoleState,
    handleSelectScan,
    handleRefreshHistory: () => consoleState.loadRecentScans().catch(() => undefined),
    handleCancelScan: () => consoleState.cancelScan(),
    handleRequestDeleteScan: (scan) => consoleState.requestDeleteScan(scan),
    handleRequestDeleteTerminalScans: () => consoleState.requestDeleteTerminalScans(),
    handleCloseDeleteDialog: () => consoleState.closeDeleteDialog(),
    handleConfirmDeleteDialog: () => consoleState.confirmDeleteDialog(),
    handleOpenReport: () => navigate('/report'),
    handleReloadLog: () =>
      consoleState.selectedScan
        ? consoleState.loadEventHistory(consoleState.selectedScan.scan_id).catch(() => undefined)
        : undefined,
    handleExportLog: () => consoleState.exportLog(describeEvent),
    formatEvent: describeEvent,
  };
}
