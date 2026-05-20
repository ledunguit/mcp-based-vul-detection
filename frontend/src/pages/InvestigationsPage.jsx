import { ConfirmDeletionModal } from '../components/ConfirmDeletionModal';
import { ScanHistoryList } from '../components/ScanHistoryList';
import { useActivityPageActions } from '../handlers/useActivityPageActions';

export function InvestigationsPage() {
  const {
    consoleState,
    handleSelectScan,
    handleRefreshHistory,
    handleRequestDeleteScan,
    handleRequestDeleteTerminalScans,
    handleCloseDeleteDialog,
    handleConfirmDeleteDialog,
  } = useActivityPageActions();

  return (
    <>
      <ScanHistoryList
        standalone
        recentScans={consoleState.recentScans}
        selectedScanId={consoleState.selectedScan?.scan_id}
        terminalScanCount={consoleState.terminalScans.length}
        deletingScans={consoleState.deletingScans}
        onRefresh={handleRefreshHistory}
        onSelectScan={handleSelectScan}
        onRequestDeleteScan={handleRequestDeleteScan}
        onRequestDeleteTerminalScans={handleRequestDeleteTerminalScans}
      />

      <ConfirmDeletionModal
        dialog={consoleState.deleteDialog}
        busy={consoleState.deletingScans}
        onClose={handleCloseDeleteDialog}
        onConfirm={handleConfirmDeleteDialog}
      />
    </>
  );
}
