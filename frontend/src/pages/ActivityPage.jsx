import { ConfirmDeletionModal } from '../components/ConfirmDeletionModal';
import { ExecutionStatusCard } from '../components/ExecutionStatusCard';
import { ScanHistoryList } from '../components/ScanHistoryList';
import { TerminalLogCard } from '../components/TerminalLogCard';
import { useActivityPageActions } from '../handlers/useActivityPageActions';

export function ActivityPage() {
  const {
    consoleState,
    handleSelectScan,
    handleRefreshHistory,
    handleCancelScan,
    handleRequestDeleteScan,
    handleRequestDeleteTerminalScans,
    handleCloseDeleteDialog,
    handleConfirmDeleteDialog,
    handleOpenReport,
    handleReloadLog,
    handleExportLog,
    formatEvent,
  } = useActivityPageActions();

  return (
    <section className="grid gap-4 xl:grid-cols-[minmax(20rem,22rem)_minmax(0,1fr)]">
      <ScanHistoryList
        recentScans={consoleState.recentScans}
        selectedScanId={consoleState.selectedScan?.scan_id}
        terminalScanCount={consoleState.terminalScans.length}
        deletingScans={consoleState.deletingScans}
        onRefresh={handleRefreshHistory}
        onSelectScan={handleSelectScan}
        onRequestDeleteScan={handleRequestDeleteScan}
        onRequestDeleteTerminalScans={handleRequestDeleteTerminalScans}
      />

      <div className="flex flex-col gap-4">
        <ExecutionStatusCard
          selectedScan={consoleState.selectedScan}
          lastEvent={consoleState.lastEvent}
          activeScan={consoleState.activeScan}
          onCancel={handleCancelScan}
          onOpenReport={handleOpenReport}
        />
        <TerminalLogCard
          selectedScan={consoleState.selectedScan}
          loadingScan={consoleState.loadingScan}
          deferredEvents={consoleState.deferredEvents}
          terminalRef={consoleState.terminalRef}
          onReload={handleReloadLog}
          onExport={handleExportLog}
          formatEvent={formatEvent}
        />
      </div>
      <ConfirmDeletionModal
        dialog={consoleState.deleteDialog}
        busy={consoleState.deletingScans}
        onClose={handleCloseDeleteDialog}
        onConfirm={handleConfirmDeleteDialog}
      />
    </section>
  );
}
