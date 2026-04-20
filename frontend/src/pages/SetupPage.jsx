import { ExpectedFlowCard } from '../components/ExpectedFlowCard';
import { SetupForm } from '../components/SetupForm';
import { TargetSnapshotCard } from '../components/TargetSnapshotCard';
import { useSetupPageActions } from '../handlers/useSetupPageActions';

export function SetupPage() {
  const { consoleState, handleStartScan, handleGoActivity } = useSetupPageActions();

  return (
    <section className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(20rem,0.85fr)]">
      <SetupForm
        loadingWorkspaces={consoleState.loadingWorkspaces}
        workspaces={consoleState.workspaces}
        workspacePath={consoleState.workspacePath}
        setWorkspacePath={consoleState.setWorkspacePath}
        allowedRoots={consoleState.allowedRoots}
        customPath={consoleState.customPath}
        setCustomPath={consoleState.setCustomPath}
        analysisMode={consoleState.analysisMode}
        setAnalysisMode={consoleState.setAnalysisMode}
        fileLimit={consoleState.fileLimit}
        setFileLimit={consoleState.setFileLimit}
        buildCommand={consoleState.buildCommand}
        setBuildCommand={consoleState.setBuildCommand}
        dynamicRunIds={consoleState.dynamicRunIds}
        setDynamicRunIds={consoleState.setDynamicRunIds}
        activeScan={consoleState.activeScan}
        onStartScan={handleStartScan}
        onGoActivity={handleGoActivity}
      />

      <div className="flex flex-col gap-4">
        <TargetSnapshotCard
          selectedWorkspace={consoleState.selectedWorkspace}
          customPath={consoleState.customPath}
          workspacePath={consoleState.workspacePath}
          analysisMode={consoleState.analysisMode}
        />
        <ExpectedFlowCard />
      </div>
    </section>
  );
}
