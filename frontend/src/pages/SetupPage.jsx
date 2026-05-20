import { Col, Row } from 'antd';

import { SetupForm } from '../components/SetupForm';
import { TargetSnapshotCard } from '../components/TargetSnapshotCard';
import { useSetupPageActions } from '../handlers/useSetupPageActions';

export function SetupPage() {
  const { consoleState, handleStartScan, handleGoActivity } = useSetupPageActions();

  return (
    <Row gutter={[16, 16]} style={{ minHeight: '100%' }}>
      <Col xs={24} xl={17} xxl={18} style={{ minWidth: 0 }}>
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
          dynamicMode={consoleState.dynamicMode}
          setDynamicMode={consoleState.setDynamicMode}
          dynamicBinaryPath={consoleState.dynamicBinaryPath}
          setDynamicBinaryPath={consoleState.setDynamicBinaryPath}
          dynamicArgs={consoleState.dynamicArgs}
          setDynamicArgs={consoleState.setDynamicArgs}
          dynamicTimeoutSec={consoleState.dynamicTimeoutSec}
          setDynamicTimeoutSec={consoleState.setDynamicTimeoutSec}
          dynamicToolPreference={consoleState.dynamicToolPreference}
          setDynamicToolPreference={consoleState.setDynamicToolPreference}
          activeScan={consoleState.activeScan}
          onStartScan={handleStartScan}
          onGoActivity={handleGoActivity}
        />
      </Col>

      <Col xs={24} xl={7} xxl={6} style={{ minWidth: 0 }}>
        <TargetSnapshotCard
          selectedWorkspace={consoleState.selectedWorkspace}
          customPath={consoleState.customPath}
          workspacePath={consoleState.workspacePath}
          analysisMode={consoleState.analysisMode}
          dynamicMode={consoleState.dynamicMode}
          dynamicToolPreference={consoleState.dynamicToolPreference}
          dynamicBinaryPath={consoleState.dynamicBinaryPath}
        />
      </Col>
    </Row>
  );
}
