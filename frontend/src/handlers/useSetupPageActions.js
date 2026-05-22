import { useNavigate } from 'react-router-dom';

import { useConsoleContext } from '../layouts/AppLayout';

export function useSetupPageActions() {
  const navigate = useNavigate();
  const consoleState = useConsoleContext();

  async function handleStartScan() {
    const result = await consoleState.startScan();
    if (result) {
      navigate(`/activity/${result.scan_id}`);
    }
  }

  return {
    consoleState,
    handleStartScan,
    handleGoActivity: () => navigate(consoleState.selectedScan?.scan_id ? `/activity/${consoleState.selectedScan.scan_id}` : '/activity'),
  };
}
