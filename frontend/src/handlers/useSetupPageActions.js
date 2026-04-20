import { useNavigate } from 'react-router-dom';

import { useConsoleContext } from '../layouts/AppLayout';

export function useSetupPageActions() {
  const navigate = useNavigate();
  const consoleState = useConsoleContext();

  async function handleStartScan() {
    const result = await consoleState.startScan();
    if (result) {
      navigate('/activity');
    }
  }

  return {
    consoleState,
    handleStartScan,
    handleGoActivity: () => navigate('/activity'),
  };
}
