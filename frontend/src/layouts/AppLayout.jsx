import { Outlet, useNavigate, useOutletContext } from 'react-router-dom';

import { AppHeader } from '../components/AppHeader';
import { ErrorBanner } from '../components/ErrorBanner';
import { WorkflowTabs } from '../components/WorkflowTabs';
import { useMemoryLeakConsole } from '../hooks/useMemoryLeakConsole';

export function AppLayout() {
  const navigate = useNavigate();
  const consoleState = useMemoryLeakConsole({
    onCompleted: () => navigate('/report'),
  });

  return (
    <main className="min-h-screen">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 p-4 lg:p-6">
        <AppHeader
          theme={consoleState.theme}
          onToggleTheme={() => consoleState.setTheme((current) => (current === 'dark' ? 'light' : 'dark'))}
          selectedScan={consoleState.selectedScan}
        />
        <ErrorBanner errorBanner={consoleState.errorBanner} />
        <WorkflowTabs />
        <Outlet context={consoleState} />
      </div>
    </main>
  );
}

export function useConsoleContext() {
  return useOutletContext();
}
