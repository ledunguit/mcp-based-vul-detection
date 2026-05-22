import { useDeferredValue, useEffect, useMemo, useRef } from 'react';

import { TERMINAL_STATES, useMemoryLeakConsoleStore } from '../stores/memoryLeakConsoleStore';

export function useMemoryLeakConsole() {
  const store = useMemoryLeakConsoleStore();
  const terminalRef = useRef(null);
  const deferredEvents = useDeferredValue(store.events);

  useEffect(() => {
    store.initialize();
  }, []);

  useEffect(() => {
    if (!store.selectedScan?.scan_id || TERMINAL_STATES.includes(store.selectedScan.status)) {
      return undefined;
    }
    const eventSource = new EventSource(`/api/scans/${store.selectedScan.scan_id}/events`);
    eventSource.onmessage = (message) => {
      store.handleStreamEvent(JSON.parse(message.data));
    };
    eventSource.onerror = () => {
      store.showError('Lost the progress stream. The scan may still be running; status refresh will continue when available.');
      eventSource.close();
    };
    return () => {
      eventSource.close();
    };
  }, [store.selectedScan?.scan_id, store.selectedScan?.status]);

  useEffect(() => {
    if (!terminalRef.current) {
      return;
    }
    terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [deferredEvents]);

  const selectedWorkspace = useMemo(
    () => store.workspaces.find((workspace) => workspace.path === (store.customPath.trim() || store.workspacePath)) || null,
    [store.customPath, store.workspacePath, store.workspaces],
  );

  const lastEvent = deferredEvents.length ? deferredEvents[deferredEvents.length - 1] : null;
  const activeScan = store.selectedScan && !TERMINAL_STATES.includes(store.selectedScan.status);
  const terminalScans = useMemo(
    () => store.recentScans.filter((scan) => TERMINAL_STATES.includes(scan.status)),
    [store.recentScans],
  );

  function exportLog(formatEvent) {
    if (!store.selectedScan?.scan_id) {
      return;
    }
    const lines = deferredEvents.flatMap((event) => formatEvent(event)).join('\n');
    const blob = new Blob([`${lines}\n`], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${store.selectedScan.scan_id}-scan-progress.log`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return {
    ...store,
    selectedWorkspace,
    deferredEvents,
    lastEvent,
    activeScan,
    terminalScans,
    terminalRef,
    exportLog,
  };
}
