import { startTransition, useDeferredValue, useEffect, useEffectEvent, useRef, useState } from 'react';

import {
  cancelScanRequest,
  createScan,
  deleteScanRequest,
  fetchScan,
  fetchScanEvents,
  fetchScanReport,
  fetchScanReportJson,
  fetchScans,
  fetchWorkspaces,
  purgeTerminalScansRequest,
} from '../services/memoryLeakApi';

const TERMINAL_STATES = ['completed', 'failed', 'cancelled'];

function formatFailure(payload) {
  if (!payload) {
    return { text: '', hint: '' };
  }
  if (typeof payload === 'string') {
    return { text: payload, hint: '' };
  }
  const code = payload.error_category || payload.error_code;
  const prefix = code ? `[${code}] ` : '';
  return {
    text: `${prefix}${payload.error || payload.message || 'Request failed'}`,
    hint: payload.remediation || '',
  };
}

export function useMemoryLeakConsole({ onCompleted } = {}) {
  const [workspaces, setWorkspaces] = useState([]);
  const [allowedRoots, setAllowedRoots] = useState([]);
  const [workspacePath, setWorkspacePath] = useState('');
  const [customPath, setCustomPath] = useState('');
  const [buildCommand, setBuildCommand] = useState('');
  const [analysisMode, setAnalysisMode] = useState('no_llm');
  const [fileLimit, setFileLimit] = useState('500');
  const [dynamicRunIds, setDynamicRunIds] = useState('');
  const [dynamicMode, setDynamicMode] = useState('selective');
  const [dynamicBinaryPath, setDynamicBinaryPath] = useState('');
  const [dynamicArgs, setDynamicArgs] = useState('');
  const [dynamicTimeoutSec, setDynamicTimeoutSec] = useState('120');
  const [dynamicToolPreference, setDynamicToolPreference] = useState('auto');
  const [recentScans, setRecentScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [events, setEvents] = useState([]);
  const [reportData, setReportData] = useState(null);
  const [reportText, setReportText] = useState('Run a scan to generate a report.');
  const [errorBanner, setErrorBanner] = useState({ text: '', hint: '' });
  const [loadingWorkspaces, setLoadingWorkspaces] = useState(true);
  const [loadingScan, setLoadingScan] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState({ open: false, mode: 'single', scan: null, count: 0 });
  const [deletingScans, setDeletingScans] = useState(false);
  const eventIdsRef = useRef(new Set());
  const terminalRef = useRef(null);
  const deferredEvents = useDeferredValue(events);

  const selectedWorkspace = workspaces.find((workspace) => workspace.path === (customPath.trim() || workspacePath)) || null;
  const lastEvent = deferredEvents.length ? deferredEvents[deferredEvents.length - 1] : null;
  const activeScan = selectedScan && !TERMINAL_STATES.includes(selectedScan.status);
  const terminalScans = recentScans.filter((scan) => TERMINAL_STATES.includes(scan.status));

  const showError = useEffectEvent((payload) => {
    startTransition(() => {
      setErrorBanner(formatFailure(payload));
    });
  });

  const clearError = useEffectEvent(() => {
    startTransition(() => {
      setErrorBanner({ text: '', hint: '' });
    });
  });

  const loadRecentScans = useEffectEvent(async () => {
    const data = await fetchScans();
    startTransition(() => {
      setRecentScans(data.scans || []);
    });
    return data.scans || [];
  });

  const loadReport = useEffectEvent(async (scanId, format = 'markdown', options = {}) => {
    if (!scanId) {
      return null;
    }
    clearError();
    let text;
    try {
      text = await fetchScanReport(scanId, format);
    } catch (error) {
      showError(error.message);
      return null;
    }
    startTransition(() => {
      setReportText(text);
    });
    if (options.notifyCompleted && typeof onCompleted === 'function') {
      onCompleted();
    }
    return text;
  });

  const loadStructuredReport = useEffectEvent(async (scanId, options = {}) => {
    if (!scanId) {
      return null;
    }
    clearError();
    try {
      const data = await fetchScanReportJson(scanId);
      startTransition(() => {
        setReportData(data);
      });
      if (options.notifyCompleted && typeof onCompleted === 'function') {
        onCompleted();
      }
      return data;
    } catch (error) {
      showError(error.payload || error.message);
      return null;
    }
  });

  const refreshStatus = useEffectEvent(async (scanId) => {
    if (!scanId) {
      return null;
    }
    const data = await fetchScan(scanId);
    startTransition(() => {
      setSelectedScan(data);
    });
    if (data.error) {
      showError(data);
    }
    return data;
  });

  const loadEventHistory = useEffectEvent(async (scanId) => {
    if (!scanId) {
      return [];
    }
    const data = await fetchScanEvents(scanId);
    const loadedEvents = data.events || [];
    eventIdsRef.current = new Set(loadedEvents.map((event) => event.event_id));
    startTransition(() => {
      setEvents(loadedEvents);
    });
    return loadedEvents;
  });

  const openScan = useEffectEvent(async (scanId, seed = null) => {
    if (!scanId) {
      return null;
    }
    setLoadingScan(true);
    try {
      const snapshot = seed || (await fetchScan(scanId));
      eventIdsRef.current = new Set();
      startTransition(() => {
        setSelectedScan(snapshot);
      });
      await loadEventHistory(scanId);
      await refreshStatus(scanId);
      if (snapshot.status === 'completed') {
        await loadStructuredReport(scanId);
        startTransition(() => {
          setReportText('Load Markdown, JSON, Snapshot, or HTML from the raw output tab when needed.');
        });
      } else {
        startTransition(() => {
          setReportData(null);
          setReportText('Run a completed scan to inspect the report.');
        });
      }
      await loadRecentScans();
      return snapshot;
    } finally {
      setLoadingScan(false);
    }
  });

  const handleStreamEvent = useEffectEvent(async (event) => {
    if (eventIdsRef.current.has(event.event_id)) {
      return;
    }
    eventIdsRef.current.add(event.event_id);
    startTransition(() => {
      setEvents((current) => [...current, event]);
    });
    await refreshStatus(event.scan_id);
    if (TERMINAL_STATES.includes(event.type)) {
      await loadRecentScans();
      if (event.type === 'completed') {
        await loadStructuredReport(event.scan_id, { notifyCompleted: true });
        startTransition(() => {
          setReportText('Load Markdown, JSON, Snapshot, or HTML from the raw output tab when needed.');
        });
      } else {
        showError(event);
      }
    }
  });

  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      try {
        const data = await fetchWorkspaces();
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setWorkspaces(data.workspaces || []);
          setAllowedRoots(data.allowed_roots || []);
          setWorkspacePath((current) => current || data.workspaces?.[0]?.path || '');
          setLoadingWorkspaces(false);
        });
        await loadRecentScans();
      } catch (error) {
        if (!cancelled) {
          showError(error.payload || error.message);
          setLoadingWorkspaces(false);
        }
      }
    }

    bootstrap();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!selectedScan?.scan_id || TERMINAL_STATES.includes(selectedScan.status)) {
      return undefined;
    }
    const eventSource = new EventSource(`/api/scans/${selectedScan.scan_id}/events`);
    eventSource.onmessage = (message) => {
      handleStreamEvent(JSON.parse(message.data));
    };
    eventSource.onerror = () => {
      showError('Lost the progress stream. The scan may still be running; status refresh will continue when available.');
      eventSource.close();
    };
    return () => {
      eventSource.close();
    };
  }, [selectedScan?.scan_id, selectedScan?.status]);

  useEffect(() => {
    if (!terminalRef.current) {
      return;
    }
    terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [deferredEvents]);

  async function startScan() {
    clearError();
    const payload = {
      workspace_path: customPath.trim() || workspacePath,
      file_limit: Number(fileLimit || 500),
      analysis_mode: analysisMode,
      build_command: buildCommand.trim() || null,
      dynamic_mode: dynamicMode,
      dynamic_binary_path: dynamicBinaryPath.trim() || null,
      dynamic_args: dynamicArgs.trim() || null,
      dynamic_timeout_sec: dynamicTimeoutSec.trim() ? Number(dynamicTimeoutSec) : null,
      dynamic_tool_preference: dynamicToolPreference === 'auto' ? null : dynamicToolPreference,
      dynamic_run_ids: dynamicRunIds
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
    };

    let data;
    try {
      data = await createScan(payload);
    } catch (error) {
      if (error.status === 409 && error.payload?.existing_scan) {
        data = error.payload.existing_scan;
        showError(`Reusing active scan ${data.scan_id} for this workspace.`);
      } else {
        showError(error.payload || error.message);
        return null;
      }
    }

    await openScan(data.scan_id, data);
    return data;
  }

  async function cancelScan() {
    if (!selectedScan?.scan_id) {
      return null;
    }
    clearError();
    try {
      const response = await cancelScanRequest(selectedScan.scan_id);
      await refreshStatus(selectedScan.scan_id);
      await loadRecentScans();
      return response;
    } catch (error) {
      showError(error.payload || error.message);
      return null;
    }
  }

  function requestDeleteScan(scan) {
    if (!scan) {
      return;
    }
    setDeleteDialog({ open: true, mode: 'single', scan, count: 1 });
  }

  function requestDeleteTerminalScans() {
    if (!terminalScans.length) {
      return;
    }
    setDeleteDialog({ open: true, mode: 'bulk', scan: null, count: terminalScans.length });
  }

  function closeDeleteDialog() {
    if (deletingScans) {
      return;
    }
    setDeleteDialog({ open: false, mode: 'single', scan: null, count: 0 });
  }

  async function confirmDeleteDialog() {
    if (!deleteDialog.open) {
      return null;
    }
    clearError();
    setDeletingScans(true);
    try {
      if (deleteDialog.mode === 'bulk') {
        const response = await purgeTerminalScansRequest();
        const deletedIds = new Set(response.deleted_scan_ids || []);
        startTransition(() => {
          setRecentScans((current) => current.filter((scan) => !deletedIds.has(scan.scan_id)));
          if (selectedScan && deletedIds.has(selectedScan.scan_id)) {
            setSelectedScan(null);
            setEvents([]);
            setReportData(null);
            setReportText('Run a scan to generate a report.');
          }
        });
        return response;
      }

      const scanId = deleteDialog.scan?.scan_id;
      if (!scanId) {
        return null;
      }
      const response = await deleteScanRequest(scanId);
      startTransition(() => {
        setRecentScans((current) => current.filter((scan) => scan.scan_id !== scanId));
        if (selectedScan?.scan_id === scanId) {
          setSelectedScan(null);
          setEvents([]);
          setReportData(null);
          setReportText('Run a scan to generate a report.');
        }
      });
      return response;
    } catch (error) {
      showError(error.payload || error.message);
      return null;
    } finally {
      setDeletingScans(false);
      setDeleteDialog({ open: false, mode: 'single', scan: null, count: 0 });
    }
  }

  function exportLog(formatEvent) {
    if (!selectedScan?.scan_id) {
      return;
    }
    const lines = deferredEvents.flatMap((event) => formatEvent(event)).join('\n');
    const blob = new Blob([`${lines}\n`], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedScan.scan_id}-scan-progress.log`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return {
    workspaces,
    allowedRoots,
    workspacePath,
    setWorkspacePath,
    customPath,
    setCustomPath,
    buildCommand,
    setBuildCommand,
    analysisMode,
    setAnalysisMode,
    fileLimit,
    setFileLimit,
    dynamicRunIds,
    setDynamicRunIds,
    dynamicMode,
    setDynamicMode,
    dynamicBinaryPath,
    setDynamicBinaryPath,
    dynamicArgs,
    setDynamicArgs,
    dynamicTimeoutSec,
    setDynamicTimeoutSec,
    dynamicToolPreference,
    setDynamicToolPreference,
    recentScans,
    selectedScan,
    setSelectedScan,
    selectedWorkspace,
    events,
    deferredEvents,
    lastEvent,
    reportData,
    reportText,
    errorBanner,
    loadingWorkspaces,
    loadingScan,
    activeScan,
    terminalScans,
    terminalRef,
    loadRecentScans,
    loadReport,
    loadStructuredReport,
    loadEventHistory,
    openScan,
    startScan,
    cancelScan,
    deleteDialog,
    deletingScans,
    requestDeleteScan,
    requestDeleteTerminalScans,
    closeDeleteDialog,
    confirmDeleteDialog,
    exportLog,
  };
}
