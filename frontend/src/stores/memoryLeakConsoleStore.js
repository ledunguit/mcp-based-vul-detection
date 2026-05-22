import { create } from 'zustand';

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

let eventIds = new Set();
let loadingScanId = null;

export const useMemoryLeakConsoleStore = create((set, get) => ({
  bootstrapped: false,
  bootstrapping: false,
  workspaces: [],
  allowedRoots: [],
  workspacePath: '',
  customPath: '',
  buildCommand: '',
  analysisMode: 'no_llm',
  fileLimit: '500',
  dynamicRunIds: '',
  dynamicMode: 'selective',
  dynamicBinaryPath: '',
  dynamicArgs: '',
  dynamicTimeoutSec: '120',
  dynamicToolPreference: 'auto',
  recentScans: [],
  selectedScan: null,
  events: [],
  reportData: null,
  reportText: 'Run a scan to generate a report.',
  errorBanner: { text: '', hint: '' },
  loadingWorkspaces: true,
  loadingScan: false,
  deleteDialog: { open: false, mode: 'single', scan: null, count: 0 },
  deletingScans: false,

  setWorkspacePath: (workspacePath) => set({ workspacePath }),
  setCustomPath: (customPath) => set({ customPath }),
  setBuildCommand: (buildCommand) => set({ buildCommand }),
  setAnalysisMode: (analysisMode) => set({ analysisMode }),
  setFileLimit: (fileLimit) => set({ fileLimit }),
  setDynamicRunIds: (dynamicRunIds) => set({ dynamicRunIds }),
  setDynamicMode: (dynamicMode) => set({ dynamicMode }),
  setDynamicBinaryPath: (dynamicBinaryPath) => set({ dynamicBinaryPath }),
  setDynamicArgs: (dynamicArgs) => set({ dynamicArgs }),
  setDynamicTimeoutSec: (dynamicTimeoutSec) => set({ dynamicTimeoutSec }),
  setDynamicToolPreference: (dynamicToolPreference) => set({ dynamicToolPreference }),

  showError: (payload) => set({ errorBanner: formatFailure(payload) }),
  clearError: () => set({ errorBanner: { text: '', hint: '' } }),

  initialize: async () => {
    if (get().bootstrapped || get().bootstrapping) {
      return;
    }
    set({ bootstrapping: true, loadingWorkspaces: true });
    try {
      const workspaceData = await fetchWorkspaces();
      const scansData = await fetchScans();
      set((state) => ({
        workspaces: workspaceData.workspaces || [],
        allowedRoots: workspaceData.allowed_roots || [],
        workspacePath: state.workspacePath || workspaceData.workspaces?.[0]?.path || '',
        recentScans: scansData.scans || [],
        loadingWorkspaces: false,
        bootstrapped: true,
        bootstrapping: false,
      }));
    } catch (error) {
      set({
        errorBanner: formatFailure(error.payload || error.message),
        loadingWorkspaces: false,
        bootstrapping: false,
      });
    }
  },

  loadRecentScans: async () => {
    const data = await fetchScans();
    set({ recentScans: data.scans || [] });
    return data.scans || [];
  },

  loadReport: async (scanId, format = 'markdown') => {
    if (!scanId) {
      return null;
    }
    get().clearError();
    try {
      const text = await fetchScanReport(scanId, format);
      set({ reportText: text });
      return text;
    } catch (error) {
      get().showError(error.message);
      return null;
    }
  },

  loadStructuredReport: async (scanId) => {
    if (!scanId) {
      return null;
    }
    get().clearError();
    try {
      const data = await fetchScanReportJson(scanId);
      set({ reportData: data });
      return data;
    } catch (error) {
      get().showError(error.payload || error.message);
      return null;
    }
  },

  refreshStatus: async (scanId) => {
    if (!scanId) {
      return null;
    }
    const data = await fetchScan(scanId);
    set({ selectedScan: data });
    if (data.error) {
      get().showError(data);
    }
    return data;
  },

  loadEventHistory: async (scanId) => {
    if (!scanId) {
      return [];
    }
    const data = await fetchScanEvents(scanId);
    const loadedEvents = data.events || [];
    eventIds = new Set(loadedEvents.map((event) => event.event_id));
    set({ events: loadedEvents });
    return loadedEvents;
  },

  openScan: async (scanId, seed = null) => {
    if (!scanId || loadingScanId === scanId) {
      return null;
    }
    loadingScanId = scanId;
    set({ loadingScan: true });
    try {
      const snapshot = seed || (await fetchScan(scanId));
      eventIds = new Set();
      set({ selectedScan: snapshot });
      await get().loadEventHistory(scanId);
      const refreshed = await get().refreshStatus(scanId);
      const effectiveScan = refreshed || snapshot;

      if (effectiveScan?.status === 'completed') {
        await get().loadStructuredReport(scanId);
        set({ reportText: 'Load Markdown, JSON, Snapshot, or HTML from the raw output tab when needed.' });
      } else {
        set({
          reportData: null,
          reportText: 'Run a completed scan to inspect the report.',
        });
      }

      await get().loadRecentScans();
      return effectiveScan;
    } finally {
      if (loadingScanId === scanId) {
        loadingScanId = null;
      }
      set({ loadingScan: false });
    }
  },

  ensureScanLoaded: async (scanId) => {
    if (!scanId) {
      return null;
    }
    if (get().selectedScan?.scan_id === scanId || loadingScanId === scanId) {
      return get().selectedScan;
    }
    const seed = get().recentScans.find((scan) => scan.scan_id === scanId) || null;
    return get().openScan(scanId, seed);
  },

  handleStreamEvent: async (event) => {
    if (eventIds.has(event.event_id)) {
      return;
    }
    eventIds.add(event.event_id);
    set((state) => ({ events: [...state.events, event] }));
    await get().refreshStatus(event.scan_id);
    if (TERMINAL_STATES.includes(event.type)) {
      await get().loadRecentScans();
      if (event.type === 'completed') {
        await get().loadStructuredReport(event.scan_id);
        set({ reportText: 'Load Markdown, JSON, Snapshot, or HTML from the raw output tab when needed.' });
      } else {
        get().showError(event);
      }
    }
  },

  startScan: async () => {
    get().clearError();
    const state = get();
    const payload = {
      workspace_path: state.customPath.trim() || state.workspacePath,
      file_limit: Number(state.fileLimit || 500),
      analysis_mode: state.analysisMode,
      build_command: state.buildCommand.trim() || null,
      dynamic_mode: state.dynamicMode,
      dynamic_binary_path: state.dynamicBinaryPath.trim() || null,
      dynamic_args: state.dynamicArgs.trim() || null,
      dynamic_timeout_sec: state.dynamicTimeoutSec.trim() ? Number(state.dynamicTimeoutSec) : null,
      dynamic_tool_preference: state.dynamicToolPreference === 'auto' ? null : state.dynamicToolPreference,
      dynamic_run_ids: state.dynamicRunIds
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
        get().showError(`Reusing active scan ${data.scan_id} for this workspace.`);
      } else {
        get().showError(error.payload || error.message);
        return null;
      }
    }

    await get().openScan(data.scan_id, data);
    return data;
  },

  cancelScan: async () => {
    const scanId = get().selectedScan?.scan_id;
    if (!scanId) {
      return null;
    }
    get().clearError();
    try {
      const response = await cancelScanRequest(scanId);
      await get().refreshStatus(scanId);
      await get().loadRecentScans();
      return response;
    } catch (error) {
      get().showError(error.payload || error.message);
      return null;
    }
  },

  requestDeleteScan: (scan) => {
    if (!scan) {
      return;
    }
    set({ deleteDialog: { open: true, mode: 'single', scan, count: 1 } });
  },

  requestDeleteTerminalScans: () => {
    const terminalScans = get().recentScans.filter((scan) => TERMINAL_STATES.includes(scan.status));
    if (!terminalScans.length) {
      return;
    }
    set({ deleteDialog: { open: true, mode: 'bulk', scan: null, count: terminalScans.length } });
  },

  closeDeleteDialog: () => {
    if (get().deletingScans) {
      return;
    }
    set({ deleteDialog: { open: false, mode: 'single', scan: null, count: 0 } });
  },

  confirmDeleteDialog: async () => {
    const { deleteDialog, selectedScan } = get();
    if (!deleteDialog.open) {
      return null;
    }
    get().clearError();
    set({ deletingScans: true });
    try {
      if (deleteDialog.mode === 'bulk') {
        const response = await purgeTerminalScansRequest();
        const deletedIds = new Set(response.deleted_scan_ids || []);
        set((state) => {
          const shouldClearSelected = selectedScan && deletedIds.has(selectedScan.scan_id);
          return {
            recentScans: state.recentScans.filter((scan) => !deletedIds.has(scan.scan_id)),
            selectedScan: shouldClearSelected ? null : state.selectedScan,
            events: shouldClearSelected ? [] : state.events,
            reportData: shouldClearSelected ? null : state.reportData,
            reportText: shouldClearSelected ? 'Run a scan to generate a report.' : state.reportText,
          };
        });
        return response;
      }

      const scanId = deleteDialog.scan?.scan_id;
      if (!scanId) {
        return null;
      }
      const response = await deleteScanRequest(scanId);
      set((state) => {
        const shouldClearSelected = state.selectedScan?.scan_id === scanId;
        return {
          recentScans: state.recentScans.filter((scan) => scan.scan_id !== scanId),
          selectedScan: shouldClearSelected ? null : state.selectedScan,
          events: shouldClearSelected ? [] : state.events,
          reportData: shouldClearSelected ? null : state.reportData,
          reportText: shouldClearSelected ? 'Run a scan to generate a report.' : state.reportText,
        };
      });
      return response;
    } catch (error) {
      get().showError(error.payload || error.message);
      return null;
    } finally {
      set({
        deletingScans: false,
        deleteDialog: { open: false, mode: 'single', scan: null, count: 0 },
      });
    }
  },
}));

export { TERMINAL_STATES };
