import { create } from 'zustand';

export const useLogsStore = create((set, get) => ({
  logs: [],
  isPaused: false,
  autoScroll: true,
  filter: '',
  levelFilter: 'ALL',

  setPaused: (isPaused) => set({ isPaused }),
  setAutoScroll: (autoScroll) => set({ autoScroll }),
  setFilter: (filter) => set({ filter }),
  setLevelFilter: (levelFilter) => set({ levelFilter }),
  clearLogs: () => set({ logs: [] }),
  appendLog: (logEntry) => set((state) => ({ logs: [...state.logs, logEntry] })),
  loadInitialLogs: async () => {
    const response = await fetch('/api/logs?format=json&limit=500');
    const data = await response.json();
    set({ logs: data.logs || [] });
    return data.logs || [];
  },
  filteredLogs: () => {
    const { logs, filter, levelFilter } = get();
    return logs.filter((log) => {
      const matchesText = filter === '' || log.message.toLowerCase().includes(filter.toLowerCase());
      const matchesLevel = levelFilter === 'ALL' || log.level === levelFilter;
      return matchesText && matchesLevel;
    });
  },
}));
