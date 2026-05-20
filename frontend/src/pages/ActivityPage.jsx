import { useCallback, useEffect, useRef, useState } from 'react';

import { TerminalLogCard } from '../components/TerminalLogCard';
import { WorkflowCanvasBoard } from '../components/WorkflowCanvasBoard';
import { useActivityPageActions } from '../handlers/useActivityPageActions';

const TERMINAL_COLLAPSED_HEIGHT = 48;
const TERMINAL_DEFAULT_HEIGHT = 280;
const TERMINAL_MIN_HEIGHT = 220;
const TERMINAL_MIN_MAIN_HEIGHT = 360;

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

export function ActivityPage() {
  const {
    consoleState,
    handleCancelScan,
    handleOpenReport,
    handleReloadLog,
    handleExportLog,
    formatEvent,
  } = useActivityPageActions();
  const shellRef = useRef(null);
  const resizeStateRef = useRef(null);
  const [terminalHeight, setTerminalHeight] = useState(TERMINAL_DEFAULT_HEIGHT);
  const [terminalCollapsed, setTerminalCollapsed] = useState(true);

  const getMaxTerminalHeight = useCallback(() => {
    const shellHeight = shellRef.current?.getBoundingClientRect().height;
    if (!shellHeight) {
      return 560;
    }
    return Math.max(TERMINAL_MIN_HEIGHT, shellHeight - TERMINAL_MIN_MAIN_HEIGHT);
  }, []);

  const handleTerminalResizeStart = useCallback(
    (event) => {
      if (event.button !== undefined && event.button !== 0) {
        return;
      }

      event.preventDefault();

      const startHeight = terminalCollapsed ? clamp(terminalHeight, TERMINAL_MIN_HEIGHT, getMaxTerminalHeight()) : terminalHeight;

      resizeStateRef.current = {
        startY: event.clientY,
        startHeight,
      };

      if (terminalCollapsed) {
        setTerminalCollapsed(false);
        setTerminalHeight(startHeight);
      }

      document.body.style.cursor = 'ns-resize';
      document.body.style.userSelect = 'none';
    },
    [getMaxTerminalHeight, terminalCollapsed, terminalHeight],
  );

  useEffect(() => {
    function handlePointerMove(event) {
      if (!resizeStateRef.current) {
        return;
      }

      const delta = resizeStateRef.current.startY - event.clientY;
      const maxHeight = getMaxTerminalHeight();
      const nextHeight = clamp(resizeStateRef.current.startHeight + delta, TERMINAL_MIN_HEIGHT, maxHeight);
      setTerminalHeight(nextHeight);
    }

    function handlePointerUp() {
      if (!resizeStateRef.current) {
        return;
      }

      resizeStateRef.current = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }

    function handleResize() {
      setTerminalHeight((current) => Math.min(current, getMaxTerminalHeight()));
    }

    handleResize();

    window.addEventListener('pointermove', handlePointerMove);
    window.addEventListener('pointerup', handlePointerUp);
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('pointerup', handlePointerUp);
      window.removeEventListener('resize', handleResize);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [getMaxTerminalHeight]);

  const terminalVisibleHeight = terminalCollapsed ? TERMINAL_COLLAPSED_HEIGHT : terminalHeight;

  return (
    <div
      ref={shellRef}
      className="activity-shell"
      style={{
        height: '100%',
        minHeight: 0,
        overflow: 'hidden',
        gridTemplateRows: 'minmax(0, 1fr) auto',
        gap: 16,
      }}
    >
      <div style={{ height: '100%', minHeight: 0 }}>
        <WorkflowCanvasBoard
          selectedScan={consoleState.selectedScan}
          lastEvent={consoleState.lastEvent}
          activeScan={consoleState.activeScan}
          deferredEvents={consoleState.deferredEvents}
          reportData={consoleState.reportData}
          onCancel={handleCancelScan}
          onOpenReport={handleOpenReport}
        />
      </div>

      <div
        style={{
          minWidth: 0,
          minHeight: terminalVisibleHeight,
          height: terminalVisibleHeight,
        }}
      >
        <TerminalLogCard
          selectedScan={consoleState.selectedScan}
          loadingScan={consoleState.loadingScan}
          deferredEvents={consoleState.deferredEvents}
          terminalRef={consoleState.terminalRef}
          onReload={handleReloadLog}
          onExport={handleExportLog}
          formatEvent={formatEvent}
          collapsed={terminalCollapsed}
          onToggleCollapse={() => setTerminalCollapsed((current) => !current)}
          onResizeStart={handleTerminalResizeStart}
        />
      </div>
    </div>
  );
}
