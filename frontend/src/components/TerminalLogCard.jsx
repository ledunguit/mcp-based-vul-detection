export function TerminalLogCard({
  selectedScan,
  loadingScan,
  deferredEvents,
  terminalRef,
  onReload,
  onExport,
  formatEvent,
}) {
  return (
    <div className="card border border-base-300 bg-base-100 shadow-xl">
      <div className="card-body gap-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h2 className="card-title text-2xl">Terminal Log</h2>
            <p className="text-sm text-base-content/65">Detailed runtime trace of the orchestrated investigation.</p>
          </div>
          <div className="flex flex-col gap-3 lg:flex-row">
            <button type="button" className="btn btn-outline" onClick={onReload} disabled={!selectedScan}>
              Reload Log
            </button>
            <button type="button" className="btn btn-outline" onClick={onExport} disabled={!selectedScan}>
              Export Log
            </button>
          </div>
        </div>

        <div className="mockup-code border border-base-300 bg-base-300/70 shadow-inner">
          <pre data-prefix="$" className="text-xs opacity-70">
            <code>{selectedScan ? `scan-progress.log :: ${selectedScan.scan_id}` : 'scan-progress.log'}</code>
          </pre>
          <div ref={terminalRef} className="max-h-[34rem] overflow-auto px-4 pb-4">
            {loadingScan ? (
              <pre data-prefix=">" className="text-info">
                <code>loading selected scan...</code>
              </pre>
            ) : null}
            {deferredEvents.length ? (
              deferredEvents.map((event) => (
                <div key={event.event_id}>
                  {formatEvent(event).map((line, index) => (
                    <pre
                      key={`${event.event_id}-${index}`}
                      data-prefix={index === 0 ? '>' : '.'}
                      className={
                        event.type === 'completed' && index === 0
                          ? 'text-success'
                          : ['failed', 'error'].includes(event.type) && index === 0
                            ? 'text-error'
                            : ['cancelled', 'cancel_requested', 'worker_termination_requested'].includes(event.type) && index === 0
                              ? 'text-warning'
                              : 'text-base-content/80'
                      }
                    >
                      <code>{line}</code>
                    </pre>
                  ))}
                </div>
              ))
            ) : (
              <pre data-prefix=">" className="text-base-content/60">
                <code>{selectedScan ? 'Waiting for scan events...' : 'No scan selected.'}</code>
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
