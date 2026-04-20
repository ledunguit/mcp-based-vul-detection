export function ConfirmDeletionModal({ dialog, busy, onClose, onConfirm }) {
  if (!dialog?.open) {
    return null;
  }

  const title = dialog.mode === 'bulk' ? 'Delete Old Scans?' : 'Delete Scan?';
  const description =
    dialog.mode === 'bulk'
      ? `This will permanently remove ${dialog.count} completed, failed, or cancelled scans and their saved reports.`
      : `This will permanently remove scan ${dialog.scan?.scan_id} and all saved reports, logs, and artifacts.`;

  return (
    <dialog className="modal modal-open">
      <div className="modal-box border border-error/30 bg-base-100 shadow-2xl">
        <h3 className="text-xl font-bold">{title}</h3>
        <p className="mt-3 text-sm leading-7 text-base-content/75">{description}</p>
        <p className="mt-2 text-sm text-base-content/60">This action cannot be undone.</p>
        <div className="modal-action">
          <button type="button" className="btn btn-ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="btn btn-error" onClick={onConfirm} disabled={busy}>
            {busy ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>
      <button type="button" className="modal-backdrop" onClick={onClose} disabled={busy} aria-label="Close confirmation modal" />
    </dialog>
  );
}
