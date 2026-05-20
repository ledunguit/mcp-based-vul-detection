import { Modal, Typography } from 'antd';

const { Text } = Typography;

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
    <Modal
      open={dialog.open}
      title={title}
      onCancel={onClose}
      onOk={onConfirm}
      okText={busy ? 'Deleting...' : 'Delete'}
      cancelText="Cancel"
      okButtonProps={{ danger: true, loading: busy }}
      cancelButtonProps={{ disabled: busy }}
      maskClosable={!busy}
      closable={!busy}
    >
      <Text>{description}</Text>
      <br />
      <Text type="secondary">This action cannot be undone.</Text>
    </Modal>
  );
}
