import { Alert } from 'antd';

export function ErrorBanner({ errorBanner }) {
  if (!errorBanner?.text) {
    return null;
  }

  return (
    <Alert
      type="error"
      message={errorBanner.text}
      description={errorBanner.hint || undefined}
      showIcon
      closable
      banner
    />
  );
}
