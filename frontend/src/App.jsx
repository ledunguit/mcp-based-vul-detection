import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { App as AntApp, ConfigProvider, theme } from 'antd';

import { AppLayout } from './layouts/AppLayout';
import { ActivityPage } from './pages/ActivityPage';
import { InvestigationsPage } from './pages/InvestigationsPage';
import { ReportPage } from './pages/ReportPage';
import { SetupPage } from './pages/SetupPage';
import { LogsPage } from './pages/LogsPage';

const lightTheme = {
  algorithm: theme.defaultAlgorithm,
  token: {
    colorPrimary: '#2e5bff',
    colorSuccess: '#0cb457',
    colorWarning: '#e68a00',
    colorError: '#d93737',
    colorInfo: '#2e5bff',
    colorTextBase: '#404754',
    colorBgBase: '#f7f8fa',
    colorPrimaryBg: '#eef2ff',
    colorPrimaryBgHover: '#d9e4ff',
    colorPrimaryBorder: '#b8c9ff',
    colorPrimaryBorderHover: '#9bb1ff',
    colorPrimaryHover: '#4a73ff',
    colorPrimaryActive: '#1a42e0',
    colorPrimaryText: '#2e5bff',
    colorPrimaryTextHover: '#4a73ff',
    colorPrimaryTextActive: '#1a42e0',
    colorSuccessBg: '#e6faf0',
    colorSuccessBgHover: '#c8f5de',
    colorSuccessBorder: '#9eeac7',
    colorSuccessBorderHover: '#74dfa7',
    colorSuccessHover: '#0fa350',
    colorSuccessActive: '#09803f',
    colorSuccessText: '#0cb457',
    colorSuccessTextHover: '#0fa350',
    colorSuccessTextActive: '#09803f',
    colorWarningBg: '#fff9e6',
    colorWarningBgHover: '#fff0cc',
    colorWarningBorder: '#ffe699',
    colorWarningBorderHover: '#ffd666',
    colorWarningHover: '#cc7000',
    colorWarningActive: '#a65800',
    colorWarningText: '#e68a00',
    colorWarningTextHover: '#cc7000',
    colorWarningTextActive: '#a65800',
    colorErrorBg: '#fff2f2',
    colorErrorBgHover: '#ffe0e0',
    colorErrorBorder: '#ffc5c5',
    colorErrorBorderHover: '#ff9e9e',
    colorErrorHover: '#c53030',
    colorErrorActive: '#a02020',
    colorErrorText: '#d93737',
    colorErrorTextHover: '#c53030',
    colorErrorTextActive: '#a02020',
    colorInfoBg: '#eef2ff',
    colorInfoBgHover: '#d9e4ff',
    colorInfoBorder: '#b8c9ff',
    colorInfoBorderHover: '#9bb1ff',
    colorInfoHover: '#4a73ff',
    colorInfoActive: '#1a42e0',
    colorInfoText: '#2e5bff',
    colorInfoTextHover: '#4a73ff',
    colorInfoTextActive: '#1a42e0',
    colorText: 'rgba(64, 71, 84, 0.9)',
    colorTextSecondary: 'rgba(64, 71, 84, 0.7)',
    colorTextTertiary: 'rgba(64, 71, 84, 0.45)',
    colorTextQuaternary: 'rgba(64, 71, 84, 0.25)',
    colorTextDisabled: 'rgba(64, 71, 84, 0.25)',
    colorBgContainer: '#ffffff',
    colorBgElevated: '#ffffff',
    colorBgLayout: '#f7f8fa',
    colorBgSpotlight: 'rgba(64, 71, 84, 0.85)',
    colorBgMask: 'rgba(64, 71, 84, 0.45)',
    colorBorder: '#e1e4e8',
    colorBorderSecondary: '#f1f3f5',
    borderRadius: 16,
    borderRadiusSM: 12,
    borderRadiusLG: 20,
    boxShadowSecondary: '0 12px 32px rgba(64, 71, 84, 0.08)',
    boxShadowTertiary: '0 8px 24px rgba(64, 71, 84, 0.06)',
  },
};

export default function App() {
  return (
    <ConfigProvider theme={lightTheme}>
      <AntApp>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<AppLayout />}>
              <Route index element={<Navigate to="/setup" replace />} />
              <Route path="setup" element={<SetupPage />} />
              <Route path="investigations" element={<InvestigationsPage />} />
              <Route path="activity/:scanId?" element={<ActivityPage />} />
              <Route path="report/:scanId?" element={<ReportPage />} />
              <Route path="logs" element={<LogsPage />} />
              <Route path="*" element={<Navigate to="/setup" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AntApp>
    </ConfigProvider>
  );
}
