import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

import { AppLayout } from './layouts/AppLayout';
import { ActivityPage } from './pages/ActivityPage';
import { ReportPage } from './pages/ReportPage';
import { SetupPage } from './pages/SetupPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppLayout />}>
          <Route index element={<Navigate to="/setup" replace />} />
          <Route path="setup" element={<SetupPage />} />
          <Route path="activity" element={<ActivityPage />} />
          <Route path="report" element={<ReportPage />} />
          <Route path="*" element={<Navigate to="/setup" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
