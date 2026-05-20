import { Statistic } from 'antd';

import { AppCard } from './AppCard';

export function AppMetricCard({ metric, value, statisticProps, valueStyle, children, ...cardProps }) {
  return (
    <AppCard size="small" bodyGap={children ? 12 : 0} {...cardProps}>
      <Statistic title={metric} value={value} valueStyle={valueStyle} {...statisticProps} />
      {children}
    </AppCard>
  );
}
