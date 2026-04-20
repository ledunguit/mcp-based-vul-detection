import { NavLink } from 'react-router-dom';

const WORKFLOW_TABS = [
  { to: '/setup', label: 'Setup', hint: 'Configure target and launch' },
  { to: '/activity', label: 'Activity', hint: 'Follow logs and scan history' },
  { to: '/report', label: 'Report', hint: 'Inspect artifacts and verdicts' },
];

export function WorkflowTabs() {
  return (
    <div className="tabs tabs-boxed w-full bg-base-100/80 p-1 shadow-md">
      {WORKFLOW_TABS.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          className={({ isActive }) => `tab h-auto flex-1 gap-1 py-3 ${isActive ? 'tab-active' : ''}`}
        >
          <span className="text-sm font-bold lg:text-base">{tab.label}</span>
          <span className="hidden text-[11px] text-base-content/60 lg:block">{tab.hint}</span>
        </NavLink>
      ))}
    </div>
  );
}
