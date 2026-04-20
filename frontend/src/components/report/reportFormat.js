export function verdictBadgeClass(verdict) {
  if (verdict === 'confirmed_leak') {
    return 'badge badge-error badge-soft';
  }
  if (verdict === 'likely_leak') {
    return 'badge badge-warning badge-soft';
  }
  if (verdict === 'false_positive') {
    return 'badge badge-success badge-soft';
  }
  return 'badge badge-info badge-soft';
}

export function formatLocation(location) {
  if (!location) {
    return 'unknown';
  }
  if (location.line && location.column) {
    return `${location.file}:${location.line}:${location.column}`;
  }
  if (location.line) {
    return `${location.file}:${location.line}`;
  }
  return location.file || 'unknown';
}

export function buildVerdictCounts(bundles) {
  const counts = {};
  for (const bundle of bundles) {
    const verdict = bundle?.verdict?.verdict || 'unjudged';
    counts[verdict] = (counts[verdict] || 0) + 1;
  }
  return counts;
}
