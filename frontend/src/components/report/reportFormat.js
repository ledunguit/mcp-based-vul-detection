export function verdictTagColor(verdict) {
  if (verdict === 'confirmed_leak') return 'red';
  if (verdict === 'likely_leak') return 'orange';
  if (verdict === 'false_positive') return 'green';
  return 'blue';
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
