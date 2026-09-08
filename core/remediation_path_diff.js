import crypto from 'crypto';

function clean(value) { return String(value ?? '').trim(); }

function ids(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(value => clean(value)).filter(Boolean))].sort();
}

/**
 * Stable identity for a path. Resource IDs, relationship types and finding IDs
 * are used rather than database row IDs so a fresh graph can be compared with
 * a previous observation without treating persistence churn as a security change.
 */
export function stableExposurePathKey(path = {}) {
  const nodes = (path.nodes || []).map(node => ({
    resourceId: clean(node.resource_id || node.resourceId || node.id),
    type: clean(node.node_type || node.nodeType || node.type).toUpperCase(),
    findingIds: ids(node.finding_ids || node.findingIds)
  }));
  const edges = (path.edges || []).map(edge => ({
    from: clean(edge.from_resource_id || edge.fromResourceId || edge.from_node_id || edge.fromNodeId),
    to: clean(edge.to_resource_id || edge.toResourceId || edge.to_node_id || edge.toNodeId),
    relationship: clean(edge.relationship || edge.type).toUpperCase()
  }));
  return JSON.stringify({ pathKey: clean(path.path_key || path.pathKey), nodes, edges });
}

function pathId(path) {
  return clean(path.id) || `path_${crypto.createHash('sha256').update(stableExposurePathKey(path)).digest('hex').slice(0, 32)}`;
}

function normalize(path) {
  return { ...path, comparisonKey: stableExposurePathKey(path), comparisonId: pathId(path) };
}

/**
 * Compares two complete graph observations. A path is only REMOVED when the
 * fresh observation is explicitly complete. Missing/incomplete reanalysis must
 * never be converted into a security-improvement claim.
 */
export function compareExposurePathSets({ before = [], after = [], afterComplete = false } = {}) {
  const previous = (Array.isArray(before) ? before : []).map(normalize);
  const current = (Array.isArray(after) ? after : []).map(normalize);
  if (!afterComplete) {
    return {
      complete: false,
      removed: [],
      unchanged: [],
      added: current,
      claimSafe: false,
      reason: 'Fresh exposure analysis is incomplete; missing paths cannot be classified as removed.'
    };
  }
  const currentKeys = new Set(current.map(item => item.comparisonKey));
  const previousKeys = new Set(previous.map(item => item.comparisonKey));
  const removed = previous.filter(item => !currentKeys.has(item.comparisonKey));
  const unchanged = previous.filter(item => currentKeys.has(item.comparisonKey));
  const added = current.filter(item => !previousKeys.has(item.comparisonKey));
  return {
    complete: true,
    removed,
    unchanged,
    added,
    claimSafe: true,
    reason: 'Fresh exposure analysis completed; path changes are based on stable graph identity.'
  };
}

export function derivePathRiskDelta(beforePaths, afterPaths, { afterComplete = false } = {}) {
  const diff = compareExposurePathSets({ before: beforePaths, after: afterPaths, afterComplete });
  if (!diff.complete) return { ...diff, removedCount: 0, addedCount: diff.added.length, netPathDelta: null };
  return { ...diff, removedCount: diff.removed.length, addedCount: diff.added.length, netPathDelta: diff.added.length - diff.removed.length };
}
