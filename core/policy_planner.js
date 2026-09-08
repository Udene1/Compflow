import crypto from 'crypto';
import { ControlMatrix } from './controls.js';
import { stableEdgeId, stableUsageId } from './execution_engine.js';

const FRAMEWORKS = new Set(['soc2', 'gdpr', 'hipaa', 'iso27001']);
const ACTIONS = new Set(['EVALUATE', 'REMEDIATE']);
const MODES = new Set(['AUDIT', 'REMEDIATE']);
const MAX_RULES = 200;
const MAX_TARGETS = 100;
const MAX_STRING = 128;
function assertString(value, code, max = MAX_STRING) { if (typeof value !== 'string' || value.length < 1 || value.length > max) throw new Error(code); return value; }
function assertFrameworks(frameworks) { if (!Array.isArray(frameworks) || frameworks.length === 0 || frameworks.length > FRAMEWORKS.size) throw new Error('POLICY_FRAMEWORKS_INVALID'); const unique = [...new Set(frameworks)]; if (unique.length !== frameworks.length || unique.some(id => !FRAMEWORKS.has(id))) throw new Error('POLICY_FRAMEWORKS_INVALID'); return unique; }
function normalizeRule(rule, index) { if (!rule || typeof rule !== 'object' || Array.isArray(rule)) throw new Error(`POLICY_RULE_INVALID:${index}`); const id = assertString(rule.id, `POLICY_RULE_ID_INVALID:${index}`); const controlId = assertString(rule.controlId, `POLICY_RULE_CONTROL_INVALID:${index}`); if (!ControlMatrix[controlId]) throw new Error(`POLICY_CONTROL_UNKNOWN:${controlId}`); const action = rule.action || 'EVALUATE'; if (!ACTIONS.has(action)) throw new Error(`POLICY_RULE_ACTION_INVALID:${index}`); return { id, controlId, action, requiresApproval: action === 'REMEDIATE' ? rule.requiresApproval !== false : false }; }
function normalizeTargets(targets) { if (!Array.isArray(targets) || targets.length < 1 || targets.length > MAX_TARGETS) throw new Error('POLICY_TARGETS_INVALID'); return targets.map((target, index) => { if (!target || typeof target !== 'object' || Array.isArray(target)) throw new Error(`POLICY_TARGET_INVALID:${index}`); return { connectionId: assertString(target.connectionId, `POLICY_TARGET_CONNECTION_INVALID:${index}`), provider: assertString(target.provider, `POLICY_TARGET_PROVIDER_INVALID:${index}`), resourceId: target.resourceId == null ? null : assertString(target.resourceId, `POLICY_TARGET_RESOURCE_INVALID:${index}`, 256) }; }); }
function node({ organizationId, executionId, nodeType, logicalKey, label, metadata = {} }) { return { id: stableUsageId(organizationId, executionId, nodeType, logicalKey), nodeType, logicalKey, status: 'PENDING', label, metadata }; }
function edge(executionId, fromNodeId, toNodeId, metadata = {}) { return { id: stableEdgeId(executionId, fromNodeId, toNodeId, 'DEPENDS_ON'), fromNodeId, toNodeId, edgeType: 'DEPENDS_ON', metadata }; }
function hashPlan(plan) { const unsigned = { ...plan }; delete unsigned.planHash; return crypto.createHash('sha256').update(JSON.stringify(unsigned)).digest('hex'); }

/** Compile a declarative compliance policy into a deterministic execution plan. Planning never claims work occurred. */
export function compilePolicyPlan({ organizationId, executionId, policy, targets }) {
  assertString(organizationId, 'POLICY_ORGANIZATION_REQUIRED'); assertString(executionId, 'POLICY_EXECUTION_REQUIRED');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('POLICY_INVALID');
  const policyId = assertString(policy.id, 'POLICY_ID_INVALID'); const version = assertString(String(policy.version ?? ''), 'POLICY_VERSION_INVALID', 32); const frameworks = assertFrameworks(policy.frameworks); const mode = policy.mode || 'AUDIT';
  if (!MODES.has(mode)) throw new Error('POLICY_MODE_INVALID'); if (!Array.isArray(policy.rules) || policy.rules.length < 1 || policy.rules.length > MAX_RULES) throw new Error('POLICY_RULES_INVALID');
  const rules = policy.rules.map(normalizeRule); const normalizedTargets = normalizeTargets(targets);
  const planNode = node({ organizationId, executionId, nodeType: 'PLAN', logicalKey: `${policyId}@${version}`, label: `Policy plan ${policyId}@${version}`, metadata: { policyId, policyVersion: version, frameworks, mode } });
  const nodes = [planNode]; const edges = []; const evidenceByCheck = new Map();
  for (const target of normalizedTargets) for (const rule of rules) {
    const evidenceKey = `${target.connectionId}:${target.resourceId || '*'}:${rule.controlId}`; let evidenceNode = evidenceByCheck.get(evidenceKey);
    if (!evidenceNode) { evidenceNode = node({ organizationId, executionId, nodeType: 'EVIDENCE_COLLECTION', logicalKey: evidenceKey, label: `Collect evidence for ${rule.controlId}`, metadata: { connectionId: target.connectionId, provider: target.provider, resourceId: target.resourceId, controlId: rule.controlId, frameworks } }); evidenceByCheck.set(evidenceKey, evidenceNode); nodes.push(evidenceNode); edges.push(edge(executionId, planNode.id, evidenceNode.id, { reason: 'policy-target' })); }
    const evaluation = node({ organizationId, executionId, nodeType: 'CONTROL_EVALUATION', logicalKey: `${evidenceKey}:evaluate:${rule.id}`, label: `Evaluate ${rule.controlId}`, metadata: { ruleId: rule.id, controlId: rule.controlId, frameworks, connectionId: target.connectionId, provider: target.provider, resourceId: target.resourceId } });
    nodes.push(evaluation); edges.push(edge(executionId, evidenceNode.id, evaluation.id, { reason: 'evidence-required' }));
    if (mode === 'REMEDIATE' && rule.action === 'REMEDIATE') {
      let dependency = evaluation;
      if (rule.requiresApproval) { const approval = node({ organizationId, executionId, nodeType: 'APPROVAL', logicalKey: `${evidenceKey}:approval:${rule.id}`, label: `Approve remediation ${rule.controlId}`, metadata: { ruleId: rule.id, controlId: rule.controlId, connectionId: target.connectionId, provider: target.provider, resourceId: target.resourceId, frameworks } }); nodes.push(approval); edges.push(edge(executionId, evaluation.id, approval.id, { reason: 'remediation-approval' })); dependency = approval; }
      const remediation = node({ organizationId, executionId, nodeType: 'REMEDIATION', logicalKey: `${evidenceKey}:remediate:${rule.id}`, label: `Remediate ${rule.controlId}`, metadata: { ruleId: rule.id, controlId: rule.controlId, frameworks, connectionId: target.connectionId, provider: target.provider, resourceId: target.resourceId, requiresApproval: rule.requiresApproval } });
      nodes.push(remediation); edges.push(edge(executionId, dependency.id, remediation.id, { reason: 'approved-remediation' }));
      const verification = node({ organizationId, executionId, nodeType: 'VERIFICATION', logicalKey: `${evidenceKey}:verify:${rule.id}`, label: `Verify ${rule.controlId}`, metadata: { ruleId: rule.id, controlId: rule.controlId, frameworks, connectionId: target.connectionId, provider: target.provider, resourceId: target.resourceId } });
      nodes.push(verification); edges.push(edge(executionId, remediation.id, verification.id, { reason: 'post-remediation-verification' }));
    }
  }
  const plan = { planVersion: 1, planHash: null, policy: { id: policyId, version, frameworks, mode }, targets: normalizedTargets, nodes, edges, counts: { nodes: nodes.length, edges: edges.length, evidence: nodes.filter(n => n.nodeType === 'EVIDENCE_COLLECTION').length, evaluations: nodes.filter(n => n.nodeType === 'CONTROL_EVALUATION').length, approvals: nodes.filter(n => n.nodeType === 'APPROVAL').length, remediations: nodes.filter(n => n.nodeType === 'REMEDIATION').length, verifications: nodes.filter(n => n.nodeType === 'VERIFICATION').length } };
  plan.planHash = hashPlan(plan); return plan;
}
export function validatePolicyPlan(plan) { if (!plan || plan.planVersion !== 1 || typeof plan.planHash !== 'string' || !Array.isArray(plan.nodes) || !Array.isArray(plan.edges)) throw new Error('POLICY_PLAN_INVALID'); const nodeIds = new Set(plan.nodes.map(n => n.id)); if (nodeIds.size !== plan.nodes.length) throw new Error('POLICY_PLAN_DUPLICATE_NODE'); for (const e of plan.edges) if (!nodeIds.has(e.fromNodeId) || !nodeIds.has(e.toNodeId) || e.fromNodeId === e.toNodeId) throw new Error('POLICY_PLAN_EDGE_INVALID'); if (hashPlan(plan) !== plan.planHash) throw new Error('POLICY_PLAN_HASH_INVALID'); return true; }
