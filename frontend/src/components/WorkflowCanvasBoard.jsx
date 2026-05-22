import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Background,
  Controls,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  applyEdgeChanges,
  applyNodeChanges,
  getBezierPath,
  useReactFlow,
  useEdgesState,
  useNodesState,
  Handle,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Button, Flex, Space, Tag, Typography, theme as antdTheme } from 'antd';

import { formatClock, tagColor } from '../utils/ui';
import { AppCard } from './ui';

const { Text } = Typography;

const NODE_LAYOUT = [
  { id: 'setup', title: 'Scan Request', subtitle: 'Workspace + options', x: 40, y: 100, theme: 'sky' },
  { id: 'startup', title: 'Startup', subtitle: 'Validate tools', x: 360, y: 70, theme: 'cyan' },
  { id: 'candidate_discovery', title: 'Candidate Discovery', subtitle: 'Index + lexical scan', x: 690, y: 100, theme: 'amber' },
  { id: 'static_analysis', title: 'Static Expansion', subtitle: 'AST + path + flow', x: 1030, y: 310, theme: 'orange' },
  { id: 'leakguard_analysis', title: 'LeakGuard', subtitle: 'Project-level static run', x: 700, y: 520, theme: 'rose' },
  { id: 'dynamic_planning', title: 'Dynamic Planning', subtitle: 'Choose binaries + inputs', x: 360, y: 540, theme: 'violet' },
  { id: 'dynamic_execution', title: 'Dynamic Execution', subtitle: 'LSan / Valgrind / ASan', x: 700, y: 760, theme: 'fuchsia' },
  { id: 'dynamic_merge', title: 'Dynamic Merge', subtitle: 'Bundle runtime evidence', x: 1060, y: 760, theme: 'indigo' },
  { id: 'judging', title: 'Judging', subtitle: 'Verdict + confidence', x: 1380, y: 560, theme: 'emerald' },
  { id: 'reporting', title: 'Reporting', subtitle: 'Build outputs', x: 1380, y: 300, theme: 'teal' },
  { id: 'report', title: 'Report Hub', subtitle: 'Overview + raw formats', x: 1380, y: 70, theme: 'lime' },
];

const EDGES = [
  ['setup', 'startup'],
  ['startup', 'candidate_discovery'],
  ['candidate_discovery', 'static_analysis'],
  ['static_analysis', 'leakguard_analysis'],
  ['leakguard_analysis', 'dynamic_planning'],
  ['dynamic_planning', 'dynamic_execution'],
  ['dynamic_execution', 'dynamic_merge'],
  ['dynamic_merge', 'judging'],
  ['judging', 'reporting'],
  ['reporting', 'report'],
];

const PHASE_TO_NODE = {
  startup: 'startup',
  candidate_discovery: 'candidate_discovery',
  static_analysis: 'static_analysis',
  leakguard_analysis: 'leakguard_analysis',
  dynamic_build: 'dynamic_planning',
  dynamic_planning: 'dynamic_planning',
  dynamic_execution: 'dynamic_execution',
  dynamic_merge: 'dynamic_merge',
  judging: 'judging',
  reporting: 'reporting',
  completed: 'report',
};

const TOOL_TO_NODE = {
  'memory.candidate_scan': 'candidate_discovery',
  'memory.ast_scan': 'static_analysis',
  'memory.function_summary': 'static_analysis',
  'memory.call_graph': 'static_analysis',
  'memory.path_constraints': 'static_analysis',
  'memory.interprocedural_flow': 'static_analysis',
  'memory.call_path_summary': 'static_analysis',
  'memory.leakguard_run': 'leakguard_analysis',
  'memory.leakguard_get_report': 'leakguard_analysis',
  'valgrind.analyze_memcheck': 'dynamic_execution',
  'lsan.run': 'dynamic_execution',
  'asan.run': 'dynamic_execution',
  'memory.get_leak_bundles': 'dynamic_merge',
};

const STATUS_ORDER = ['pending', 'running', 'completed', 'skipped', 'failed', 'cancelled'];

function eventNodeId(event) {
  if (!event) {
    return null;
  }
  if (event.type === 'scan_completed' || event.type === 'completed') {
    return 'report';
  }
  if (event.phase && PHASE_TO_NODE[event.phase]) {
    return PHASE_TO_NODE[event.phase];
  }
  if (event.type === 'dynamic_plan_ready') {
    return 'dynamic_planning';
  }
  if (event.type === 'dynamic_run_created') {
    return 'dynamic_execution';
  }
  if (event.type === 'task_updated') {
    return event.phase === 'candidate_discovery' ? 'candidate_discovery' : 'static_analysis';
  }
  if (event.tool && TOOL_TO_NODE[event.tool]) {
    return TOOL_TO_NODE[event.tool];
  }
  return null;
}

function normalizeNodeStatus(status) {
  if (status === 'starting') {
    return 'running';
  }
  if (status === 'queued') {
    return 'pending';
  }
  return STATUS_ORDER.includes(status) ? status : 'pending';
}

function summarizePairs(payload) {
  if (!payload) {
    return [];
  }
  return Object.entries(payload).filter(
    ([, value]) => value !== undefined && value !== null && value !== '' && (!Array.isArray(value) || value.length),
  );
}

function compactJson(value) {
  if (value === null || value === undefined || value === '') {
    return 'n/a';
  }
  if (Array.isArray(value)) {
    return value.length ? value.join(', ') : '[]';
  }
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

function phaseOutput(nodeId, selectedScan, reportData, events) {
  const relevantEvents = events.filter((event) => eventNodeId(event) === nodeId);
  const latest = relevantEvents.length ? relevantEvents[relevantEvents.length - 1] : null;

  if (nodeId === 'setup') {
    return {
      input: summarizePairs({
        workspace: selectedScan?.workspace_path,
        analysis_mode: selectedScan?.analysis_mode,
        file_limit: selectedScan?.file_limit,
        build_command: selectedScan?.build_command,
        dynamic_mode: selectedScan?.dynamic_mode,
        dynamic_tool_preference: selectedScan?.dynamic_tool_preference,
        dynamic_binary_path: selectedScan?.dynamic_binary_path,
      }),
      output: summarizePairs({
        scan_id: selectedScan?.scan_id,
        status: selectedScan?.status,
        created_at: selectedScan?.created_at ? formatClock(selectedScan.created_at) : null,
      }),
      latest,
    };
  }

  if (nodeId === 'candidate_discovery') {
    const taskEvent = [...relevantEvents].reverse().find((event) => event.type === 'task_updated');
    return {
      input: summarizePairs({
        phase: latest?.message,
        indexed_files: latest?.indexed_file_count,
      }),
      output: summarizePairs({
        scanned_files: taskEvent?.scanned_files,
        candidate_files: reportData?.candidate_source_file_count ?? selectedScan?.candidate_count,
        findings: reportData?.finding_count ?? selectedScan?.finding_count ?? selectedScan?.bundle_count,
      }),
      latest,
    };
  }

  if (nodeId === 'dynamic_planning') {
    const plan = latest?.dynamic_plan || reportData?.dynamic_execution_plan;
    return {
      input: summarizePairs({
        mode: selectedScan?.dynamic_mode,
        tool_preference: selectedScan?.dynamic_tool_preference,
        binary_hint: selectedScan?.dynamic_binary_path,
      }),
      output: summarizePairs({
        targets: plan?.target_count,
        executables: plan?.discovered_executable_count,
        sample_inputs: plan?.discovered_input_count,
      }),
      latest,
    };
  }

  if (nodeId === 'dynamic_execution') {
    return {
      input: summarizePairs({
        message: latest?.message,
        target_path: latest?.target?.target_path || latest?.target_path,
        tool: latest?.target?.tool || latest?.tool,
      }),
      output: summarizePairs({
        run_id: latest?.run_id,
        auto_runs: reportData?.auto_dynamic_run_ids?.length,
        external_runs: reportData?.external_dynamic_run_ids?.length,
      }),
      latest,
    };
  }

  if (nodeId === 'judging') {
    const judgeSummary = reportData?.judge_summary || selectedScan?.judge_summary;
    return {
      input: summarizePairs({
        requested_mode: judgeSummary?.requested_mode,
        judge_scope: judgeSummary?.judge_scope,
      }),
      output: summarizePairs({
        effective_mode: judgeSummary?.effective_mode,
        llm_success: judgeSummary?.llm_success_count,
        llm_skipped: judgeSummary?.llm_skipped_count,
      }),
      latest,
    };
  }

  if (nodeId === 'report') {
    return {
      input: summarizePairs({
        finding_count: reportData?.finding_count ?? selectedScan?.finding_count ?? selectedScan?.bundle_count,
        evidence_count: reportData?.evidence_count ?? selectedScan?.evidence_count,
      }),
      output: summarizePairs({
        formats: 'overview, markdown, json, snapshot, html',
        status: selectedScan?.status,
      }),
      latest,
    };
  }

  return {
    input: summarizePairs({
      message: latest?.message,
      tool: latest?.tool,
      subject: latest?.subject,
    }),
    output: summarizePairs({
      status: latest?.status || selectedScan?.status,
      duration_ms: latest?.duration_ms,
      finding_count: latest?.finding_count ?? latest?.bundle_count,
      evidence_count: latest?.evidence_count,
    }),
    latest,
  };
}

function computeNodeModel(selectedScan, reportData, deferredEvents) {
  const events = deferredEvents || [];
  const reached = new Set(selectedScan ? ['setup'] : []);
  const nodeEvents = Object.fromEntries(NODE_LAYOUT.map((node) => [node.id, []]));
  let currentNodeId = selectedScan ? 'setup' : null;

  for (const event of events) {
    const nodeId = eventNodeId(event);
    if (!nodeId) {
      continue;
    }
    nodeEvents[nodeId].push(event);
    reached.add(nodeId);
    currentNodeId = nodeId;
  }

  if (reportData || selectedScan?.status === 'completed') {
    reached.add('report');
    currentNodeId = 'report';
  }

  const terminalStatus = normalizeNodeStatus(selectedScan?.status);

  const nodes = NODE_LAYOUT.map((node) => {
    let status = 'pending';
    const hasEvents = nodeEvents[node.id].length > 0;
    const maybeSkippedByMode =
      node.id.startsWith('dynamic_') && selectedScan?.dynamic_mode === 'off'
        ? 'skipped'
        : node.id === 'leakguard_analysis' && selectedScan?.status === 'completed' && !reportData?.leakguard_tool && !hasEvents
          ? 'skipped'
          : null;

    if (!selectedScan && node.id !== 'setup') {
      status = 'pending';
    } else if (node.id === 'setup' && selectedScan) {
      status = 'completed';
    } else if (currentNodeId === node.id && ['failed', 'cancelled'].includes(selectedScan?.status || '')) {
      status = terminalStatus;
    } else if (currentNodeId === node.id && !['completed', 'failed', 'cancelled'].includes(selectedScan?.status || '')) {
      status = 'running';
    } else if (reached.has(node.id)) {
      status = 'completed';
    } else if (maybeSkippedByMode) {
      status = maybeSkippedByMode;
    }

    if (node.id === 'report' && selectedScan?.status === 'completed') {
      status = 'completed';
    }

    const io = phaseOutput(node.id, selectedScan, reportData, events);
    return {
      ...node,
      width: node.id === 'report' ? 320 : 270,
      height: node.id === 'report' ? 220 : 170,
      status,
      latestEvent: io.latest,
      input: io.input,
      output: io.output,
    };
  });

  const nodesById = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const edges = EDGES.map(([from, to]) => {
    const fromNode = nodesById[from];
    const toNode = nodesById[to];
    const active = fromNode.status === 'running' || toNode.status === 'running';
    const complete =
      ['completed', 'running'].includes(fromNode.status) && ['completed', 'running', 'skipped'].includes(toNode.status);
    return { id: `${from}-${to}`, from, to, active, complete };
  });

  return { nodes, edges, currentNodeId };
}

function stageAccent(token, stageTheme) {
  const accents = {
    sky: '#6aa8ff',
    cyan: '#34b6d9',
    amber: '#d9981f',
    orange: '#dd7b28',
    rose: '#d66b8c',
    violet: '#7562ff',
    fuchsia: '#b85ee8',
    indigo: '#4f6fd9',
    emerald: token.colorSuccess,
    teal: '#169c92',
    lime: '#75ad1a',
  };

  return accents[stageTheme] || token.colorPrimary;
}

function nodePalette(token, status) {
  if (status === 'running') {
    return {
      border: token.colorPrimary,
      background: `linear-gradient(180deg, ${token.colorPrimaryBgHover}, ${token.colorBgContainer})`,
      card: token.colorPrimaryBg,
      muted: token.colorPrimaryText,
      shadow: `0 0 0 1px ${token.colorPrimaryBorder}`,
    };
  }
  if (status === 'completed') {
    return {
      border: token.colorSuccessBorder,
      background: `linear-gradient(180deg, ${token.colorSuccessBgHover}, ${token.colorBgContainer})`,
      card: token.colorSuccessBg,
      muted: token.colorSuccessText,
      shadow: `0 0 0 1px ${token.colorSuccessBorder}`,
    };
  }
  if (status === 'failed') {
    return {
      border: token.colorErrorBorder,
      background: `linear-gradient(180deg, ${token.colorErrorBgHover}, ${token.colorBgContainer})`,
      card: token.colorErrorBg,
      muted: token.colorErrorText,
      shadow: `0 0 0 1px ${token.colorErrorBorder}`,
    };
  }
  if (status === 'cancelled') {
    return {
      border: token.colorWarningBorder,
      background: `linear-gradient(180deg, ${token.colorWarningBgHover}, ${token.colorBgContainer})`,
      card: token.colorWarningBg,
      muted: token.colorWarningText,
      shadow: `0 0 0 1px ${token.colorWarningBorder}`,
    };
  }
  if (status === 'skipped') {
    return {
      border: token.colorBorderSecondary,
      background: token.colorBgLayout,
      card: token.colorBgContainer,
      muted: token.colorTextTertiary,
      shadow: 'none',
    };
  }
  return {
    border: token.colorBorderSecondary,
    background: token.colorBgContainer,
    card: token.colorBgLayout,
    muted: token.colorTextSecondary,
    shadow: 'none',
  };
}

function WorkflowNode({ data, selected }) {
  const { token } = antdTheme.useToken();
  const accent = stageAccent(token, data.theme);
  const palette = nodePalette(token, data.status);

  return (
    <div
      className="rf-workflow-node"
      style={{
        borderColor: palette.border,
        background: palette.background,
        boxShadow: selected ? `${token.boxShadowSecondary}, 0 0 0 1px ${palette.border}` : palette.shadow,
        ['--workflow-accent']: accent,
        ['--workflow-handle-border']: token.colorBgContainer,
      }}
      title={`${data.title}\n\nInput:\n${data.input.length ? data.input.map(([key, value]) => `${key}: ${compactJson(value)}`).join('\n') : 'No explicit input'}\n\nOutput:\n${data.output.length ? data.output.map(([key, value]) => `${key}: ${compactJson(value)}`).join('\n') : 'No explicit output'}`}
    >
      <Handle type="target" position={Position.Left} className="rf-workflow-handle" />

      <Flex justify="space-between" align="start" gap={12}>
        <div>
          <div className="workflow-node-title">{data.title}</div>
          <div className="workflow-node-subtitle">{data.subtitle}</div>
        </div>
        <Tag color={tagColor(data.status)}>{data.status}</Tag>
      </Flex>

      <Flex vertical gap={8} style={{ marginTop: 16 }}>
        {data.output.slice(0, 2).map(([key, value]) => (
          <div key={key} className="workflow-node-output-card" style={{ background: palette.card }}>
            <div className="workflow-node-output-key" style={{ color: palette.muted }}>
              {key}
            </div>
            <div className="workflow-node-output-value">{compactJson(value)}</div>
          </div>
        ))}

        {!data.output.length ? <div className="workflow-node-empty">Waiting for data.</div> : null}
      </Flex>
      <Handle type="source" position={Position.Right} className="rf-workflow-handle" />
    </div>
  );
}

function WorkflowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  markerEnd,
}) {
  const { token } = antdTheme.useToken();
  const [path] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });

  const stroke = data?.active ? token.colorPrimary : data?.complete ? token.colorSuccess : token.colorBorderSecondary;

  return (
    <>
      <path
        id={id}
        d={path}
        markerEnd={markerEnd}
        style={{
          fill: 'none',
          stroke,
          strokeWidth: data?.active ? 3 : data?.complete ? 2.5 : 1.8,
          opacity: data?.active || data?.complete ? 0.95 : 0.55,
          strokeLinecap: 'round',
        }}
      />
      {data?.active ? (
        <path
          d={path}
          className="workflow-edge-signal"
          style={{
            fill: 'none',
            stroke: token.colorPrimaryHover,
            strokeWidth: 1.5,
            strokeLinecap: 'round',
          }}
        />
      ) : null}
    </>
  );
}

const nodeTypes = { workflow: WorkflowNode };
const edgeTypes = { workflow: WorkflowEdge };

function WorkflowCanvas({
  selectedScan,
  lastEvent,
  activeScan,
  deferredEvents,
  reportData,
  onCancel,
  onOpenReport,
}) {
  const [hoveredNodeId, setHoveredNodeId] = useState(null);
  const { token } = antdTheme.useToken();
  const reactFlow = useReactFlow();
  const canvasShellRef = useRef(null);
  const model = useMemo(() => computeNodeModel(selectedScan, reportData, deferredEvents), [selectedScan, reportData, deferredEvents]);

  const flowColors = useMemo(
    () => ({
      mode: 'light',
      backgroundColor: token.colorPrimaryBorder,
      minimapMaskColor: 'rgba(247, 248, 250, 0.76)',
      minimapBgColor: token.colorBgContainer,
      nodeStrokeColor: token.colorBorderSecondary,
      nodeColor: (node) => {
        if (node.data?.status === 'running') return token.colorPrimary;
        if (node.data?.status === 'completed') return token.colorSuccess;
        if (node.data?.status === 'failed') return token.colorError;
        if (node.data?.status === 'cancelled') return token.colorWarning;
        return token.colorTextTertiary;
      },
    }),
    [token],
  );

  const initialNodes = useMemo(
    () =>
      model.nodes.map((node) => ({
        id: node.id,
        type: 'workflow',
        position: { x: node.x, y: node.y },
        draggable: true,
        data: node,
      })),
    [model.nodes],
  );

  const initialEdges = useMemo(
    () =>
      model.edges.map((edge) => ({
        id: edge.id,
        source: edge.from,
        target: edge.to,
        type: 'workflow',
        animated: edge.active,
        data: { active: edge.active, complete: edge.complete },
      })),
    [model.edges],
  );

  const [nodes, setNodes] = useNodesState(initialNodes);
  const [edges, setEdges] = useEdgesState(initialEdges);

  useEffect(() => {
    setNodes((currentNodes) =>
      currentNodes.map((currentNode) => {
        const nextNode = initialNodes.find((item) => item.id === currentNode.id);
        if (!nextNode) {
          return currentNode;
        }
        return { ...currentNode, data: nextNode.data };
      }),
    );
  }, [initialNodes, setNodes]);

  useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      reactFlow.fitView({ padding: 0.16, duration: 0 });
    });

    return () => window.cancelAnimationFrame(frame);
  }, [reactFlow, selectedScan?.scan_id, model.nodes.length, model.currentNodeId]);

  const nodesById = useMemo(() => Object.fromEntries(model.nodes.map((node) => [node.id, node])), [model.nodes]);
  const hoverNode = hoveredNodeId ? nodesById[hoveredNodeId] : null;
  const hoverPopupStyle = useMemo(() => {
    if (!hoverNode || !canvasShellRef.current) {
      return null;
    }

    const popupWidth = 384;
    const edgeGap = 24;
    const estimatedPopupHeight = 320;
    const canvasElement = canvasShellRef.current;
    const nodeElement = canvasElement.querySelector(`.react-flow__node[data-id="${hoverNode.id}"]`);

    if (!nodeElement) {
      return null;
    }

    const canvasRect = canvasElement.getBoundingClientRect();
    const nodeRect = nodeElement.getBoundingClientRect();
    const nodeLeft = nodeRect.left - canvasRect.left;
    const nodeRight = nodeRect.right - canvasRect.left;
    const nodeTop = nodeRect.top - canvasRect.top;
    const preferredRight = nodeRight + edgeGap;
    const preferredLeft = nodeLeft - popupWidth - edgeGap;
    const hasRoomOnRight = preferredRight + popupWidth <= canvasRect.width - edgeGap;
    const left = hasRoomOnRight ? preferredRight : Math.max(edgeGap, preferredLeft);
    const top = Math.min(
      Math.max(edgeGap, nodeTop),
      Math.max(edgeGap, canvasRect.height - estimatedPopupHeight - edgeGap),
    );

    return {
      left,
      top,
    };
  }, [hoverNode, nodes]);

  const onNodesChange = useCallback((changes) => setNodes((current) => applyNodeChanges(changes, current)), [setNodes]);
  const onEdgesChange = useCallback((changes) => setEdges((current) => applyEdgeChanges(changes, current)), [setEdges]);
  const onNodeMouseEnter = useCallback((_, node) => setHoveredNodeId(node.id), []);
  const onNodeMouseLeave = useCallback(() => setHoveredNodeId(null), []);
  const scanLabel = selectedScan?.scan_id || 'No scan selected';
  const statusLabel = selectedScan?.status || 'idle';
  const workspaceLabel = selectedScan?.workspace_path || 'No workspace selected';
  const lastEventLabel = lastEvent ? `${lastEvent.type} • ${formatClock(lastEvent.timestamp)}` : 'Waiting for events';

  return (
    <AppCard
      style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
      styles={{ header: { display: 'none' } }}
      bodyStyle={{ flex: 1, minHeight: 0, overflow: 'hidden' }}
    >
      <Flex vertical gap={16} style={{ flex: 1, minHeight: 0 }}>
        <Flex justify="space-between" align="center" gap={12} wrap>
          <Flex vertical gap={6} style={{ minWidth: 0, flex: '1 1 360px' }}>
            <Space wrap size={[8, 8]}>
              <Tag color={tagColor(statusLabel)}>{statusLabel}</Tag>
              <Text strong>{scanLabel}</Text>
              <Text type="secondary">{lastEventLabel}</Text>
            </Space>
            <Text
              type="secondary"
              title={workspaceLabel}
              style={{
                display: 'block',
                maxWidth: '100%',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {workspaceLabel}
            </Text>
          </Flex>

          <Space wrap size={[8, 8]} style={{ justifyContent: 'flex-end' }}>
            <Button danger type="primary" size="small" onClick={onCancel} disabled={!activeScan}>
              Cancel Scan
            </Button>
            <Button type="primary" size="small" onClick={onOpenReport} disabled={!selectedScan}>
              Open Full Report
            </Button>
            {[
              ['Findings', selectedScan?.finding_count ?? selectedScan?.bundle_count ?? '-'],
              ['Candidates', selectedScan?.candidate_count ?? '-'],
              ['Evidence', selectedScan?.evidence_count ?? '-'],
            ].map(([label, value]) => (
              <div
                key={label}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '6px 10px',
                  borderRadius: 999,
                  border: `1px solid ${token.colorBorderSecondary}`,
                  background: token.colorBgLayout,
                }}
              >
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {label}
                </Text>
                <Text strong>{value}</Text>
              </div>
            ))}
          </Space>
        </Flex>

        <div
          ref={canvasShellRef}
          className="workflow-canvas-shell"
          style={{
            position: 'relative',
            flex: 1,
            minHeight: 0,
            background: token.colorBgContainer,
            border: `1px solid ${token.colorBorderSecondary}`,
            borderRadius: token.borderRadiusLG,
            overflow: 'hidden',
            ['--workflow-minimap-border']: token.colorBorderSecondary,
          }}
        >
          <ReactFlow
            colorMode={flowColors.mode}
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeMouseEnter={onNodeMouseEnter}
            onNodeMouseLeave={onNodeMouseLeave}
            fitView
            fitViewOptions={{ padding: 0.16, duration: 450 }}
            minZoom={0.35}
            maxZoom={1.6}
            nodesDraggable
            nodesConnectable={false}
            elementsSelectable
            panOnDrag
            zoomOnScroll
            proOptions={{ hideAttribution: true }}
            defaultEdgeOptions={{ animated: true }}
          >
            <Controls className="workflow-flow-ui" showInteractive={false} position="bottom-right" />
            <MiniMap
              className="workflow-flow-ui"
              pannable
              zoomable
              position="bottom-left"
              nodeStrokeWidth={3}
              bgColor={flowColors.minimapBgColor}
              maskColor={flowColors.minimapMaskColor}
              nodeStrokeColor={flowColors.nodeStrokeColor}
              nodeColor={flowColors.nodeColor}
            />
            <Background gap={20} size={1.1} color={flowColors.backgroundColor} />
          </ReactFlow>

          {hoverNode && hoverPopupStyle ? (
            <AppCard
              size="small"
              bodyGap={12}
              style={{
                position: 'absolute',
                width: 384,
                maxHeight: 'calc(100% - 32px)',
                pointerEvents: 'none',
                borderColor: token.colorBorderSecondary,
                boxShadow: token.boxShadowSecondary,
                ...hoverPopupStyle,
              }}
              bodyStyle={{ overflow: 'auto' }}
            >
              <Flex justify="space-between" align="start" gap={12}>
                <div>
                  <Text strong>{hoverNode.title}</Text>
                  <div>
                    <Text type="secondary">{hoverNode.subtitle}</Text>
                  </div>
                </div>
                <Tag color={tagColor(hoverNode.status)}>{hoverNode.status}</Tag>
              </Flex>

              {hoverNode.latestEvent ? (
                <Text type="secondary">{hoverNode.latestEvent.type} • {formatClock(hoverNode.latestEvent.timestamp)}</Text>
              ) : null}

              <AppCard size="small" title="Input" bodyGap={8}>
                {hoverNode.input.length ? (
                  hoverNode.input.slice(0, 3).map(([key, value]) => (
                    <Flex key={key} justify="space-between" gap={12} style={{ marginBottom: 8 }}>
                      <Text type="secondary">{key}</Text>
                      <Text style={{ textAlign: 'right' }}>{compactJson(value)}</Text>
                    </Flex>
                  ))
                ) : (
                  <Text type="secondary">No explicit input yet.</Text>
                )}
              </AppCard>

              <AppCard size="small" title="Output" bodyGap={8}>
                {hoverNode.output.length ? (
                  hoverNode.output.slice(0, 3).map(([key, value]) => (
                    <Flex key={key} justify="space-between" gap={12} style={{ marginBottom: 8 }}>
                      <Text type="secondary">{key}</Text>
                      <Text style={{ textAlign: 'right' }}>{compactJson(value)}</Text>
                    </Flex>
                  ))
                ) : (
                  <Text type="secondary">Waiting for data.</Text>
                )}
              </AppCard>
            </AppCard>
          ) : null}
        </div>
      </Flex>
    </AppCard>
  );
}

export function WorkflowCanvasBoard(props) {
  return (
    <ReactFlowProvider>
      <WorkflowCanvas {...props} />
    </ReactFlowProvider>
  );
}
