import React, { useState } from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider, useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import ReactFlow, {
  Background,
  Controls,
  BaseEdge,
  getBezierPath,
  Handle,
  Position,
  type EdgeProps,
  type NodeProps,
} from 'reactflow';
import 'reactflow/dist/style.css';
import './index.css';
import { AnalysisPanelDrawer } from './AnalysisPanelDrawer';
import {
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Shield,
  Network,
  Loader2,
  AlertCircle,
  Inbox,
  Maximize2,
  Router,
  Info,
  Trash2,
  Check,
  Settings,
  Database,
  RefreshCw,
  ArrowLeft,
  ArrowUpDown,
  Search,
  Globe,
  Plus,
  X,
  Pencil,
  MessageSquare,
  RotateCcw,
  Filter,
  Upload,
  Copy,
} from 'lucide-react';

/* ── Layout constants ── */
const HANDLE_RIGHT = 'right';
const HANDLE_LEFT = 'left';

const ROW_HEIGHT = 56;
/** Minimal vertical gap for both columns (expansion pushes down via layoutHeight only) */
const NODE_GAP = 16;
const TOP_PADDING = 12;
/** Small extra gap only between interface groups (right column), not endpoints */
const IF_EXTRA_GAP = 6;
/** Gaps and defaults for measured layout (right columns start after firewall's right edge) */
const COL_GAP = 80;
const DEFAULT_LEFT_MAX_W = 200;
const DEFAULT_FW_W = 220;
const RIGHT_COL_WIDTH = 200;   // interface group column width for router/expanded placement
const ROUTER_COL_WIDTH = 100;
const LEFT_X = 0;
/** Fallback fixed X when nodeSizes not yet available (layout will recompute when sizes report) */
const FW_X = 450;
const IG_X = 650;         // InterfaceGroup column
const ROUTER_X = 900;     // Per-group router column
const EXPANDED_X = 1150;  // Expanded router devices
const EXPANDED_NODE_ZINDEX = 1000;
const MAX_VISIBLE_SOURCES = 9;
/** Base height for interface/zone nodes (collapsed); expanded uses estimateIGNodeHeight */
const BASE_IF_HEIGHT = 56;
/** Base height for endpoint nodes (collapsed); expanded uses estimateNodeHeight */
const BASE_EP_HEIGHT = 44;
/** Firewall node half-height for vertical center (px-4 py-3 + content ≈ 40px) */
const FW_HALF_HEIGHT = 20;

/**
 * Estimate the rendered height of an endpoint node so we can push
 * subsequent nodes down when one is expanded.
 */
function estimateNodeHeight(
  nodeData: any,
  isExpanded: boolean,
  isDestination: boolean,
): number {
  if (!isExpanded) return ROW_HEIGHT;

  // Base: label row + outer padding (px-3 py-2 → 8+8 top/bot) + border
  let h = 40;

  // Expanded metadata section: mt-2 pt-2 border-t ≈ 16px overhead
  h += 16;
  if (nodeData?.device_name != null && String(nodeData.device_name).trim() !== '') h += 20;
  if (nodeData?.ip != null) h += 20;
  if (nodeData?.mac != null) h += 20;

  // Services list
  const services: any[] = Array.isArray(nodeData?.services) ? nodeData.services : [];
  if (services.length > 0) {
    h += 28; // mt-2 + header
    h += services.length * 18;
  }

  // "By source" table (destination only)
  if (isDestination) {
    h += 30; // mt-3 + header
    const breakdown: any[] = Array.isArray(nodeData?.source_breakdown) ? nodeData.source_breakdown : [];
    if (breakdown.length > 0) {
      h += 24; // table header row
      const totalRows = breakdown.reduce(
        (acc: number, src: any) => acc + (Array.isArray(src.services) ? src.services.length : 0),
        0,
      );
      // The table has max-h-[200px] with overflow, so cap row contribution
      h += Math.min(totalRows * 24, 200);
    } else {
      h += 20; // "No conn_close data" message
    }
  }

  return Math.max(h, ROW_HEIGHT);
}

/* ── Reusable UI helpers ── */
function cn(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(' ');
}

/* ── Edge helpers (unchanged logic) ── */
function aggregateEdgePayloads(edgeList: any[]): Record<string, unknown> {
  if (edgeList.length === 0) return {};
  const sum = (key: string) => edgeList.reduce((a, e) => a + (Number(e[key]) || 0), 0);
  const mergeObjects = (key: string) => {
    const out: Record<string, number> = {};
    edgeList.forEach((e) => {
      const o = e[key];
      if (o && typeof o === 'object') {
        Object.entries(o).forEach(([k, v]) => { out[k] = (out[k] || 0) + Number(v || 0); });
      }
    });
    return out;
  };
  const lastSeens = edgeList.map((e) => e.last_seen).filter(Boolean);
  const lastSeen = lastSeens.length ? lastSeens.sort().pop()! : null;
  return {
    count_open: sum('count_open'),
    count_close: sum('count_close'),
    bytes_src_to_dst: sum('bytes_src_to_dst'),
    bytes_dst_to_src: sum('bytes_dst_to_src'),
    top_ports: mergeObjects('top_ports'),
    top_rules: mergeObjects('top_rules'),
    top_apps: mergeObjects('top_apps'),
    last_seen: lastSeen,
  };
}

function formatEdgeTooltip(data: Record<string, unknown> | undefined): string {
  if (!data || typeof data !== 'object') return '';
  const parts: string[] = [];
  if (Number(data.count_open) > 0) parts.push(`Connections: ${data.count_open}`);
  if (Number(data.bytes_src_to_dst) > 0 || Number(data.bytes_dst_to_src) > 0) {
    parts.push(`Bytes →: ${data.bytes_src_to_dst ?? 0}, ←: ${data.bytes_dst_to_src ?? 0}`);
  }
  if (data.last_seen) parts.push(`Last: ${String(data.last_seen).slice(0, 19)}`);
  const topServices = data.top_services as Array<{ proto?: string; port?: number; app_name?: string | null }> | undefined;
  if (Array.isArray(topServices) && topServices.length > 0) {
    const lines = topServices.map((s) => {
      const proto = (s.proto ?? 'ip').toUpperCase();
      const port = s.port ?? 0;
      const app = s.app_name != null && String(s.app_name).trim() !== '' ? ` — ${String(s.app_name).trim()}` : '';
      return `${proto}/${port}${app}`;
    });
    parts.push('Services: ' + lines.join(', '));
  }
  return parts.length ? parts.join('\n') : '';
}

function MetricEdge(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, style, markerEnd, markerStart } = props;
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition: sourcePosition ?? Position.Right,
    targetPosition: targetPosition ?? Position.Left,
  });
  const tooltip = formatEdgeTooltip(data as Record<string, unknown> | undefined);
  return (
    <g>
      {tooltip ? <title>{tooltip}</title> : null}
      <BaseEdge
        id={id}
        path={path}
        labelX={labelX}
        labelY={labelY}
        style={style}
        markerEnd={markerEnd}
        markerStart={markerStart}
      />
    </g>
  );
}

/* ── Node expansion helpers (unchanged logic) ── */
function isExpandable(mac: string | null | undefined): boolean {
  return mac != null && String(mac).trim() !== '';
}

function isDestinationExpandable(data: any): boolean {
  if (Array.isArray(data?.source_breakdown) && data.source_breakdown.length > 0) return true;
  if (Array.isArray(data?.services) && data.services.length > 0) return true;
  return isExpandable(data?.mac);
}

/* ── Endpoint Node Content ── */
function EndpointNodeContent({
  nodeId,
  data,
  expanded,
  onToggle,
  isDestination,
}: {
  nodeId: string | undefined;
  data: any;
  expanded: boolean;
  onToggle: (() => void) | undefined;
  isDestination: boolean;
}) {
  const [hover, setHover] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number } | null>(null);
  const expandable = isDestination ? isDestinationExpandable(data) : isExpandable(data?.mac);
  const hasFilterActions = !!(data?.endpointId && (data?.onSetAsSource || data?.onSetAsDest));

  const handleExpandClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!expandable) return;
    onToggle?.();
  };

  const handleContextMenu = (e: React.MouseEvent) => {
    if (!hasFilterActions) return;
    e.preventDefault();
    e.stopPropagation();
    setContextMenu({ x: e.clientX, y: e.clientY });
  };

  React.useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    window.addEventListener('click', close);
    window.addEventListener('contextmenu', close);
    return () => {
      window.removeEventListener('click', close);
      window.removeEventListener('contextmenu', close);
    };
  }, [contextMenu]);

  const isExpanded = expanded && expandable;
  return (
    <>
      <div
        className={cn(
          'rounded-xl border border-border bg-card px-3 py-2 min-w-[100px] transition-all duration-150',
          isExpanded && 'border-ring shadow-lg ring-1 ring-ring/30',
          !isExpanded && hover && expandable && 'shadow-md border-muted-foreground/40',
          expandable ? 'cursor-pointer' : 'cursor-default',
        )}
        style={{ pointerEvents: 'auto' }}
        onClick={handleExpandClick}
        onContextMenu={handleContextMenu}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        role={expandable ? 'button' : undefined}
        onKeyDown={expandable ? (e) => e.key === 'Enter' && onToggle?.() : undefined}
        tabIndex={expandable ? 0 : undefined}
      >
        {/* Label row: title + identification badges (max 2) + filter icon(s) + expand chevron */}
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-semibold text-card-foreground truncate min-w-0 flex-1">
            {data?.label ?? '—'}
          </span>
          {(() => {
            const typeName = (data?.type_name ?? data?.identification?.device_type_name ?? '').toString().trim();
            const osName = (data?.os_name ?? data?.identification?.device_os_name ?? '').toString().trim();
            const vendor = (data?.vendor ?? data?.identification?.device_vendor ?? '').toString().trim();
            const badges: string[] = [];
            if (typeName) badges.push(typeName);
            if (osName) badges.push(osName);
            if (badges.length < 2 && vendor) badges.push(vendor.length > 20 ? `${vendor.slice(0, 18)}…` : vendor);
            const two = badges.slice(0, 2);
            if (two.length === 0) return null;
            return (
              <div className="flex items-center flex-shrink-0 gap-1">
                {two.map((t, i) => (
                  <span key={i} className="max-w-[90px] truncate text-[10px] px-1.5 py-0.5 rounded bg-muted/60 text-muted-foreground" title={t}>
                    {t}
                  </span>
                ))}
              </div>
            );
          })()}
          <div className="flex items-center flex-shrink-0 gap-0.5">
            {!isDestination && data?.endpointId && data?.onSetAsSource && (
              <button
                type="button"
                className={cn(
                  'p-1 rounded-md transition-colors',
                  data.isActiveSource
                    ? 'bg-primary/20 text-primary'
                    : 'hover:bg-accent text-muted-foreground hover:text-foreground',
                )}
                onClick={(e) => { e.stopPropagation(); data.onSetAsSource(); }}
                aria-label={data.isActiveSource ? 'Source filter active' : 'Use as source filter'}
                title={data.isActiveSource ? 'Source filter active' : 'Use as source filter'}
              >
                <Filter className={cn('w-3.5 h-3.5', data.isActiveSource && 'fill-current')} />
              </button>
            )}
            {isDestination && data?.endpointId && data?.onSetAsDest && (
              <button
                type="button"
                className={cn(
                  'p-1 rounded-md transition-colors',
                  data.isActiveDest
                    ? 'bg-primary/20 text-primary'
                    : 'hover:bg-accent text-muted-foreground hover:text-foreground',
                )}
                onClick={(e) => { e.stopPropagation(); data.onSetAsDest(); }}
                aria-label={data.isActiveDest ? 'Destination filter active' : 'Use as destination filter'}
                title={data.isActiveDest ? 'Destination filter active' : 'Use as destination filter'}
              >
                <Filter className={cn('w-3.5 h-3.5', data.isActiveDest && 'fill-current')} />
              </button>
            )}
            {expandable && (
              <button
                type="button"
                className="p-0.5 rounded hover:bg-accent transition-colors text-muted-foreground hover:text-foreground"
                onClick={(e) => { e.stopPropagation(); handleExpandClick(e); }}
                aria-label={expanded ? 'Collapse' : 'Expand'}
                title={expanded ? 'Collapse' : 'Expand'}
              >
                <span className={cn('block transition-transform duration-200', isExpanded && 'rotate-90')}>
                  <ChevronRight className="w-3.5 h-3.5" />
                </span>
              </button>
            )}
          </div>
        </div>
        {/* Expanded details */}
        {isExpanded && (
          <div className="mt-2 pt-2 border-t border-border space-y-1 text-xs text-muted-foreground leading-relaxed">
            {data?.device_name != null && String(data.device_name).trim() !== '' && (
              <div>Device: <span className="text-card-foreground">{data.device_name}</span></div>
            )}
            {data?.ip != null && <div>IP: <span className="text-card-foreground">{data.ip}</span></div>}
            {data?.mac != null && <div>MAC: <span className="text-card-foreground">{data.mac}</span></div>}

            {/* Identification section (DEVICE logs / overrides): 2-col grid, only rows when value exists */}
            {(() => {
              const vendor = (data?.vendor ?? data?.identification?.device_vendor ?? '').toString().trim();
              const typeName = (data?.type_name ?? data?.identification?.device_type_name ?? '').toString().trim();
              const osName = (data?.os_name ?? data?.identification?.device_os_name ?? '').toString().trim();
              const brand = (data?.brand ?? data?.identification?.device_brand ?? '').toString().trim();
              const model = (data?.model ?? data?.identification?.device_model ?? '').toString().trim();
              const rows = [
                vendor && { label: 'Vendor', value: vendor },
                typeName && { label: 'Type', value: typeName },
                osName && { label: 'OS', value: osName },
                brand && { label: 'Brand', value: brand },
                model && { label: 'Model', value: model },
              ].filter(Boolean) as { label: string; value: string }[];
              if (rows.length === 0) return null;
              return (
                <div className="mt-2">
                  <div className="text-xs font-semibold text-card-foreground mb-1">Identification</div>
                  <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
                    {rows.map((r) => (
                      <React.Fragment key={r.label}>
                        <span className="text-muted-foreground">{r.label}</span>
                        <span className="text-card-foreground">{r.value}</span>
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* Services section */}
            {Array.isArray(data?.services) && data.services.length > 0 && (
              <div className="mt-2">
                <div className="text-xs font-semibold text-card-foreground mb-1">Services</div>
                {data.services.map((svc: { proto?: string; port?: number; app_name?: string | null; count?: number }, i: number) => {
                  const proto = (svc.proto ?? 'ip').toUpperCase();
                  const port = svc.port ?? 0;
                  const app = svc.app_name != null && String(svc.app_name).trim() !== '' ? String(svc.app_name).trim() : null;
                  const count = svc.count ?? 0;
                  const line = app ? `${proto}/${port} — ${app} (${count})` : `${proto}/${port} (${count})`;
                  return <div key={i}>{line}</div>;
                })}
                {(data.services[0] as { services_total?: number })?.services_total != null && (data.services[0] as { services_total: number }).services_total > data.services.length && (
                  <div className="italic mt-0.5">+{(data.services[0] as { services_total: number }).services_total - data.services.length} more</div>
                )}
              </div>
            )}

            {/* By-source section */}
            {isDestination && (
              <div className="mt-3">
                <div className="text-xs font-semibold text-card-foreground mb-1">By source</div>
                {Array.isArray(data?.source_breakdown) && data.source_breakdown.length > 0 ? (
                  <div className="overflow-x-auto max-h-[200px] overflow-y-auto">
                    <table className="w-full text-[10px] border-collapse">
                      <thead>
                        <tr className="border-b border-border text-muted-foreground">
                          <th className="text-left px-1.5 py-1 font-medium">Source</th>
                          <th className="text-left px-1.5 py-1 font-medium">Dest Port</th>
                          <th className="text-left px-1.5 py-1 font-medium">App</th>
                          <th className="text-right px-1.5 py-1 font-medium">Count</th>
                          <th className="w-7 px-0.5 py-1" title="Inspect raw logs" />
                        </tr>
                      </thead>
                      <tbody>
                        {data.source_breakdown.flatMap((src: { source_label?: string; src_ip?: string; services?: Array<{ proto?: string; port?: number; app_name?: string | null; count?: number }> }, si: number) =>
                          (src.services || []).map((svc: { proto?: string; port?: number; app_name?: string | null; count?: number }, vi: number) => (
                            <tr key={`${si}-${vi}`} className={cn('border-b border-border/50', si % 2 === 0 && 'bg-muted/20')}>
                              <td className="px-1.5 py-1">{vi === 0 ? (src.source_label ?? '—') : ''}</td>
                              <td className="px-1.5 py-1">{(svc.proto ?? 'ip').toUpperCase()}/{svc.port ?? 0}</td>
                              <td className="px-1.5 py-1">{svc.app_name != null && String(svc.app_name).trim() !== '' ? String(svc.app_name).trim() : '—'}</td>
                              <td className="px-1.5 py-1 text-right tabular-nums">{svc.count ?? 0}</td>
                              <td className="w-7 px-0.5 py-1">
                                {typeof data?.onInspect === 'function' && src.src_ip && data?.ip && (
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      data.onInspect({
                                        source_label: src.source_label,
                                        src_ip: src.src_ip,
                                        proto: svc.proto ?? 'TCP',
                                        port: svc.port ?? 0,
                                        app_name: svc.app_name,
                                      });
                                    }}
                                    className="p-0.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                                    title="Inspect raw logs"
                                    aria-label="Inspect raw logs"
                                  >
                                    <Search className="w-3 h-3" />
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="italic text-muted-foreground/60">No conn_close data in selected time range</div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Context menu */}
      {contextMenu && (
        <div
          className="fixed z-[10000] rounded-lg border border-border bg-card shadow-xl p-1 min-w-[160px]"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          {data?.onSetAsSource && (
            <button
              type="button"
              className="block w-full text-left px-3 py-2 text-sm rounded-md hover:bg-accent text-card-foreground transition-colors"
              onClick={() => { data.onSetAsSource(); setContextMenu(null); }}
            >
              Set as Source Filter
            </button>
          )}
          {data?.onSetAsDest && (
            <button
              type="button"
              className="block w-full text-left px-3 py-2 text-sm rounded-md hover:bg-accent text-card-foreground transition-colors"
              onClick={() => { data.onSetAsDest(); setContextMenu(null); }}
            >
              Set as Destination Filter
            </button>
          )}
        </div>
      )}
    </>
  );
}

/* ── Node components ── */
function LeftEndpointNode({ id, data }: NodeProps) {
  return (
    <>
      <Handle type="source" position={Position.Right} id={HANDLE_RIGHT} />
      <EndpointNodeContent
        nodeId={id}
        data={data}
        expanded={!!data?.expanded}
        onToggle={data?.onToggle}
        isDestination={false}
      />
    </>
  );
}

function RightEndpointNode({ id, data }: NodeProps) {
  return (
    <>
      <Handle type="target" position={Position.Left} id={HANDLE_LEFT} />
      <EndpointNodeContent
        nodeId={id}
        data={data}
        expanded={!!data?.expanded}
        onToggle={data?.onToggle}
        isDestination={true}
      />
    </>
  );
}

function FirewallNode({ id, data }: NodeProps) {
  const ref = React.useRef<HTMLDivElement>(null);
  const label = data?.label ?? 'Firewall';
  React.useEffect(() => {
    const el = ref.current;
    const onSize = data?.onNodeSize as ((nodeId: string, w: number, h: number) => void) | undefined;
    if (!el || !onSize) return;
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      onSize(String(id), width, height);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [id, data?.onNodeSize]);
  return (
    <div
      ref={ref}
      className="flex items-center gap-2 px-4 py-3 rounded-xl border border-border bg-card shadow-sm hover:shadow-md transition-shadow max-w-[260px]"
      title={typeof label === 'string' && label.length > 32 ? label : undefined}
    >
      <Handle type="target" position={Position.Left} id={HANDLE_LEFT} />
      <Shield className="w-4 h-4 text-primary flex-shrink-0" />
      <span className="text-sm font-semibold text-card-foreground truncate block min-w-0">{label}</span>
      <Handle type="source" position={Position.Right} id={HANDLE_RIGHT} />
    </div>
  );
}

function RouterBucketNode({ data }: NodeProps) {
  const handleClick = () => {
    if (typeof data?.onClick === 'function') (data.onClick as () => void)();
  };
  const countMatch = String(data?.label ?? '').match(/\((\d+)\)/);
  const countText = countMatch ? countMatch[1] : null;
  const baseLabel = countText ? String(data?.label ?? '').replace(/\s*\(\d+\).*/, '') : (data?.label ?? 'Router');

  return (
    <div
      className={cn(
        'flex items-center gap-2 px-3 py-2 rounded-xl border border-border bg-card shadow-sm transition-shadow min-w-[80px]',
        data?.clickable ? 'cursor-pointer hover:shadow-md hover:border-muted-foreground/40' : 'cursor-default',
      )}
      onClick={handleClick}
      role={data?.clickable ? 'button' : undefined}
      onKeyDown={data?.clickable ? (e) => e.key === 'Enter' && handleClick() : undefined}
      tabIndex={data?.clickable ? 0 : undefined}
    >
      <Handle type="target" position={Position.Left} id={HANDLE_LEFT} />
      <Handle type="source" position={Position.Right} id={HANDLE_RIGHT} />
      <Network className="w-3.5 h-3.5 text-primary flex-shrink-0" />
      <span className="text-sm font-semibold text-card-foreground">{baseLabel}</span>
      {countText && (
        <span className="inline-flex items-center justify-center rounded-full bg-primary/15 text-primary text-[10px] font-semibold px-1.5 py-0.5 min-w-[20px]">
          {countText}
        </span>
      )}
      {String(data?.label ?? '').includes('▼') && (
        <ChevronDown className="w-3 h-3 text-muted-foreground" />
      )}
    </div>
  );
}

/** Services view (legacy flat): one node per (proto, port, app). Kept for backward compat if API sends service_nodes. */
function estimateServiceNodeHeight(data: any, expanded: boolean): number {
  if (!expanded) return BASE_EP_HEIGHT;
  let h = 44 + 16;
  const byPair: any[] = Array.isArray(data?.by_pair) ? data.by_pair : [];
  h += 24;
  h += Math.min(byPair.length * 24, 240);
  return Math.max(h, BASE_EP_HEIGHT);
}

function ServiceNode({ id, data }: NodeProps) {
  const expanded = !!(data?.expanded ?? data?.isExpanded);
  const onToggle = typeof data?.onToggle === 'function' ? (data.onToggle as () => void) : undefined;
  const label = (data?.label ?? '—') as string;
  const appDisplay = data?.app != null && String(data.app).trim() !== '' ? String(data.app).trim() : '—';
  const count = Number(data?.count) ?? 0;
  const byPair: Array<{ source_label?: string; dest_label?: string; src_ip?: string; dest_ip?: string; count?: number }> = Array.isArray(data?.by_pair) ? data.by_pair : [];

  return (
    <>
      <Handle type="target" position={Position.Left} id={HANDLE_LEFT} />
      <div className="rounded-xl border border-border bg-card shadow-sm hover:shadow-md transition-shadow overflow-hidden min-w-[140px] max-w-[220px]">
        <div
          className={cn(
            'flex items-center gap-1.5 px-3 py-2',
            onToggle && 'cursor-pointer',
          )}
          onClick={onToggle}
          role={onToggle ? 'button' : undefined}
          onKeyDown={onToggle ? (e) => e.key === 'Enter' && onToggle() : undefined}
          tabIndex={onToggle ? 0 : undefined}
        >
          <span className="text-sm font-semibold text-card-foreground truncate flex-1">{label}</span>
          {count > 0 && (
            <span className="inline-flex items-center justify-center rounded-full bg-primary/15 text-primary text-[10px] font-semibold px-1.5 py-0.5 min-w-[20px] flex-shrink-0">
              {count.toLocaleString()}
            </span>
          )}
          {onToggle && (
            <span className={cn('block transition-transform duration-200 flex-shrink-0', expanded && 'rotate-90')}>
              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
            </span>
          )}
        </div>
        <div className="px-3 pb-1.5 -mt-0.5 text-[11px] text-muted-foreground truncate">{appDisplay}</div>
        {expanded && byPair.length > 0 && (
          <div className="mt-0 pt-2 border-t border-border px-2 pb-2">
            <div className="text-[10px] font-semibold text-card-foreground mb-1">By source & destination</div>
            <div className="overflow-auto max-h-[240px] rounded border border-border/50">
              <table className="w-full text-[10px] border-collapse">
                <thead className="sticky top-0 bg-muted/80 z-[1]">
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="text-left px-1.5 py-1 font-medium">Source</th>
                    <th className="text-left px-1.5 py-1 font-medium">Destination</th>
                    <th className="text-right px-1.5 py-1 font-medium">Count</th>
                    <th className="w-7 px-0.5 py-1" title="Inspect raw logs" />
                  </tr>
                </thead>
                <tbody>
                  {byPair.map((row, i) => (
                    <tr key={i} className={cn('border-b border-border/50', i % 2 === 0 && 'bg-muted/20')}>
                      <td className="px-1.5 py-1 truncate max-w-[80px]" title={row.source_label ?? '—'}>{row.source_label ?? '—'}</td>
                      <td className="px-1.5 py-1 truncate max-w-[80px]" title={row.dest_label ?? '—'}>{row.dest_label ?? '—'}</td>
                      <td className="px-1.5 py-1 text-right tabular-nums">{row.count ?? 0}</td>
                      <td className="w-7 px-0.5 py-1">
                        {typeof data?.onInspect === 'function' && row.src_ip && row.dest_ip && (
                          <button type="button" onClick={(e) => { e.stopPropagation(); data.onInspect(row); }} className="p-0.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground" title="Inspect raw logs" aria-label="Inspect raw logs">
                            <Search className="w-3 h-3" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        {expanded && byPair.length === 0 && (
          <div className="mt-0 pt-2 border-t border-border px-2 pb-2 text-[10px] italic text-muted-foreground">No flows in range</div>
        )}
      </div>
    </>
  );
}

/** Services v2: Port node (proto/port). Compact pill + count badge + apps badge + chevron to expand/collapse apps. */
const SERVICE_PORT_HEIGHT = 40;
function ServicePortNode({ id, data }: NodeProps) {
  const expanded = !!(data?.expanded ?? data?.isExpanded);
  const onToggle = typeof data?.onToggle === 'function' ? (data.onToggle as () => void) : undefined;
  const label = (data?.label ?? '—') as string;
  const count = Number(data?.count) ?? 0;
  const destIpCount = data?.dest_ip_count != null ? Number(data.dest_ip_count) : undefined;
  const appCount = Number(data?.appCount) ?? 0;
  const hasApps = appCount > 0;

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onToggle && hasApps) onToggle();
  };

  return (
    <>
      <Handle type="target" position={Position.Left} id={HANDLE_LEFT} />
      <Handle type="source" position={Position.Right} id={HANDLE_RIGHT} />
      <div
        className={cn(
          'flex items-center justify-between gap-3 min-w-[200px] max-w-[280px] px-4 py-3 rounded-xl border border-border bg-card shadow-sm transition-shadow',
          onToggle && hasApps && 'cursor-pointer hover:shadow-md hover:border-muted-foreground/40',
        )}
        onClick={handleClick}
        role={onToggle && hasApps ? 'button' : undefined}
        onKeyDown={onToggle && hasApps ? (e) => { if (e.key === 'Enter') { e.preventDefault(); onToggle(); } } : undefined}
        tabIndex={onToggle && hasApps ? 0 : undefined}
      >
        <span className="font-medium text-card-foreground whitespace-nowrap flex-shrink-0">{label}</span>
        <div className="flex items-center gap-2 ml-auto flex-shrink-0">
          {(destIpCount ?? count) > 0 && (
            <span
              className="inline-flex items-center justify-center rounded-full bg-primary/15 text-primary text-[10px] font-semibold px-1.5 py-0.5 min-w-[20px]"
              title="Unique destination IPs"
            >
              {(destIpCount ?? count).toLocaleString()}
            </span>
          )}
          {hasApps && (
            <span className="text-muted-foreground text-sm whitespace-nowrap" title={`${appCount} app(s)`}>
              {appCount} app{appCount !== 1 ? 's' : ''}
            </span>
          )}
          {onToggle && hasApps && (
            <span className={cn('block transition-transform duration-200', expanded && 'rotate-90')}>
              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
            </span>
          )}
        </div>
      </div>
    </>
  );
}

const ROWS_PER_PAGE = 10;
const TABLE_ROW_HEIGHT = 24;
const TABLE_HEADER_HEIGHT = 24;
const PAGER_HEIGHT = 36;

/** Services v2: App node (app or —). Expandable with Source + Destination table + pagination. */
function estimateServiceAppNodeHeight(data: any, expanded: boolean): number {
  if (!expanded) return BASE_EP_HEIGHT;
  let h = 44 + 16;
  const byPair: any[] = Array.isArray(data?.by_pair) ? data.by_pair : [];
  h += 24; // section title
  if (byPair.length <= ROWS_PER_PAGE) {
    h += TABLE_HEADER_HEIGHT + byPair.length * TABLE_ROW_HEIGHT;
  } else {
    h += TABLE_HEADER_HEIGHT + ROWS_PER_PAGE * TABLE_ROW_HEIGHT + PAGER_HEIGHT;
  }
  return Math.max(h, BASE_EP_HEIGHT);
}

function ServiceAppNode({ id, data }: NodeProps) {
  const expanded = !!(data?.expanded ?? data?.isExpanded);
  const onToggle = typeof data?.onToggle === 'function' ? (data.onToggle as () => void) : undefined;
  const label = (data?.label ?? '—') as string;
  const count = Number(data?.count) ?? 0;
  const destIpCount = data?.dest_ip_count != null ? Number(data.dest_ip_count) : undefined;
  const byPair: Array<{ source_label?: string; dest_label?: string; src_ip?: string; dest_ip?: string; count?: number }> = Array.isArray(data?.by_pair) ? data.by_pair : [];

  const [page, setPage] = useState(1);

  React.useEffect(() => {
    setPage(1);
  }, [expanded, id, data?.by_pair]);

  const totalRows = byPair.length;
  const totalPages = Math.max(1, Math.ceil(totalRows / ROWS_PER_PAGE));
  const start = (page - 1) * ROWS_PER_PAGE;
  const end = start + ROWS_PER_PAGE;
  const pageRows = byPair.slice(start, end);

  React.useEffect(() => {
    if (page > totalPages) setPage(Math.max(1, totalPages));
  }, [page, totalPages]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!expanded || totalRows <= ROWS_PER_PAGE) return;
    if (e.key === 'ArrowLeft') { e.preventDefault(); setPage((p) => Math.max(1, p - 1)); }
    if (e.key === 'ArrowRight') { e.preventDefault(); setPage((p) => Math.min(totalPages, p + 1)); }
  };

  return (
    <>
      <Handle type="target" position={Position.Left} id={HANDLE_LEFT} />
      <div
        className={cn(
          'rounded-xl border border-border bg-card shadow-sm hover:shadow-md transition-shadow overflow-hidden',
          expanded ? 'min-w-[520px] w-[520px]' : 'min-w-[240px] max-w-[280px]',
        )}
      >
        <div
          className={cn(
            'flex items-center gap-1.5 px-3 py-2',
            onToggle && 'cursor-pointer',
          )}
          onClick={onToggle}
          role={onToggle ? 'button' : undefined}
          onKeyDown={onToggle ? (e) => e.key === 'Enter' && onToggle() : undefined}
          tabIndex={onToggle ? 0 : undefined}
        >
          <span className="text-sm font-semibold text-card-foreground truncate flex-1">{label}</span>
          {(destIpCount ?? count) > 0 && (
            <span
              className="inline-flex items-center justify-center rounded-full bg-primary/15 text-primary text-[10px] font-semibold px-1.5 py-0.5 min-w-[20px] flex-shrink-0"
              title="Unique destination IPs"
            >
              {(destIpCount ?? count).toLocaleString()}
            </span>
          )}
          {onToggle && (
            <span className={cn('block transition-transform duration-200 flex-shrink-0', expanded && 'rotate-90')}>
              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
            </span>
          )}
        </div>
        {expanded && byPair.length > 0 && (
          <div className="mt-0 pt-2 border-t border-border px-2 pb-2" tabIndex={0} onKeyDown={handleKeyDown}>
            <div className="text-[10px] font-semibold text-card-foreground mb-1">By source & destination</div>
            <div
              className="rounded border border-border/50 overflow-hidden"
              style={{
                height: totalRows <= ROWS_PER_PAGE
                  ? TABLE_HEADER_HEIGHT + totalRows * TABLE_ROW_HEIGHT
                  : TABLE_HEADER_HEIGHT + ROWS_PER_PAGE * TABLE_ROW_HEIGHT,
                maxHeight: 320,
              }}
            >
              <table className="w-full text-[10px] border-collapse table-fixed">
                <thead className="sticky top-0 bg-muted/80 z-[1]">
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="text-left px-2 py-1 font-medium w-[180px]">Source</th>
                    <th className="text-left px-2 py-1 font-medium w-[200px]">Destination</th>
                    <th className="text-right px-2 py-1 font-medium w-[80px]">Count</th>
                    <th className="w-8 px-1 py-1" title="Inspect raw logs" />
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((row, i) => (
                    <tr key={start + i} className={cn('border-b border-border/50', (start + i) % 2 === 0 && 'bg-muted/20')}>
                      <td className="px-2 py-1 w-[180px] min-w-[180px] whitespace-nowrap" title={row.source_label ?? '—'}>{row.source_label ?? '—'}</td>
                      <td className="px-2 py-1 w-[200px] min-w-[200px] whitespace-nowrap" title={row.dest_label ?? '—'}>{row.dest_label ?? '—'}</td>
                      <td className="px-2 py-1 w-[80px] min-w-[80px] text-right tabular-nums whitespace-nowrap">{row.count ?? 0}</td>
                      <td className="w-8 px-1 py-1">
                        {typeof data?.onInspect === 'function' && row.src_ip && row.dest_ip && (
                          <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); data.onInspect(row); }}
                            className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                            title="Inspect raw logs"
                            aria-label="Inspect raw logs"
                          >
                            <Search className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalRows > ROWS_PER_PAGE && (
              <div className="flex items-center justify-between gap-2 mt-2 h-9">
                <button
                  type="button"
                  disabled={page === 1}
                  onClick={(e) => { e.stopPropagation(); setPage((p) => Math.max(1, p - 1)); }}
                  className="px-2 py-1 text-xs font-medium rounded-md hover:bg-muted disabled:opacity-50 disabled:pointer-events-none text-foreground"
                >
                  Prev
                </button>
                <span className="text-xs text-muted-foreground tabular-nums">
                  {start + 1}–{Math.min(end, totalRows)} of {totalRows}
                </span>
                <button
                  type="button"
                  disabled={page === totalPages}
                  onClick={(e) => { e.stopPropagation(); setPage((p) => Math.min(totalPages, p + 1)); }}
                  className="px-2 py-1 text-xs font-medium rounded-md hover:bg-muted disabled:opacity-50 disabled:pointer-events-none text-foreground"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        )}
        {expanded && byPair.length === 0 && (
          <div className="mt-0 pt-2 border-t border-border px-2 pb-2 text-[10px] italic text-muted-foreground">No flows in range</div>
        )}
      </div>
    </>
  );
}

/**
 * Estimate the rendered height of an InterfaceGroupNode based on
 * its local devices and their expansion state.
 */
function estimateIGNodeHeight(
  localDevices: any[],
  expandedNodeIds: Set<string>,
): number {
  // Header: dest_if + dest_zone lines + padding
  let h = 48;
  if (localDevices.length === 0) return h;
  // device list padding
  h += 8;
  for (const dev of localDevices) {
    const isExp = expandedNodeIds.has(dev.id);
    if (!isExp) {
      h += 28; // collapsed device row
    } else {
      h += estimateNodeHeight(dev, true, true);
    }
  }
  h += 8; // bottom padding
  return h;
}

/** Stack nodes vertically: each node's y = previous y + previous layoutHeight + gap */
function layoutColumn(
  columnNodes: { position: { y: number }; data: { layoutHeight?: number } }[],
  startY: number,
  gap: number,
) {
  let y = startY;
  const defaultH = ROW_HEIGHT;
  for (const n of columnNodes) {
    n.position.y = y;
    y += (n.data?.layoutHeight ?? defaultH) + gap;
  }
}

/** Shift column so its vertical center aligns with centerY */
function centerColumnAround(
  columnNodes: { position: { y: number }; data: { layoutHeight?: number } }[],
  centerY: number,
) {
  if (columnNodes.length === 0) return;
  const defaultH = ROW_HEIGHT;
  const top = columnNodes[0].position.y;
  const last = columnNodes[columnNodes.length - 1];
  const bottom = last.position.y + (last.data?.layoutHeight ?? defaultH);
  const columnCenter = (top + bottom) / 2;
  const delta = centerY - columnCenter;
  columnNodes.forEach((n) => (n.position.y += delta));
}

function InterfaceGroupNode({ data }: NodeProps) {
  const devices: any[] = data?.local_devices || [];
  const hasRouter = !!data?.has_router;
  const expandedNodeIds: Set<string> = data?.expandedNodeIds || new Set();
  const toggleNode: (id: string) => void = data?.onToggleDevice || (() => {});
  const onSetAsDest = data?.onSetAsDest;

  return (
    <div className="rounded-xl border border-border bg-card shadow-sm min-w-[180px] max-w-[220px]">
      <Handle type="target" position={Position.Left} id={HANDLE_LEFT} />
      {hasRouter && <Handle type="source" position={Position.Right} id={HANDLE_RIGHT} />}

      {/* Header */}
      <div className={cn('px-3 py-2', devices.length > 0 && 'border-b border-border')}>
        {data?.dest_if && (
          <div className="text-xs font-semibold text-card-foreground">If: {data.dest_if}</div>
        )}
        {data?.dest_zone && (
          <div className="text-xs text-muted-foreground">Zone: {data.dest_zone}</div>
        )}
        {!data?.dest_if && !data?.dest_zone && (
          <div className="text-xs text-muted-foreground">unknown</div>
        )}
      </div>

      {/* Local devices */}
      {devices.length > 0 && (
        <div className="px-2 py-1 space-y-0.5">
          {devices.map((dev: any) => {
            const isExp = expandedNodeIds.has(dev.id);
            const expandable = !!(
              (dev.mac && String(dev.mac).trim()) ||
              (Array.isArray(dev.services) && dev.services.length > 0) ||
              (Array.isArray(dev.source_breakdown) && dev.source_breakdown.length > 0)
            );
            return (
              <div key={dev.id}>
                <div
                  className={cn(
                    'flex items-center gap-1.5 px-1.5 py-1 rounded-md text-xs transition-colors',
                    expandable && 'cursor-pointer hover:bg-accent/50',
                    isExp && 'bg-accent/30',
                  )}
                  onClick={expandable ? () => toggleNode(dev.id) : undefined}
                >
                  <span className="font-medium text-card-foreground truncate flex-1">
                    {dev.label ?? dev.ip ?? '—'}
                  </span>
                  {expandable && (
                    <span className={cn('block transition-transform duration-200 text-muted-foreground', isExp && 'rotate-90')}>
                      <ChevronRight className="w-3 h-3" />
                    </span>
                  )}
                </div>
                {isExp && (
                  <div className="ml-1.5 pl-2 border-l border-border/50 mt-0.5 mb-1 space-y-1 text-[10px] text-muted-foreground leading-relaxed">
                    {dev.device_name && String(dev.device_name).trim() !== '' && (
                      <div>Device: <span className="text-card-foreground">{dev.device_name}</span></div>
                    )}
                    {dev.ip && <div>IP: <span className="text-card-foreground">{dev.ip}</span></div>}
                    {dev.mac && <div>MAC: <span className="text-card-foreground">{dev.mac}</span></div>}
                    {/* Identification (DEVICE logs / overrides): 2-col grid, only when values exist */}
                    {(() => {
                      const vendor = (dev.vendor ?? dev.identification?.device_vendor ?? '').toString().trim();
                      const typeName = (dev.type_name ?? dev.identification?.device_type_name ?? '').toString().trim();
                      const osName = (dev.os_name ?? dev.identification?.device_os_name ?? '').toString().trim();
                      const brand = (dev.brand ?? dev.identification?.device_brand ?? '').toString().trim();
                      const model = (dev.model ?? dev.identification?.device_model ?? '').toString().trim();
                      const rows = [
                        vendor && { label: 'Vendor', value: vendor },
                        typeName && { label: 'Type', value: typeName },
                        osName && { label: 'OS', value: osName },
                        brand && { label: 'Brand', value: brand },
                        model && { label: 'Model', value: model },
                      ].filter(Boolean) as { label: string; value: string }[];
                      if (rows.length === 0) return null;
                      return (
                        <div className="mt-1">
                          <div className="font-semibold text-card-foreground mb-0.5">Identification</div>
                          <div className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5">
                            {rows.map((r) => (
                              <React.Fragment key={r.label}>
                                <span className="text-muted-foreground">{r.label}</span>
                                <span className="text-card-foreground">{r.value}</span>
                              </React.Fragment>
                            ))}
                          </div>
                        </div>
                      );
                    })()}
                    {Array.isArray(dev.services) && dev.services.length > 0 && (
                      <div className="mt-1">
                        <div className="font-semibold text-card-foreground mb-0.5">Services</div>
                        {dev.services.map((svc: any, i: number) => {
                          const proto = (svc.proto ?? 'ip').toUpperCase();
                          const port = svc.port ?? 0;
                          const app = svc.app_name != null && String(svc.app_name).trim() !== '' ? String(svc.app_name).trim() : null;
                          const count = svc.count ?? 0;
                          return <div key={i}>{app ? `${proto}/${port} — ${app} (${count})` : `${proto}/${port} (${count})`}</div>;
                        })}
                      </div>
                    )}
                    {Array.isArray(dev.source_breakdown) && dev.source_breakdown.length > 0 && (
                      <div className="mt-1">
                        <div className="font-semibold text-card-foreground mb-0.5">By source</div>
                        <div className="overflow-x-auto max-h-[120px] overflow-y-auto">
                          <table className="w-full text-[9px] border-collapse">
                            <thead>
                              <tr className="border-b border-border text-muted-foreground">
                                <th className="text-left px-1 py-0.5 font-medium">Source</th>
                                <th className="text-left px-1 py-0.5 font-medium">Port</th>
                                <th className="text-left px-1 py-0.5 font-medium">App</th>
                                <th className="text-right px-1 py-0.5 font-medium">Count</th>
                                <th className="w-6 px-0.5 py-0.5" title="Inspect raw logs" />
                              </tr>
                            </thead>
                            <tbody>
                              {dev.source_breakdown.flatMap((src: any, si: number) =>
                                (src.services || []).map((svc: any, vi: number) => (
                                  <tr key={`${si}-${vi}`} className="border-b border-border/30">
                                    <td className="px-1 py-0.5">{vi === 0 ? (src.source_label ?? '—') : ''}</td>
                                    <td className="px-1 py-0.5">{(svc.proto ?? 'ip').toUpperCase()}/{svc.port ?? 0}</td>
                                    <td className="px-1 py-0.5">{svc.app_name != null && String(svc.app_name).trim() !== '' ? String(svc.app_name).trim() : '—'}</td>
                                    <td className="px-1 py-0.5 text-right tabular-nums">{svc.count ?? 0}</td>
                                    <td className="w-6 px-0.5 py-0.5">
                                      {typeof dev.onInspect === 'function' && src.src_ip && dev.ip && (
                                        <button
                                          type="button"
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            dev.onInspect({
                                              source_label: src.source_label,
                                              src_ip: src.src_ip,
                                              proto: svc.proto ?? 'TCP',
                                              port: svc.port ?? 0,
                                              app_name: svc.app_name,
                                            });
                                          }}
                                          className="p-0.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                                          title="Inspect raw logs"
                                          aria-label="Inspect raw logs"
                                        >
                                          <Search className="w-3 h-3" />
                                        </button>
                                      )}
                                    </td>
                                  </tr>
                                ))
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                    {onSetAsDest && dev.id && (
                      <button
                        type="button"
                        className="mt-1 w-full text-[10px] font-medium px-2 py-0.5 rounded bg-primary/15 text-primary hover:bg-primary/25 transition-colors"
                        onClick={(e) => { e.stopPropagation(); onSetAsDest(String(dev.id).replace(/^right-/, '')); }}
                      >
                        Use as Dest
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ── Collapsed sources "+X more" / "Show less" node ── */
function CollapsedSourcesNode({ data }: NodeProps) {
  return (
    <div
      className="flex items-center gap-2 px-3 py-2 rounded-xl border border-dashed border-border bg-card/80 shadow-sm cursor-pointer hover:shadow-md hover:border-muted-foreground/40 transition-all min-w-[100px]"
      onClick={() => data?.onClick?.()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && data?.onClick?.()}
    >
      <Handle type="source" position={Position.Right} id={HANDLE_RIGHT} />
      <ChevronDown className={cn('w-3.5 h-3.5 text-muted-foreground transition-transform', data?.expanded && 'rotate-180')} />
      <span className="text-sm font-medium text-muted-foreground">{data?.label ?? '+N more'}</span>
    </div>
  );
}

const nodeTypes = {
  leftEndpoint: LeftEndpointNode,
  rightEndpoint: RightEndpointNode,
  firewall: FirewallNode,
  routerBucket: RouterBucketNode,
  interfaceGroup: InterfaceGroupNode,
  serviceNode: ServiceNode,
  servicePortNode: ServicePortNode,
  serviceAppNode: ServiceAppNode,
  collapsedSourcesNode: CollapsedSourcesNode,
};

const edgeTypes = {
  metricEdge: MetricEdge,
};

const queryClient = new QueryClient();

const API = '/api';

type FilterKind = 'zone' | 'interface' | 'endpoint' | 'any';

/* ── Styled select wrapper ── */
function StyledSelect({
  value,
  onChange,
  disabled,
  children,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      className={cn(
        'h-9 rounded-lg border border-border bg-input px-3 text-sm text-foreground',
        'focus:outline-none focus:ring-2 focus:ring-ring/50 focus:border-ring',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        'appearance-none',
        className,
      )}
    >
      {children}
    </select>
  );
}

/* ── Label helper ── */
function FieldLabel({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

/* ── Device Inventory Panel ── */
function DeviceInventoryPanel({
  device,
  timeFrom,
  timeTo,
  onRouterMacsChanged,
}: {
  device: string;
  timeFrom: string;
  timeTo: string;
  onRouterMacsChanged: () => void;
}) {
  const [confirmMac, setConfirmMac] = useState<string | null>(null);

  const fromISO = timeFrom ? new Date(timeFrom).toISOString() : '';
  const toISO = timeTo ? new Date(timeTo).toISOString() : '';

  const { data: inventory = [], refetch: refetchInventory } = useQuery({
    queryKey: ['inventory/macs', device, fromISO, toISO],
    queryFn: async () => {
      const params = new URLSearchParams({ device });
      if (fromISO) params.set('time_from', fromISO);
      if (toISO) params.set('time_to', toISO);
      const res = await fetch(`${API}/inventory/macs?${params}`);
      if (!res.ok) return [];
      return res.json();
    },
    enabled: !!device,
  });

  const { data: routerMacs = [], refetch: refetchRouterMacs } = useQuery({
    queryKey: ['router-macs', device],
    queryFn: async () => {
      const res = await fetch(`${API}/router-macs?device=${encodeURIComponent(device)}`);
      if (!res.ok) return [];
      return res.json();
    },
    enabled: !!device,
  });

  const handleFlag = async (mac: string) => {
    try {
      await fetch(`${API}/router-macs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device, mac, direction: 'src' }),
      });
      refetchInventory();
      refetchRouterMacs();
      onRouterMacsChanged();
    } finally {
      setConfirmMac(null);
    }
  };

  const handleUnflag = async (macId: number) => {
    await fetch(`${API}/router-macs/${macId}`, { method: 'DELETE' });
    refetchInventory();
    refetchRouterMacs();
    onRouterMacsChanged();
  };

  const routerMacMap: Record<string, number> = {};
  routerMacs.forEach((rm: { id: number; mac: string }) => {
    routerMacMap[rm.mac] = rm.id;
  });

  if (!device) {
    return (
      <div className="text-sm text-muted-foreground text-center py-6">
        Select a firewall device to view MAC inventory.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Flagged Router MACs summary */}
      {routerMacs.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs font-medium text-muted-foreground">Active router MACs:</span>
          {routerMacs.map((rm: { id: number; mac: string }) => (
            <span key={rm.id} className="inline-flex items-center gap-1.5 text-xs bg-primary/10 text-primary px-2 py-1 rounded-md">
              <Router className="w-3 h-3" />
              {rm.mac}
              <button
                type="button"
                className="ml-0.5 p-0.5 rounded hover:bg-destructive/20 hover:text-destructive transition-colors"
                title="Remove router MAC flag"
                onClick={() => handleUnflag(rm.id)}
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}

      {/* Inventory table */}
      {inventory.length === 0 ? (
        <div className="text-sm text-muted-foreground text-center py-4">
          No source MACs found in the selected time range.
        </div>
      ) : (
        <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
          <table className="w-full text-sm border-collapse">
            <thead className="sticky top-0 bg-card z-10">
              <tr className="border-b border-border text-muted-foreground">
                <th className="text-left px-3 py-2 font-medium">MAC</th>
                <th className="text-right px-3 py-2 font-medium">IP count</th>
                <th className="text-left px-3 py-2 font-medium">Example IPs</th>
                <th className="text-left px-3 py-2 font-medium">Last seen</th>
                <th className="text-center px-3 py-2 font-medium">Status</th>
                <th className="text-center px-3 py-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {inventory.map((row: any) => {
                const isFlagged = !!routerMacMap[row.mac];
                const flaggedId = routerMacMap[row.mac];
                return (
                  <tr key={row.mac} className={cn(
                    'border-b border-border/50 transition-colors',
                    isFlagged && 'bg-primary/5',
                    row.suggested_router && !isFlagged && 'bg-yellow-500/5',
                  )}>
                    <td className="px-3 py-2 font-mono text-xs">{row.mac}</td>
                    <td className="px-3 py-2 text-right tabular-nums font-semibold">{row.distinct_ip_count}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {(row.sample_ips || []).join(', ')}
                      {row.distinct_ip_count > 3 && <span className="italic"> +{row.distinct_ip_count - 3} more</span>}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {row.last_seen ? String(row.last_seen).slice(0, 19).replace('T', ' ') : '—'}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {isFlagged ? (
                        <span className="inline-flex items-center gap-1 text-xs text-primary font-medium">
                          <Check className="w-3 h-3" /> Router MAC
                        </span>
                      ) : row.suggested_router ? (
                        <span className="inline-flex items-center gap-1 text-xs text-yellow-600 font-medium"
                              title="Many IPs share this MAC. This usually indicates the next-hop router MAC, not distinct devices.">
                          <Info className="w-3 h-3" /> Suggested
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {isFlagged ? (
                        <button
                          type="button"
                          className="text-xs px-2 py-1 rounded-md bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors"
                          onClick={() => handleUnflag(flaggedId)}
                        >
                          Unflag
                        </button>
                      ) : confirmMac === row.mac ? (
                        <div className="flex items-center gap-1 justify-center">
                          <button
                            type="button"
                            className="text-xs px-2 py-1 rounded-md bg-primary text-primary-foreground hover:opacity-90 transition-colors"
                            onClick={() => handleFlag(row.mac)}
                          >
                            Confirm
                          </button>
                          <button
                            type="button"
                            className="text-xs px-2 py-1 rounded-md bg-muted text-muted-foreground hover:bg-accent transition-colors"
                            onClick={() => setConfirmMac(null)}
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          className={cn(
                            'text-xs px-2 py-1 rounded-md transition-colors',
                            row.suggested_router
                              ? 'bg-yellow-500/15 text-yellow-700 hover:bg-yellow-500/25'
                              : 'bg-muted text-muted-foreground hover:bg-accent',
                          )}
                          onClick={() => setConfirmMac(row.mac)}
                          title="Many IPs share this MAC. This usually indicates the next-hop router MAC, not distinct devices."
                        >
                          Flag as Router MAC
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ── Dashboard Page ── */
function DashboardPage({
  initialDeviceId = null,
  onConsumeInitialDevice,
  initialTimeRange = null,
  onConsumeInitialTimeRange,
}: {
  initialDeviceId?: string | null;
  onConsumeInitialDevice?: () => void;
  initialTimeRange?: { timeMin: string; timeMax: string } | null;
  onConsumeInitialTimeRange?: () => void;
} = {}) {
  const { data: deviceGroups = [], refetch: refetchDeviceGroups } = useQuery({
    queryKey: ['devices/groups'],
    queryFn: async () => {
      const res = await fetch(`${API}/devices/groups`);
      if (!res.ok) throw new Error('Failed to load device groups');
      return res.json();
    },
  });

  const { data: haCandidates = [] } = useQuery({
    queryKey: ['devices/ha-candidates'],
    queryFn: async () => {
      const res = await fetch(`${API}/devices/ha-candidates`);
      if (!res.ok) return [];
      return res.json();
    },
  });

  const [device, setDevice] = useState('');
  React.useEffect(() => {
    if (initialDeviceId && initialDeviceId.trim()) {
      setDevice(initialDeviceId.trim());
      onConsumeInitialDevice?.();
    }
  }, [initialDeviceId, onConsumeInitialDevice]);

  const [haBannerDismissed, setHaBannerDismissed] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem('ha-banner-dismissed');
      if (raw) return new Set(JSON.parse(raw));
    } catch (_) {}
    return new Set();
  });
  const [srcKind, setSrcKind] = useState<FilterKind>('zone');
  const [srcValue, setSrcValue] = useState('');
  const [dstKind, setDstKind] = useState<FilterKind>('any');
  const [dstValue, setDstValue] = useState('');
  const [timeFrom, setTimeFrom] = useState(() => {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0);
    const pad = (n: number) => n.toString().padStart(2, '0');
    return `${start.getFullYear()}-${pad(start.getMonth() + 1)}-${pad(start.getDate())}T${pad(start.getHours())}:${pad(start.getMinutes())}`;
  });
  const [timeTo, setTimeTo] = useState(() => {
    const now = new Date();
    const end = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59);
    const pad = (n: number) => n.toString().padStart(2, '0');
    return `${end.getFullYear()}-${pad(end.getMonth() + 1)}-${pad(end.getDate())}T${pad(end.getHours())}:${pad(end.getMinutes())}`;
  });

  React.useEffect(() => {
    if (initialTimeRange?.timeMin && initialTimeRange?.timeMax) {
      setTimeFrom(isoToDatetimeLocal(initialTimeRange.timeMin));
      setTimeTo(isoToDatetimeLocal(initialTimeRange.timeMax));
      onConsumeInitialTimeRange?.();
    }
  }, [initialTimeRange?.timeMin, initialTimeRange?.timeMax, onConsumeInitialTimeRange]);

  const [view, setView] = useState<'original' | 'translated'>('original');
  const [destView, setDestView] = useState<'endpoints' | 'services'>('services');
  const [graphResult, setGraphResult] = useState<any>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [showInventory, setShowInventory] = useState(false);

  const graphAbortRef = React.useRef<AbortController | null>(null);

  // When Source Firewall is cleared, reset all dashboard state and abort any in-flight request
  React.useEffect(() => {
    if (device != null && device !== '') return;
    graphAbortRef.current?.abort();
    graphAbortRef.current = null;
    setSrcKind('zone');
    setSrcValue('');
    setDestView('services');
    setDstKind('any');
    setDstValue('');
    setGraphResult(null);
    setGraphError(null);
    setGraphLoading(false);
  }, [device]);

  const hasDeviceAndTime = !!device && !!timeFrom && !!timeTo;

  // Router MAC rules count
  const { data: routerMacRules = [], refetch: refetchRouterMacs } = useQuery({
    queryKey: ['router-macs', device],
    queryFn: async () => {
      const res = await fetch(`${API}/router-macs?device=${encodeURIComponent(device)}`);
      if (!res.ok) return [];
      return res.json();
    },
    enabled: !!device,
  });
  const routerMacCount = routerMacRules.length;

  const { data: zones = [] } = useQuery({
    queryKey: ['endpoints', device, 'zone'],
    queryFn: async () => {
      const res = await fetch(`${API}/endpoints?device=${encodeURIComponent(device)}&kind=zone`);
      if (!res.ok) return [];
      return res.json();
    },
    enabled: !!device,
  });
  const { data: interfaces = [] } = useQuery({
    queryKey: ['endpoints', device, 'interface'],
    queryFn: async () => {
      const res = await fetch(`${API}/endpoints?device=${encodeURIComponent(device)}&kind=interface`);
      if (!res.ok) return [];
      return res.json();
    },
    enabled: !!device,
  });
  const { data: endpointList = [] } = useQuery({
    queryKey: ['endpoints/list', device, timeFrom, timeTo],
    queryFn: async () => {
      const fromISO = new Date(timeFrom).toISOString();
      const toISO = new Date(timeTo).toISOString();
      const res = await fetch(
        `${API}/endpoints/list?device=${encodeURIComponent(device)}&time_from=${encodeURIComponent(fromISO)}&time_to=${encodeURIComponent(toISO)}&has_mac=true`
      );
      if (!res.ok) return [];
      return res.json();
    },
    enabled: hasDeviceAndTime,
  });

  const srcOptions =
    srcKind === 'zone' ? zones : srcKind === 'interface' ? interfaces : endpointList;
  const dstOptions =
    dstKind === 'zone' ? zones : dstKind === 'interface' ? interfaces : endpointList;

  React.useEffect(() => {
    if (srcKind === 'endpoint' && endpointList.length > 0) {
      const ids = new Set(endpointList.map((e: { id: number }) => String(e.id)));
      if (srcValue && !ids.has(srcValue)) setSrcValue('');
    }
    if (srcKind === 'endpoint' && endpointList.length === 0 && srcValue) setSrcValue('');
  }, [srcKind, endpointList, srcValue]);
  React.useEffect(() => {
    if (dstKind === 'endpoint' && endpointList.length > 0) {
      const ids = new Set(endpointList.map((e: { id: number }) => String(e.id)));
      if (dstValue && !ids.has(dstValue)) setDstValue('');
    }
    if (dstKind === 'endpoint' && endpointList.length === 0 && dstValue) setDstValue('');
  }, [dstKind, endpointList, dstValue]);

  const deviceLabel = React.useMemo(() => {
    const g = (deviceGroups as { id: string; label: string }[]).find((x) => x.id === device);
    return g ? g.label : (device || '');
  }, [deviceGroups, device]);

  const handleDeviceChange = (v: string) => {
    setDevice(v);
    setSrcValue('');
    setDstValue('');
  };

  const enableHaCluster = React.useCallback(async (base: string) => {
    try {
      const res = await fetch(`${API}/devices/groups/enable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base, enabled: true }),
      });
      if (!res.ok) throw new Error(await res.text());
      await refetchDeviceGroups();
    } catch (e) {
      console.error('Failed to enable HA cluster:', e);
    }
  }, [refetchDeviceGroups]);

  const dismissHaBanner = React.useCallback((base: string) => {
    setHaBannerDismissed((prev) => {
      const next = new Set(prev);
      next.add(base);
      try {
        localStorage.setItem('ha-banner-dismissed', JSON.stringify([...next]));
      } catch (_) {}
      return next;
    });
  }, []);
  const handleSrcKindChange = (v: FilterKind) => {
    setSrcKind(v);
    setSrcValue('');
  };
  const handleDstKindChange = (v: FilterKind) => {
    setDstKind(v);
    if (v === 'any') setDstValue('');
    else setDstValue('');
  };

  const canAnalyze =
    !!device &&
    !!srcValue &&
    (!!dstValue || dstKind === 'any') &&
    !!timeFrom &&
    !!timeTo &&
    !graphLoading;

  type FilterOverride = { srcKind?: FilterKind; srcValue?: string; dstKind?: FilterKind; dstValue?: string };

  const runAnalyze = React.useCallback(async (override?: FilterOverride): Promise<void> => {
    const sk = override?.srcKind ?? srcKind;
    const sv = override?.srcValue ?? srcValue;
    const dk = override?.dstKind ?? dstKind;
    const dv = override?.dstValue ?? dstValue;
    const canRun =
      !!device &&
      !!sv &&
      (!!dv || dk === 'any') &&
      !!timeFrom &&
      !!timeTo &&
      !graphLoading;
    if (!canRun) return;
    const requestedDevice = device;
    graphAbortRef.current?.abort();
    graphAbortRef.current = new AbortController();
    const signal = graphAbortRef.current.signal;
    setGraphResult(null);
    setGraphError(null);
    setGraphLoading(true);
    try {
      const fromISO = new Date(timeFrom).toISOString();
      const toISO = new Date(timeTo).toISOString();
      const params = new URLSearchParams({
        device: requestedDevice,
        src_kind: sk,
        src_value: sv,
        dst_kind: dk,
        ...(dk !== 'any' ? { dst_value: dv } : {}),
        time_from: fromISO,
        time_to: toISO,
        view,
        dest_view: destView,
      });
      const res = await fetch(`${API}/graph?${params}`, { signal });
      if (requestedDevice !== device) return;
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || 'Failed to load graph');
      }
      const data = await res.json();
      if (requestedDevice !== device) return;
      setGraphResult(data);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return;
      if (requestedDevice !== device) return;
      setGraphError((e as Error).message);
      setGraphResult(null);
      throw e;
    } finally {
      if (requestedDevice === device) setGraphLoading(false);
    }
  }, [device, srcKind, srcValue, dstKind, dstValue, timeFrom, timeTo, view, destView]);

  const applyFiltersAndAnalyze = React.useCallback(
    (next: FilterOverride) => {
      if (next.srcKind !== undefined) setSrcKind(next.srcKind);
      if (next.srcValue !== undefined) setSrcValue(next.srcValue);
      if (next.dstKind !== undefined) setDstKind(next.dstKind);
      if (next.dstValue !== undefined) setDstValue(next.dstValue);
      const merged: FilterOverride = {
        srcKind: next.srcKind ?? srcKind,
        srcValue: next.srcValue ?? srcValue,
        dstKind: next.dstKind ?? dstKind,
        dstValue: next.dstValue ?? dstValue,
      };
      runAnalyze(merged);
    },
    [runAnalyze, srcKind, srcValue, dstKind, dstValue],
  );

  const setSourceFilterFromEndpoint = React.useCallback(
    (endpointId: string) => {
      applyFiltersAndAnalyze({ srcKind: 'endpoint', srcValue: endpointId });
    },
    [applyFiltersAndAnalyze],
  );
  const setDestinationFilterFromEndpoint = React.useCallback(
    (endpointId: string) => {
      applyFiltersAndAnalyze({ dstKind: 'endpoint', dstValue: endpointId });
    },
    [applyFiltersAndAnalyze],
  );

  const haBannersToShow = React.useMemo(() => {
    const enabledBases = new Set(
      (deviceGroups as { id: string; kind: string }[])
        .filter((g) => g.kind === 'ha')
        .map((g) => (g.id as string).replace(/^ha:/, ''))
    );
    return (haCandidates as { base: string; master: string; slave: string; suggested_label: string }[]).filter(
      (c) => !enabledBases.has(c.base) && !haBannerDismissed.has(c.base)
    );
  }, [haCandidates, deviceGroups, haBannerDismissed]);

  /* Summary text for the app bar */
  const summaryParts: string[] = [];
  if (deviceLabel) summaryParts.push(deviceLabel);
  if (timeFrom && timeTo) {
    const fmt = (s: string) => s.replace('T', ' ');
    summaryParts.push(`${fmt(timeFrom)} → ${fmt(timeTo)}`);
  }
  const summaryText = summaryParts.length > 0 ? summaryParts.join(' · ') : 'No filters selected';

  return (
    <div className="flex flex-col h-[calc(100vh-56px)] min-h-[320px]">
      {/* ── Analysis Panel Drawer (collapsed summary bar or expanded config) ── */}
      <AnalysisPanelDrawer
        device={device}
        setDevice={handleDeviceChange}
        deviceLabel={deviceLabel}
        deviceGroups={deviceGroups as { id: string; label: string }[]}
        srcKind={srcKind}
        setSrcKind={setSrcKind}
        srcValue={srcValue}
        setSrcValue={setSrcValue}
        handleSrcKindChange={handleSrcKindChange}
        destView={destView}
        setDestView={setDestView}
        dstKind={dstKind}
        setDstKind={setDstKind}
        dstValue={dstValue}
        setDstValue={setDstValue}
        handleDstKindChange={handleDstKindChange}
        timeFrom={timeFrom}
        setTimeFrom={setTimeFrom}
        timeTo={timeTo}
        setTimeTo={setTimeTo}
        view={view}
        setView={setView}
        onAnalyze={runAnalyze}
        isAnalyzing={graphLoading}
        analyzeError={graphError}
        hasDeviceSelected={!!device}
        hasDeviceAndTime={hasDeviceAndTime}
        canAnalyze={canAnalyze}
        srcOptions={srcOptions}
        dstOptions={dstOptions}
        endpointList={endpointList}
        showInventory={showInventory}
        setShowInventory={setShowInventory}
        routerMacCount={routerMacCount}
      />

      {/* ── HA cluster suggestion banners ── */}
      {haBannersToShow.length > 0 && (
        <div className="mx-3 mt-2 space-y-1.5">
          {haBannersToShow.map((c: { base: string; master: string; slave: string; suggested_label: string }) => (
            <div
              key={c.base}
              className="flex flex-wrap items-center gap-2 px-3 py-2 rounded-lg bg-muted/60 border border-border text-xs text-foreground"
            >
              <span>
                Detected HA pair: <strong>{c.master}</strong> + <strong>{c.slave}</strong>. Combine into &apos;{c.suggested_label}&apos;?
              </span>
              <button
                type="button"
                className="px-2 py-1 rounded bg-primary text-primary-foreground hover:opacity-90 text-xs font-medium"
                onClick={() => enableHaCluster(c.base)}
              >
                Enable HA cluster
              </button>
              <button
                type="button"
                className="px-2 py-1 rounded border border-border hover:bg-muted text-muted-foreground"
                onClick={() => dismissHaBanner(c.base)}
              >
                Dismiss
              </button>
            </div>
          ))}
        </div>
      )}

      {/* ── Router MAC banner ── */}
      {routerMacCount > 0 && !showInventory && (
        <div className="mx-3 mt-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-primary/5 border border-primary/20 text-xs text-primary">
            <Router className="w-3.5 h-3.5 flex-shrink-0" />
            <span>Router MAC rules active: <strong>{routerMacCount}</strong></span>
            <button
              type="button"
              className="ml-auto text-primary/70 hover:text-primary underline"
              onClick={() => setShowInventory(true)}
            >
              Manage
            </button>
          </div>
        </div>
      )}

      {/* ── Device Inventory Panel ── */}
      {showInventory && device && (
        <div className="mx-3 mt-2">
          <div className="rounded-2xl border border-border bg-card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-card-foreground flex items-center gap-2">
                <Router className="w-4 h-4 text-primary" />
                Device Inventory — Source MACs
              </h3>
              <button
                type="button"
                className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setShowInventory(false)}
              >
                Close
              </button>
            </div>
            <DeviceInventoryPanel
              device={device}
              timeFrom={timeFrom}
              timeTo={timeTo}
              onRouterMacsChanged={() => {
                refetchRouterMacs();
                // Refresh endpoint list so dropdown updates
                queryClient.invalidateQueries({ queryKey: ['endpoints/list'] });
              }}
            />
          </div>
        </div>
      )}

      {/* ── Error alert (only when device selected) ── */}
      {device && graphError && (
        <div className="mx-3 mt-3">
          <div className="flex items-start gap-3 p-3 rounded-xl border border-destructive/50 bg-destructive/10 text-destructive-foreground">
            <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
            <div className="text-sm">{graphError}</div>
          </div>
        </div>
      )}

      {/* ── No device: empty state only ── */}
      {!device && (
        <div className="flex-1 flex items-center justify-center m-3">
          <div className="flex flex-col items-center gap-3 text-muted-foreground text-center max-w-sm">
            <Inbox className="w-12 h-12 opacity-40" />
            <p className="text-sm font-medium text-foreground">Select a Source Firewall</p>
            <p className="text-xs">Choose a device to analyze traffic and generate the diagram.</p>
          </div>
        </div>
      )}

      {/* ── Diagram area (when device selected): one container, overlay when analyzing ── */}
      {device && (
        <div className="flex-1 flex flex-col min-h-[300px] m-3 rounded-2xl border border-border bg-card/50 shadow-sm overflow-hidden relative">
          {/* Loading overlay: blocks interaction, centered in graph area */}
          {graphLoading && (
            <div className="absolute inset-0 z-20 flex items-center justify-center bg-background/80 backdrop-blur-[1px]">
              <div className="flex flex-col items-center gap-3 text-muted-foreground">
                <Loader2 className="w-10 h-10 animate-spin opacity-80" />
                <p className="text-sm font-medium text-foreground">Analyzing…</p>
              </div>
            </div>
          )}
          {/* Content */}
          {graphResult && !graphError && (
            (graphResult.left_nodes?.length || (graphResult.interface_groups || []).length > 0 || (graphResult.service_nodes?.length ?? 0) > 0 || (graphResult.service_port_nodes?.length ?? 0) > 0 || (graphResult.router_bucket_left?.count ?? 0) > 0 || (graphResult.edges?.length ?? 0)) > 0
              ? (
                  <DashboardDiagram
                    data={graphResult}
                    device={device}
                    deviceLabel={deviceLabel}
                    onSetSourceFilter={setSourceFilterFromEndpoint}
                    onSetDestinationFilter={setDestinationFilterFromEndpoint}
                    activeSourceEndpointId={srcKind === 'endpoint' ? srcValue : null}
                    activeDestEndpointId={dstKind === 'endpoint' ? dstValue : null}
                    embedded
                  />
                )
              : (
                  <div className="flex-1 flex items-center justify-center min-h-[280px]">
                    <div className="flex flex-col items-center gap-3 text-muted-foreground">
                      <Inbox className="w-12 h-12 opacity-40" />
                      <p className="text-sm">No traffic found for selected filters / time range.</p>
                    </div>
                  </div>
                )
          )}
          {!graphResult && !graphLoading && !graphError && (
            <div className="flex-1 flex items-center justify-center min-h-[280px]">
              <div className="flex flex-col items-center gap-3 text-muted-foreground">
                <Inbox className="w-12 h-12 opacity-40" />
                <p className="text-sm">Select filters and click Analyze to view the traffic diagram.</p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Inspect logs modal (raw logs for a service + source + destination row) ── */
function InspectLogsModal({
  open,
  onClose,
  device,
  timeFrom,
  timeTo,
  view,
  proto,
  port,
  appName,
  sourceLabel,
  destLabel,
  srcIp,
  destIp,
}: {
  open: boolean;
  onClose: () => void;
  device: string;
  timeFrom: string | null;
  timeTo: string | null;
  view: string;
  proto: string;
  port: number;
  appName: string;
  sourceLabel: string;
  destLabel: string;
  /** Canonical source IP for API (required; use label only for display) */
  srcIp: string;
  /** Canonical destination IP for API (required) */
  destIp: string;
}) {
  const [page, setPage] = useState(0);
  const limit = 100;
  const offset = page * limit;

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['graph/inspect-logs', device, timeFrom, timeTo, view, proto, port, appName, srcIp, destIp, offset, limit],
    queryFn: async () => {
      const params = new URLSearchParams({
        device,
        view,
        proto: proto || 'TCP',
        dest_port: String(port),
        src_ip: srcIp || '',
        dest_ip: destIp || '',
        limit: String(limit),
        offset: String(offset),
      });
      if (timeFrom) params.set('time_from', timeFrom);
      if (timeTo) params.set('time_to', timeTo);
      if (appName && appName !== '-' && appName.trim()) params.set('app_name', appName.trim());
      const res = await fetch(`${API}/graph/inspect-logs?${params}`);
      if (!res.ok) throw new Error(await res.text() || 'Failed to load logs');
      return res.json();
    },
    enabled: open && !!device && !!timeFrom && !!timeTo && !!srcIp && !!destIp,
  });

  const rows: any[] = data?.rows ?? [];
  const total: number = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  React.useEffect(() => {
    if (open) setPage(0);
  }, [open, srcIp, destIp, proto, port]);

  if (!open) return null;

  const title = `Raw logs: ${sourceLabel ?? '—'} → ${destLabel ?? '—'} (${proto ?? 'TCP'}/${port ?? 0}${appName && appName !== '-' ? `, app: ${appName}` : ''})`;

  return (
    <div className="fixed inset-0 z-[2000] flex items-center justify-center p-4 bg-black/50" onClick={onClose}>
      <div
        className="bg-card border border-border rounded-xl shadow-xl max-w-4xl w-full max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 className="text-sm font-semibold text-foreground truncate pr-4" title={title}>{title}</h2>
          <button type="button" onClick={onClose} className="p-1.5 rounded-md hover:bg-muted text-muted-foreground" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-auto p-4 min-h-0">
          {isLoading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          )}
          {isError && (
            <div className="py-6 text-center text-destructive text-sm">
              {(error as Error)?.message ?? 'Failed to load raw logs.'}
            </div>
          )}
          {!isLoading && !isError && rows.length === 0 && (
            <p className="text-sm text-muted-foreground py-6 text-center">No raw logs found for this selection.</p>
          )}
          {!isLoading && !isError && rows.length > 0 && (
            <>
              <div className="overflow-auto rounded border border-border">
                <table className="w-full text-xs border-collapse">
                  <thead className="sticky top-0 bg-muted/90">
                    <tr className="text-left text-muted-foreground">
                      <th className="px-2 py-1.5 font-medium">Time</th>
                      <th className="px-2 py-1.5 font-medium">Event</th>
                      <th className="px-2 py-1.5 font-medium">Src (ip:port)</th>
                      <th className="px-2 py-1.5 font-medium">Dst (ip:port)</th>
                      <th className="px-2 py-1.5 font-medium">Rule</th>
                      <th className="px-2 py-1.5 font-medium">App</th>
                      <th className="px-2 py-1.5 font-medium">Bytes</th>
                      <th className="px-2 py-1.5 font-medium w-16">Raw</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r: any, i: number) => (
                      <InspectLogRow key={r.ts_utc + String(i)} row={r} />
                    ))}
                  </tbody>
                </table>
              </div>
              {totalPages > 1 && (
                <div className="flex items-center justify-between gap-2 mt-3 text-xs text-muted-foreground">
                  <span>Page {page + 1} of {totalPages} ({total} total)</span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={page <= 0}
                      onClick={() => setPage((p) => Math.max(0, p - 1))}
                      className="px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-50 disabled:pointer-events-none"
                    >
                      Prev
                    </button>
                    <button
                      type="button"
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                      className="px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-50 disabled:pointer-events-none"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function InspectLogRow({ row }: { row: any }) {
  const [expandRaw, setExpandRaw] = useState(false);
  const raw = row.raw_line ?? '';
  const fmtTs = (s: string | null) => {
    if (!s) return '—';
    try { return new Date(s).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' }); } catch { return s; }
  };
  return (
    <>
      <tr className="border-b border-border/50 hover:bg-muted/30">
        <td className="px-2 py-1 whitespace-nowrap">{fmtTs(row.ts_utc)}</td>
        <td className="px-2 py-1">{row.event_type ?? '—'}</td>
        <td className="px-2 py-1 font-mono">{row.src_ip ?? '—'}:{row.src_port ?? '—'}</td>
        <td className="px-2 py-1 font-mono">{row.dest_ip ?? '—'}:{row.dest_port ?? '—'}</td>
        <td className="px-2 py-1 truncate max-w-[120px]" title={row.rule ?? ''}>{row.rule ?? '—'}</td>
        <td className="px-2 py-1">{row.app_name ?? '—'}</td>
        <td className="px-2 py-1 tabular-nums">{(row.bytes_orig ?? 0)}+{(row.bytes_term ?? 0)}</td>
        <td className="px-2 py-1">
          {raw ? (
            <button
              type="button"
              onClick={() => setExpandRaw((e) => !e)}
              className="text-[10px] text-primary hover:underline"
            >
              {expandRaw ? 'Collapse' : 'View'}
            </button>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </td>
      </tr>
      {expandRaw && raw ? (
        <tr>
          <td colSpan={8} className="px-2 py-1 bg-muted/40 font-mono text-[10px] break-all whitespace-pre-wrap align-top">
            {raw}
          </td>
        </tr>
      ) : null}
    </>
  );
}

/* ── Dashboard Diagram ── */
function DashboardDiagram({
  data,
  device,
  deviceLabel,
  onSetSourceFilter,
  onSetDestinationFilter,
  activeSourceEndpointId,
  activeDestEndpointId,
  embedded,
}: {
  data: any;
  device: string;
  deviceLabel?: string;
  onSetSourceFilter?: (endpointId: string) => void;
  onSetDestinationFilter?: (endpointId: string) => void;
  activeSourceEndpointId?: string | null;
  activeDestEndpointId?: string | null;
  /** When true, omit outer margin (used inside diagram-area wrapper with loading overlay) */
  embedded?: boolean;
}) {
  // Per-group router expand state: set of ig group ids whose router is expanded
  const [expandedRouters, setExpandedRouters] = useState<Set<string>>(new Set());
  const [expandedNodeIds, setExpandedNodeIds] = useState<Set<string>>(new Set());
  const [expandedServicePorts, setExpandedServicePorts] = useState<Set<string>>(new Set());
  const [showAllSources, setShowAllSources] = useState(false);
  const [expandedLeftRouter, setExpandedLeftRouter] = useState(false);
  /** Inspect raw logs modal: row from "By source & destination" (canonical src_ip/dest_ip for API) */
  const [inspectModal, setInspectModal] = useState<{
    source_label: string;
    dest_label: string;
    src_ip: string;
    dest_ip: string;
    proto: string;
    port: number;
    app: string;
  } | null>(null);
  /** Measured node dimensions for layout (firewall width drives right-column X) */
  const [nodeSizes, setNodeSizes] = useState<Record<string, { w: number; h: number }>>({});
  const reactFlowRef = React.useRef<any>(null);

  const reportNodeSize = React.useCallback((nodeId: string, w: number, h: number) => {
    setNodeSizes((prev) => {
      const cur = prev[nodeId];
      if (cur && cur.w === w && cur.h === h) return prev;
      return { ...prev, [nodeId]: { w, h } };
    });
  }, []);

  React.useEffect(() => {
    setExpandedRouters(new Set());
    setExpandedNodeIds(new Set());
    setExpandedServicePorts(new Set());
    setShowAllSources(false);
    setExpandedLeftRouter(false);
  }, [data?.meta?.device, data?.meta?.time_from, data?.meta?.time_to]);

  const firewallLabel = (deviceLabel != null && deviceLabel.trim()) ? deviceLabel : ((device && device.trim()) ? device : 'Firewall');

  const toggleNodeExpanded = React.useCallback((nodeId: string) => {
    setExpandedNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  }, []);

  const toggleRouterExpanded = React.useCallback((igId: string) => {
    setExpandedRouters((prev) => {
      const next = new Set(prev);
      if (next.has(igId)) next.delete(igId);
      else next.add(igId);
      return next;
    });
  }, []);

  const toggleServicePortExpand = React.useCallback((portId: string) => {
    setExpandedServicePorts((prev) => {
      const next = new Set(prev);
      if (next.has(portId)) next.delete(portId);
      else next.add(portId);
      return next;
    });
  }, []);

  const { nodes, edges, sourcesSummary } = React.useMemo(() => {
    // Defensive dedupe by node id (last wins) so ReactFlow never sees duplicate ids (e.g. HA graph)
    const dedupeNodesById = (arr: any[]): any[] => {
      const byId = new Map<string, any>();
      for (const n of arr) {
        if (n?.id != null) byId.set(String(n.id), n);
      }
      return [...byId.values()];
    };
    const left: any[] = dedupeNodesById(data.left_nodes || []);
    const interfaceGroups = data.interface_groups || [];
    const routerLeft = data.router_bucket_left || {};
    const leftCount = routerLeft.count ?? 0;
    const apiEdges: any[] = data.edges || [];
    const hiddenNodesLeft: any[] = dedupeNodesById(routerLeft.hidden_nodes || []);
    const hiddenEdgesLeft: any[] = routerLeft.hidden_edges || [];
    const hiddenNodeIdsLeft = new Set<string>(routerLeft.hidden_node_ids || []);

    const fwW = nodeSizes['fw']?.w ?? DEFAULT_FW_W;
    const leftMaxW = DEFAULT_LEFT_MAX_W;
    const xLeft = LEFT_X;
    const xFirewall = leftMaxW + COL_GAP;
    const xRight = xFirewall + fwW + COL_GAP;
    const xRouter = xRight + RIGHT_COL_WIDTH + COL_GAP;
    const xExpanded = xRouter + ROUTER_COL_WIDTH + COL_GAP;

    const nodes: any[] = [];
    const edges: any[] = [];

    const endpointIdFromNodeId = (nodeId: string) => String((nodeId || '').replace(/^(left|right)-/, ''));

    const fwNode = {
      id: 'fw',
      position: { x: xFirewall, y: 0 },
      data: { label: firewallLabel, onNodeSize: reportNodeSize },
      type: 'firewall',
    };
    nodes.push(fwNode);

    // ── Left column: sort by seen_count, collapse if >MAX_VISIBLE_SOURCES ──
    const sortedLeft = [...left].sort(
      (a, b) => (Number(b.seen_count) || 0) - (Number(a.seen_count) || 0),
    );
    const totalSources = sortedLeft.length;
    const needCollapse = totalSources > MAX_VISIBLE_SOURCES && !showAllSources;
    const visibleSources = needCollapse ? sortedLeft.slice(0, MAX_VISIBLE_SOURCES) : sortedLeft;
    const hiddenCount = needCollapse ? totalSources - MAX_VISIBLE_SOURCES : 0;

    // Build a set of rendered node IDs so we can filter edges later
    const renderedNodeIds = new Set<string>(['fw', 'router-left']);
    const leftColumnNodes: any[] = [];
    const leftChildrenColumnNodes: any[] = []; // expanded left-router endpoints, one column to the left

    visibleSources.forEach((n: any) => {
      const isNodeExpanded = expandedNodeIds.has(n.id);
      const layoutH = estimateNodeHeight(n, isNodeExpanded, false);
      renderedNodeIds.add(n.id);
      const node = {
        id: n.id,
        position: { x: LEFT_X, y: 0 },
        data: {
          label: n.label,
          ip: n.ip,
          mac: n.mac,
          device_name: n.device_name,
          ...(n.vendor && { vendor: n.vendor }),
          ...(n.type_name && { type_name: n.type_name }),
          ...(n.os_name && { os_name: n.os_name }),
          ...(n.brand && { brand: n.brand }),
          ...(n.model && { model: n.model }),
          ...(n.identification && { identification: n.identification }),
          expanded: isNodeExpanded,
          isExpanded: isNodeExpanded,
          layoutHeight: layoutH,
          onToggle: () => toggleNodeExpanded(n.id),
          endpointId: endpointIdFromNodeId(n.id),
          onSetAsSource: onSetSourceFilter ? () => onSetSourceFilter(endpointIdFromNodeId(n.id)) : undefined,
          onSetAsDest: onSetDestinationFilter ? () => onSetDestinationFilter(endpointIdFromNodeId(n.id)) : undefined,
          isActiveSource: activeSourceEndpointId != null && activeSourceEndpointId === endpointIdFromNodeId(n.id),
          isActiveDest: activeDestEndpointId != null && activeDestEndpointId === endpointIdFromNodeId(n.id),
        },
        type: 'leftEndpoint',
        style: isNodeExpanded ? { zIndex: EXPANDED_NODE_ZINDEX } : { zIndex: 0 },
      };
      nodes.push(node);
      leftColumnNodes.push(node);
    });

    // Collapsed "+X more" or "Show less" node
    if (needCollapse && hiddenCount > 0) {
      const node = {
        id: 'src-more',
        position: { x: LEFT_X, y: 0 },
        data: { label: `+${hiddenCount} more`, expanded: false, layoutHeight: ROW_HEIGHT, onClick: () => setShowAllSources(true) },
        type: 'collapsedSourcesNode',
      };
      nodes.push(node);
      leftColumnNodes.push(node);
    } else if (showAllSources && totalSources > MAX_VISIBLE_SOURCES) {
      const node = {
        id: 'src-less',
        position: { x: LEFT_X, y: 0 },
        data: { label: `Show top ${MAX_VISIBLE_SOURCES}`, expanded: true, layoutHeight: ROW_HEIGHT, onClick: () => setShowAllSources(false) },
        type: 'collapsedSourcesNode',
      };
      nodes.push(node);
      leftColumnNodes.push(node);
    }

    if (leftCount > 0) {
      const isLeftRouterExpanded = expandedLeftRouter;
      const routerLeftX = xLeft; // same column as other left nodes when collapsed
      const node = {
        id: 'router-left',
        position: { x: routerLeftX, y: 0 },
        data: {
          label: isLeftRouterExpanded ? `Router (${leftCount}) ▼` : `Router (${leftCount})`,
          layoutHeight: ROW_HEIGHT,
          clickable: true,
          onClick: () => setExpandedLeftRouter((v) => !v),
        },
        type: 'routerBucket',
      };
      nodes.push(node);
      leftColumnNodes.push(node);

      // When expanded: add hidden source nodes one column to the left of the router
      if (isLeftRouterExpanded && hiddenNodesLeft.length > 0) {
        const xLeftChildren = xLeft - COL_GAP - DEFAULT_LEFT_MAX_W; // one column to the left of router/sources
        hiddenNodesLeft.forEach((n: any) => {
          renderedNodeIds.add(n.id);
          const isNodeExpanded = expandedNodeIds.has(n.id);
          const layoutH = estimateNodeHeight(n, isNodeExpanded, false);
          const nodeEl = {
            id: n.id,
            position: { x: xLeftChildren, y: 0 },
            data: {
              label: n.label,
              ip: n.ip,
              mac: n.mac,
              device_name: n.device_name,
              ...(n.vendor && { vendor: n.vendor }),
              ...(n.type_name && { type_name: n.type_name }),
              ...(n.os_name && { os_name: n.os_name }),
              ...(n.brand && { brand: n.brand }),
              ...(n.model && { model: n.model }),
              ...(n.identification && { identification: n.identification }),
              expanded: isNodeExpanded,
              isExpanded: isNodeExpanded,
              layoutHeight: layoutH,
              onToggle: () => toggleNodeExpanded(n.id),
              endpointId: endpointIdFromNodeId(n.id),
              onSetAsSource: onSetSourceFilter ? () => onSetSourceFilter(endpointIdFromNodeId(n.id)) : undefined,
              onSetAsDest: onSetDestinationFilter ? () => onSetDestinationFilter(endpointIdFromNodeId(n.id)) : undefined,
              isActiveSource: activeSourceEndpointId != null && activeSourceEndpointId === endpointIdFromNodeId(n.id),
              isActiveDest: activeDestEndpointId != null && activeDestEndpointId === endpointIdFromNodeId(n.id),
            },
            type: 'leftEndpoint',
            style: isNodeExpanded ? { zIndex: EXPANDED_NODE_ZINDEX } : { zIndex: 0 },
          };
          nodes.push(nodeEl);
          leftChildrenColumnNodes.push(nodeEl);
        });
      }
    }

    const sourcesSummary = totalSources > MAX_VISIBLE_SOURCES
      ? (showAllSources
        ? `Sources: ${totalSources} — showing all`
        : `Sources: ${totalSources} — top ${MAX_VISIBLE_SOURCES} by activity`)
      : '';

    // ── Right column: hierarchical Services (port→app), flat Services (legacy), or InterfaceGroup ──
    const rightColumnNodes: any[] = [];
    let expandedY = TOP_PADDING;
    const servicePortNodesList: any[] = data.service_port_nodes || [];
    const serviceAppNodesList: any[] = data.service_app_nodes || [];
    const isServicesHierarchical = servicePortNodesList.length > 0;
    const serviceNodesList: any[] = data.service_nodes || [];
    const isServicesFlat = !isServicesHierarchical && serviceNodesList.length > 0;

    if (isServicesHierarchical) {
      // Group app nodes by parent_port_id, sort by count desc within each port
      const appsByPort: Record<string, any[]> = {};
      serviceAppNodesList.forEach((an: any) => {
        const pid = (an.data || an).parent_port_id;
        if (!pid) return;
        if (!appsByPort[pid]) appsByPort[pid] = [];
        appsByPort[pid].push(an);
      });
      Object.keys(appsByPort).forEach((pid) => {
        appsByPort[pid].sort((a: any, b: any) => (Number((b.data || b).count) || 0) - (Number((a.data || a).count) || 0));
      });

      // Sort port nodes: port asc, then TCP before UDP, then stable by id
      function protoRank(proto: string): number {
        const p = (proto ?? '').toString().toUpperCase();
        if (p === 'TCP') return 0;
        if (p === 'UDP') return 1;
        return 2;
      }
      const sortedPortNodes = [...servicePortNodesList].sort((a: any, b: any) => {
        const da = a.data || a;
        const db = b.data || b;
        const portA = Number(da.port ?? da.destport ?? 0);
        const portB = Number(db.port ?? db.destport ?? 0);
        if (portA !== portB) return portA - portB;
        const rA = protoRank(da.proto);
        const rB = protoRank(db.proto);
        if (rA !== rB) return rA - rB;
        return String(a.id ?? '').localeCompare(String(b.id ?? ''));
      });

      sortedPortNodes.forEach((pn: any) => {
        const pd = pn.data || pn;
        const portId = pn.id;
        renderedNodeIds.add(portId);
        const portExpanded = expandedServicePorts.has(portId);
        const appsForPort = appsByPort[portId] || [];

        const portNode = {
          id: portId,
          position: { x: xRight, y: 0 },
          data: {
            label: pd.label,
            proto: pd.proto,
            port: pd.port,
            count: pd.count,
            dest_ip_count: pd.dest_ip_count,
            appCount: appsForPort.length,
            expanded: portExpanded,
            isExpanded: portExpanded,
            layoutHeight: SERVICE_PORT_HEIGHT,
            onToggle: () => toggleServicePortExpand(portId),
          },
          type: 'servicePortNode',
          style: { zIndex: 0 },
        };
        nodes.push(portNode);
        rightColumnNodes.push(portNode);

        if (portExpanded) {
          appsForPort.forEach((an: any) => {
            const ad = an.data || an;
            renderedNodeIds.add(an.id);
            const appExpanded = expandedNodeIds.has(an.id);
            const layoutH = estimateServiceAppNodeHeight(ad, appExpanded);
            const appNode = {
              id: an.id,
              position: { x: xRouter, y: 0 },
              data: {
                label: ad.label,
                proto: ad.proto,
                port: ad.port,
                app: ad.app,
                appKey: ad.appKey,
                count: ad.count,
                dest_ip_count: ad.dest_ip_count,
                by_pair: ad.by_pair,
                expanded: appExpanded,
                isExpanded: appExpanded,
                layoutHeight: layoutH,
                onToggle: () => toggleNodeExpanded(an.id),
                onInspect: (row: { source_label?: string; dest_label?: string; src_ip?: string; dest_ip?: string; count?: number }) => setInspectModal({
                  source_label: row.source_label ?? '',
                  dest_label: row.dest_label ?? '',
                  src_ip: row.src_ip ?? '',
                  dest_ip: row.dest_ip ?? '',
                  proto: ad.proto ?? 'TCP',
                  port: ad.port ?? 0,
                  app: ad.appKey ?? '-',
                }),
              },
              type: 'serviceAppNode',
              style: appExpanded ? { zIndex: EXPANDED_NODE_ZINDEX } : { zIndex: 0 },
            };
            nodes.push(appNode);
            rightColumnNodes.push(appNode);
          });
        }
      });
    } else if (isServicesFlat) {
      serviceNodesList.forEach((sn: any) => {
        const d = sn.data || sn;
        renderedNodeIds.add(sn.id);
        const isExpanded = expandedNodeIds.has(sn.id);
        const layoutH = estimateServiceNodeHeight(d, isExpanded);
        const node = {
          id: sn.id,
          position: { x: xRight, y: 0 },
          data: {
            label: d.label,
            proto: d.proto,
            port: d.port,
            app: d.app,
            count: d.count,
            by_pair: d.by_pair,
            expanded: isExpanded,
            isExpanded: isExpanded,
            layoutHeight: layoutH,
            onToggle: () => toggleNodeExpanded(sn.id),
          },
          type: 'serviceNode',
          style: isExpanded ? { zIndex: EXPANDED_NODE_ZINDEX } : { zIndex: 0 },
        };
        nodes.push(node);
        rightColumnNodes.push(node);
      });
    } else {
    interfaceGroups.forEach((group: any) => {
      const igId = group.id;
      const localDevices: any[] = group.local_devices || [];
      const router = group.router;
      const hasRouter = !!router && router.count > 0;
      const igLayoutHeight = estimateIGNodeHeight(localDevices, expandedNodeIds);

      // InterfaceGroup node (position set later by layoutColumn + centerColumnAround)
      renderedNodeIds.add(igId);
      const igNode = {
        id: igId,
        position: { x: xRight, y: 0 },
        data: {
          dest_if: group.dest_if,
          dest_zone: group.dest_zone,
          label: group.label,
          local_devices: localDevices.map((dev: any) => ({
            ...dev,
            onInspect: dev.ip
              ? (row: { source_label?: string; src_ip?: string; proto?: string; port?: number; app_name?: string | null }) =>
                  setInspectModal({
                    source_label: row.source_label ?? '',
                    dest_label: dev.label ?? '',
                    src_ip: row.src_ip ?? '',
                    dest_ip: dev.ip ?? '',
                    proto: row.proto ?? 'TCP',
                    port: row.port ?? 0,
                    app: (row.app_name != null && String(row.app_name).trim() !== '') ? String(row.app_name).trim() : '-',
                  })
              : undefined,
          })),
          has_router: hasRouter,
          layoutHeight: igLayoutHeight,
          expandedNodeIds,
          onToggleDevice: toggleNodeExpanded,
          onSetAsDest: onSetDestinationFilter ? (epId: string) => onSetDestinationFilter(epId) : undefined,
        },
        type: 'interfaceGroup',
        style: { zIndex: 1 },
      };
      nodes.push(igNode);
      rightColumnNodes.push(igNode);

      // Per-group Router node (Column B); position.y set after centering
      if (hasRouter) {
        const routerNodeId = router.node_id;
        const routerCount = router.count;
        const isRouterExpanded = expandedRouters.has(igId);
        const hiddenNodes: any[] = router.hidden_nodes || [];
        const hiddenEdges: any[] = router.hidden_edges || [];

        renderedNodeIds.add(routerNodeId);
        nodes.push({
          id: routerNodeId,
          position: { x: xRouter, y: 0 },
          data: {
            label: isRouterExpanded ? `Router (${routerCount}) ▼` : `Router (${routerCount})`,
            clickable: true,
            onClick: () => toggleRouterExpanded(igId),
            _igNodeId: igId,
          },
          type: 'routerBucket',
        });

        // Expanded router devices (Column C) — height-aware stack
        if (isRouterExpanded && hiddenNodes.length > 0) {
          const byTarget: Record<string, any[]> = {};
          hiddenEdges.forEach((e: any) => {
            const t = e.target_node_id;
            if (!byTarget[t]) byTarget[t] = [];
            byTarget[t].push(e);
          });

          hiddenNodes.forEach((n: any) => {
            const isNodeExpanded = expandedNodeIds.has(n.id);
            const nodeH = estimateNodeHeight(n, isNodeExpanded, true);
            renderedNodeIds.add(n.id);
            const destIp = n.ip ?? '';
            const destLabel = n.label ?? '';
            nodes.push({
              id: n.id,
              position: { x: xExpanded, y: expandedY },
              data: {
                label: n.label,
                ip: n.ip,
                mac: n.mac,
                device_name: n.device_name,
                ...(n.vendor && { vendor: n.vendor }),
                ...(n.type_name && { type_name: n.type_name }),
                ...(n.os_name && { os_name: n.os_name }),
                ...(n.brand && { brand: n.brand }),
                ...(n.model && { model: n.model }),
                ...(n.identification && { identification: n.identification }),
                services: n.services,
                source_breakdown: n.source_breakdown,
                expanded: isNodeExpanded,
                isExpanded: isNodeExpanded,
                onToggle: () => toggleNodeExpanded(n.id),
                endpointId: endpointIdFromNodeId(n.id),
                onSetAsSource: onSetSourceFilter ? () => onSetSourceFilter(endpointIdFromNodeId(n.id)) : undefined,
                onSetAsDest: onSetDestinationFilter ? () => onSetDestinationFilter(endpointIdFromNodeId(n.id)) : undefined,
                isActiveSource: activeSourceEndpointId != null && activeSourceEndpointId === endpointIdFromNodeId(n.id),
                isActiveDest: activeDestEndpointId != null && activeDestEndpointId === endpointIdFromNodeId(n.id),
                onInspect: (row: { source_label?: string; src_ip?: string; proto?: string; port?: number; app_name?: string | null }) => setInspectModal({
                  source_label: row.source_label ?? '',
                  dest_label: destLabel,
                  src_ip: row.src_ip ?? '',
                  dest_ip: destIp,
                  proto: row.proto ?? 'TCP',
                  port: row.port ?? 0,
                  app: (row.app_name != null && String(row.app_name).trim() !== '') ? String(row.app_name).trim() : '-',
                }),
              },
              type: 'rightEndpoint',
              style: isNodeExpanded ? { zIndex: EXPANDED_NODE_ZINDEX } : { zIndex: 0 },
            });

            const eGroup = byTarget[n.id] || [];
            const payload = aggregateEdgePayloads(eGroup);
            const first = eGroup[0];
            if (first?.top_services) payload.top_services = first.top_services;
            edges.push({
              id: `e-${routerNodeId}-${n.id}`,
              source: routerNodeId,
              target: n.id,
              sourceHandle: HANDLE_RIGHT,
              targetHandle: HANDLE_LEFT,
              type: 'metricEdge',
              data: payload,
            });

            expandedY += nodeH + NODE_GAP;
          });
        }
      }
    });
    }

    // When left router is expanded, add edges from each hidden source to router-left (not to fw)
    if (expandedLeftRouter && leftCount > 0 && hiddenNodesLeft.length > 0) {
      const aggBySrc: Record<string, any> = {};
      hiddenEdgesLeft.forEach((e: any) => {
        const src = e.source_node_id;
        if (!hiddenNodeIdsLeft.has(src)) return;
        if (!aggBySrc[src]) aggBySrc[src] = { count_open: 0, count_close: 0, bytes_src_to_dst: 0, bytes_dst_to_src: 0, top_ports: {}, top_rules: {}, top_apps: {}, last_seen: null, top_services: [] };
        const into = aggBySrc[src];
        into.count_open = (into.count_open || 0) + (e.count_open || 0);
        into.count_close = (into.count_close || 0) + (e.count_close || 0);
        into.bytes_src_to_dst = (into.bytes_src_to_dst || 0) + (e.bytes_src_to_dst || 0);
        into.bytes_dst_to_src = (into.bytes_dst_to_src || 0) + (e.bytes_dst_to_src || 0);
        if (e.last_seen && (!into.last_seen || e.last_seen > into.last_seen)) into.last_seen = e.last_seen;
      });
      Object.keys(aggBySrc).forEach((src, i) => {
        const d = aggBySrc[src];
        edges.push({
          id: `e-left-${src}-router-left-${i}`,
          source: src,
          target: 'router-left',
          sourceHandle: HANDLE_RIGHT,
          targetHandle: HANDLE_LEFT,
          type: 'metricEdge',
          data: {
            count_open: d.count_open,
            count_close: d.count_close,
            bytes_src_to_dst: d.bytes_src_to_dst,
            bytes_dst_to_src: d.bytes_dst_to_src,
            top_ports: d.top_ports,
            top_rules: d.top_rules,
            top_apps: d.top_apps,
            last_seen: d.last_seen,
            top_services: d.top_services,
          },
        });
      });
    }

    // ── Edges from API (left->fw, fw->ig or fw->svc) ──
    // Only include edges whose source AND target are rendered nodes.
    // When left router is expanded, omit edges from hidden left nodes to fw (they go to router-left above).
    apiEdges.forEach((e: any, i: number) => {
      const src = e.source_node_id;
      const tgt = e.target_node_id;
      if (!src || !tgt) return;
      if (expandedLeftRouter && hiddenNodeIdsLeft.has(src)) return; // hidden source -> fw not rendered; we use source -> router-left
      if (!renderedNodeIds.has(src) || !renderedNodeIds.has(tgt)) return;
      edges.push({
        id: `e-${src}-${tgt}-${i}`,
        source: src,
        target: tgt,
        sourceHandle: HANDLE_RIGHT,
        targetHandle: HANDLE_LEFT,
        type: 'metricEdge',
        data: {
          count_open: e.count_open,
          count_close: e.count_close,
          bytes_src_to_dst: e.bytes_src_to_dst,
          bytes_dst_to_src: e.bytes_dst_to_src,
          top_ports: e.top_ports,
          top_rules: e.top_rules,
          top_apps: e.top_apps,
          last_seen: e.last_seen,
          top_services: e.top_services,
        },
      });
    });

    // Stack both columns (height-aware: expanded nodes push below; gap stays constant)
    layoutColumn(leftColumnNodes, TOP_PADDING, NODE_GAP);
    if (leftChildrenColumnNodes.length > 0) layoutColumn(leftChildrenColumnNodes, TOP_PADDING, NODE_GAP);
    layoutColumn(rightColumnNodes, TOP_PADDING, NODE_GAP + IF_EXTRA_GAP);

    // Position firewall so its center is between the two column centers
    const defaultH = ROW_HEIGHT;
    let leftTop = leftColumnNodes[0]?.position.y ?? TOP_PADDING;
    const leftLast = leftColumnNodes[leftColumnNodes.length - 1];
    let leftBottom = leftLast ? leftLast.position.y + (leftLast.data?.layoutHeight ?? defaultH) : leftTop;
    if (leftChildrenColumnNodes.length > 0) {
      const cTop = leftChildrenColumnNodes[0]?.position.y ?? TOP_PADDING;
      const cLast = leftChildrenColumnNodes[leftChildrenColumnNodes.length - 1];
      const cBottom = cLast ? cLast.position.y + (cLast.data?.layoutHeight ?? defaultH) : cTop;
      leftTop = Math.min(leftTop, cTop);
      leftBottom = Math.max(leftBottom, cBottom);
    }
    const leftCenter = (leftColumnNodes.length > 0 || leftChildrenColumnNodes.length > 0) ? (leftTop + leftBottom) / 2 : TOP_PADDING + 40;

    const rightTop = rightColumnNodes[0]?.position.y ?? TOP_PADDING;
    const rightLast = rightColumnNodes[rightColumnNodes.length - 1];
    const rightBottom = rightLast ? rightLast.position.y + (rightLast.data?.layoutHeight ?? defaultH) : rightTop;
    const rightCenter = rightColumnNodes.length > 0 ? (rightTop + rightBottom) / 2 : TOP_PADDING + 40;

    const fwCenterY = (leftCenter + rightCenter) / 2;
    fwNode.position.y = Math.max(0, fwCenterY - FW_HALF_HEIGHT);

    // Center both columns around firewall center so layout stays symmetric
    centerColumnAround(leftColumnNodes, fwNode.position.y + FW_HALF_HEIGHT);
    if (leftChildrenColumnNodes.length > 0) centerColumnAround(leftChildrenColumnNodes, fwNode.position.y + FW_HALF_HEIGHT);
    centerColumnAround(rightColumnNodes, fwNode.position.y + FW_HALF_HEIGHT);

    // Router nodes: vertically centered with their interface node (stable when interface expands)
    nodes.forEach((node: any) => {
      const igId = node.data?._igNodeId;
      if (!igId) return;
      const igNode = nodes.find((n: any) => n.id === igId);
      if (!igNode?.data?.layoutHeight) return;
      node.position.y = igNode.position.y + (igNode.data.layoutHeight - ROW_HEIGHT) / 2;
    });

    // Sort: expanded nodes last so they render on top
    nodes.sort((a: any, b: any) => {
      const aEx = expandedNodeIds.has(a.id);
      const bEx = expandedNodeIds.has(b.id);
      if (aEx && !bEx) return 1;
      if (!aEx && bEx) return -1;
      return 0;
    });

    return { nodes, edges, sourcesSummary };
  }, [data, firewallLabel, expandedRouters, expandedNodeIds, expandedServicePorts, showAllSources, expandedLeftRouter, nodeSizes, reportNodeSize, toggleNodeExpanded, toggleRouterExpanded, toggleServicePortExpand, onSetSourceFilter, onSetDestinationFilter, activeSourceEndpointId, activeDestEndpointId]);

  const interfaceGroups = data.interface_groups || [];
  const hasAnyIG = interfaceGroups.some((g: any) =>
    (g.local_devices?.length ?? 0) > 0 || (g.router?.count ?? 0) > 0
  );
  const hasServiceNodes = (data.service_nodes?.length ?? 0) > 0 || (data.service_port_nodes?.length ?? 0) > 0;
  const empty =
    (data.left_nodes?.length ?? 0) === 0 &&
    !hasAnyIG &&
    !hasServiceNodes &&
    (data.router_bucket_left?.count ?? 0) === 0;
  if (empty) return null;

  return (
    <div className={cn('rounded-2xl border border-border bg-card/50 shadow-sm overflow-hidden relative', embedded ? 'flex-1 min-h-0' : 'flex-1 min-h-[300px] m-3')}>
      {sourcesSummary && (
        <div className="absolute top-2 left-3 z-10 text-[11px] text-muted-foreground bg-card/80 backdrop-blur-sm px-2 py-0.5 rounded">
          {sourcesSummary}
        </div>
      )}
      <ReactFlow
        ref={reactFlowRef}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={true}
      >
        <Background gap={20} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
      {inspectModal && (
        <InspectLogsModal
          open={!!inspectModal}
          onClose={() => setInspectModal(null)}
          device={device}
          timeFrom={data?.meta?.time_from ?? null}
          timeTo={data?.meta?.time_to ?? null}
          view={data?.meta?.view ?? 'original'}
          proto={inspectModal.proto}
          port={inspectModal.port}
          appName={inspectModal.app}
          sourceLabel={inspectModal.source_label}
          destLabel={inspectModal.dest_label}
          srcIp={inspectModal.src_ip}
          destIp={inspectModal.dest_ip}
        />
      )}
    </div>
  );
}

/* ── Ingest stats (hidden behind (i) icon, show on hover) ── */
type StatsSnapshot = {
  udp_packets?: number;
  udp_bytes?: number;
  lines?: number;
  records_total?: number;
  records_ok?: number;
  parse_err?: number;
  filtered_id?: number;
  db_raw_logs?: number;
  db_events?: number;
  last_updated?: string | null;
};

function HeaderStatsStrip() {
  const [hover, setHover] = useState(false);
  const { data, isError, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: async (): Promise<StatsSnapshot> => {
      const res = await fetch(`${API}/stats`);
      if (!res.ok) throw new Error('Stats unavailable');
      return res.json();
    },
    enabled: hover,
    refetchInterval: hover ? 3000 : false,
    retry: false,
    refetchOnWindowFocus: false,
  });

    return (
    <div
      className="relative flex items-center justify-end"
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      <button
        type="button"
        className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors focus:outline-none focus:ring-2 focus:ring-ring"
        aria-label="Ingest stats"
      >
        <Info className="w-4 h-4" />
      </button>
      {hover && (
        <div className="absolute right-0 top-full mt-1 w-72 rounded-lg border border-border bg-card shadow-lg p-3 z-[100] text-xs text-muted-foreground">
          {isLoading && !data && (
            <div className="flex items-center gap-2 py-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Loading stats…</span>
            </div>
          )}
          {isError && (
            <span className="text-muted-foreground">Stats unavailable</span>
          )}
          {data && !isError && (
            <div className="space-y-2">
              <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                <span>Raw logs</span>
                <span className="font-medium tabular-nums text-foreground">{data.db_raw_logs?.toLocaleString() ?? 0}</span>
                <span>Parsed events</span>
                <span className="font-medium tabular-nums text-foreground">{data.db_events?.toLocaleString() ?? 0}</span>
                <span>OK</span>
                <span className="font-medium tabular-nums text-foreground">{data.records_ok?.toLocaleString() ?? 0}</span>
                <span>Filtered</span>
                <span className="font-medium tabular-nums text-foreground">{data.filtered_id?.toLocaleString() ?? 0}</span>
                <span>Errors</span>
                <span className={cn('font-medium tabular-nums', (data.parse_err ?? 0) > 0 ? 'text-destructive' : 'text-foreground')}>{data.parse_err?.toLocaleString() ?? 0}</span>
              </div>
              <div className="pt-2 border-t border-border space-y-0.5 text-muted-foreground/80">
                <div>UDP packets: {(data.udp_packets ?? 0).toLocaleString()}</div>
                <div>UDP bytes: {(data.udp_bytes ?? 0).toLocaleString()}</div>
                <div>Total records: {(data.records_total ?? 0).toLocaleString()}</div>
                {data.last_updated && <div>Last updated: {data.last_updated}</div>}
              </div>
            </div>
          )}
        </div>
      )}
      </div>
    );
  }

/* ── Settings Page ── */
function SettingsPage({ onBack }: { onBack: () => void }) {
  const [activeTab, setActiveTab] = useState<'endpoints' | 'database'>('endpoints');

  // ── Fetch settings ──
  const { data: settings, refetch: refetchSettings } = useQuery({
    queryKey: ['settings'],
    queryFn: async () => {
      const res = await fetch(`${API}/settings`);
      if (!res.ok) throw new Error('Failed to load settings');
      return res.json();
    },
  });

  // ── Fetch DB stats ──
  const { data: dbStats, refetch: refetchDbStats, isFetching: dbStatsLoading } = useQuery({
    queryKey: ['stats/db'],
    queryFn: async () => {
      const res = await fetch(`${API}/stats/db`);
      if (!res.ok) throw new Error('Failed to load DB stats');
      return res.json();
    },
  });

  // ── Local state for retention form ──
  const retention = settings?.log_retention ?? { enabled: true, keep_days: 3 };
  const [retEnabled, setRetEnabled] = useState<boolean>(retention.enabled);
  const [retDays, setRetDays] = useState<number>(retention.keep_days);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [cleanupRunning, setCleanupRunning] = useState(false);
  const [cleanupMsg, setCleanupMsg] = useState<string | null>(null);

  // ── Local state for local-networks form ──
  const lnDefault = { enabled: true, cidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] };
  const lnSetting = settings?.local_networks ?? lnDefault;
  const [lnEnabled, setLnEnabled] = useState<boolean>(lnSetting.enabled);
  const [lnCidrs, setLnCidrs] = useState<string[]>(lnSetting.cidrs ?? lnDefault.cidrs);
  const [lnNewCidr, setLnNewCidr] = useState('');
  const [lnNewError, setLnNewError] = useState<string | null>(null);
  const [lnSaving, setLnSaving] = useState(false);
  const [lnSaveMsg, setLnSaveMsg] = useState<string | null>(null);

  // Sync local state when settings load
  React.useEffect(() => {
    if (settings?.log_retention) {
      setRetEnabled(settings.log_retention.enabled);
      setRetDays(settings.log_retention.keep_days);
    }
  }, [settings?.log_retention]);

  React.useEffect(() => {
    const ln = settings?.local_networks;
    if (ln) {
      setLnEnabled(ln.enabled);
      setLnCidrs(ln.cidrs ?? lnDefault.cidrs);
    }
  }, [settings?.local_networks]);

  // ── CIDR validation helper ──
  const isValidCidr = (s: string): { valid: boolean; normalized: string; error?: string } => {
    const trimmed = s.trim();
    if (!trimmed) return { valid: false, normalized: '', error: 'Empty input' };
    // Basic regex: IPv4 CIDR like x.x.x.x/N
    const match = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
    if (!match) return { valid: false, normalized: '', error: 'Invalid format. Use x.x.x.x/N' };
    const parts = match[1].split('.').map(Number);
    if (parts.some((p) => p < 0 || p > 255)) return { valid: false, normalized: '', error: 'Invalid IP octets' };
    const prefix = Number(match[2]);
    if (prefix < 0 || prefix > 32) return { valid: false, normalized: '', error: 'Prefix must be 0-32' };
    // Normalize: compute network address
    const ip32 = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const net = (ip32 & mask) >>> 0;
    const norm = `${(net >>> 24) & 0xff}.${(net >>> 16) & 0xff}.${(net >>> 8) & 0xff}.${net & 0xff}/${prefix}`;
    return { valid: true, normalized: norm };
  };

  const handleAddCidr = () => {
    setLnNewError(null);
    const result = isValidCidr(lnNewCidr);
    if (!result.valid) {
      setLnNewError(result.error ?? 'Invalid CIDR');
      return;
    }
    if (lnCidrs.includes(result.normalized)) {
      setLnNewError('Already in list');
      return;
    }
    setLnCidrs((prev) => [...prev, result.normalized]);
    setLnNewCidr('');
  };

  const handleRemoveCidr = (cidr: string) => {
    setLnCidrs((prev) => prev.filter((c) => c !== cidr));
  };

  const handleSaveLocalNetworks = async () => {
    setLnSaving(true);
    setLnSaveMsg(null);
    try {
      const res = await fetch(`${API}/settings/local-networks`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: lnEnabled, cidrs: lnCidrs }),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(body);
      }
      await refetchSettings();
      setLnSaveMsg('Saved');
      setTimeout(() => setLnSaveMsg(null), 2000);
    } catch (e) {
      setLnSaveMsg(`Error: ${(e as Error).message}`);
    } finally {
      setLnSaving(false);
    }
  };

  const handleSaveRetention = async () => {
    setSaving(true);
    setSaveMsg(null);
    try {
      const res = await fetch(`${API}/settings/log-retention`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: retEnabled, keep_days: retDays }),
      });
      if (!res.ok) throw new Error(await res.text());
      await refetchSettings();
      setSaveMsg('Saved');
      setTimeout(() => setSaveMsg(null), 2000);
    } catch (e) {
      setSaveMsg(`Error: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleRunCleanup = async () => {
    setCleanupRunning(true);
    setCleanupMsg(null);
    try {
      const res = await fetch(`${API}/maintenance/cleanup`, { method: 'POST' });
      if (!res.ok) throw new Error(await res.text());
      const summary = await res.json();
      if (summary.skipped) {
        setCleanupMsg('Skipped: retention is disabled.');
      } else {
        setCleanupMsg(
          `Deleted ${(summary.deleted_events ?? 0).toLocaleString()} events, ${(summary.deleted_raw_logs ?? 0).toLocaleString()} raw logs in ${summary.duration_ms ?? 0}ms` +
          (summary.vacuum_ran ? ' (vacuum ran)' : '')
        );
      }
      await refetchDbStats();
      await refetchSettings();
    } catch (e) {
      setCleanupMsg(`Error: ${(e as Error).message}`);
    } finally {
      setCleanupRunning(false);
    }
  };

  const fmtTs = (iso: string | null | undefined) => {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString();
    } catch { return iso; }
  };

  const fmtBytes = (b: number | null | undefined) => {
    if (b == null) return '—';
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`;
    return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const lastCleanup = dbStats?.last_cleanup;

  return (
    <div className="max-w-3xl mx-auto p-6 space-y-6">
      <button
        type="button"
        onClick={onBack}
        className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors mb-2"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Dashboard
      </button>
      <h2 className="text-lg font-semibold text-foreground">Settings</h2>

      {/* ── Tabs ── */}
      <div className="space-y-4">
        <div className="flex gap-1 rounded-lg bg-muted/50 p-1 w-fit">
          {([
            { id: 'endpoints' as const, label: 'Device Inventory', icon: <Globe className="w-3.5 h-3.5" /> },
            { id: 'database' as const, label: 'Database', icon: <Database className="w-3.5 h-3.5" /> },
          ]).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-all',
                activeTab === tab.id
                  ? 'bg-card text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground',
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Device Inventory Tab ── */}
        {activeTab === 'endpoints' && (
          <div className="space-y-4">
            <div className="rounded-2xl border border-border bg-card p-5 space-y-4">
              <h3 className="text-sm font-semibold text-card-foreground flex items-center gap-2">
                <Globe className="w-4 h-4 text-primary" /> Local Networks
              </h3>
              <p className="text-xs text-muted-foreground">
                Define which CIDR ranges are considered &quot;local&quot;. When enabled, the Device Inventory page
                and the Dashboard Endpoint filters will default to showing only devices whose IP falls within these ranges.
              </p>
              <label className="flex items-center gap-3 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={lnEnabled}
                  onChange={(e) => setLnEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-border accent-primary"
                />
                Enable local-network pre-filter by default
              </label>

              {/* CIDR list */}
              <div className="space-y-2">
                {lnCidrs.length > 0 ? (
                  <div className="space-y-1">
                    {lnCidrs.map((cidr) => (
                      <div
                        key={cidr}
                        className="flex items-center justify-between gap-2 px-3 py-1.5 rounded-lg bg-muted/40 border border-border/50"
                      >
                        <span className="text-sm font-mono text-foreground">{cidr}</span>
                        <button
                          type="button"
                          onClick={() => handleRemoveCidr(cidr)}
                          className="p-0.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                          title="Remove"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground italic">No CIDRs configured. RFC1918 defaults will be used.</p>
                )}

                {/* Add new CIDR input */}
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={lnNewCidr}
                    onChange={(e) => { setLnNewCidr(e.target.value); setLnNewError(null); }}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddCidr()}
                    placeholder="e.g. 10.0.0.0/8"
                    className="h-9 w-48 rounded-lg border border-border bg-input px-3 text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/50"
                  />
                  <button
                    type="button"
                    onClick={handleAddCidr}
                    className="h-9 px-3 rounded-lg text-sm font-medium flex items-center gap-1.5 border border-border bg-card hover:bg-muted transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5" /> Add
                  </button>
                </div>
                {lnNewError && (
                  <p className="text-xs text-destructive">{lnNewError}</p>
                )}
              </div>

              {/* Save */}
              <div className="flex items-center gap-3 pt-1">
                <button
                  type="button"
                  onClick={handleSaveLocalNetworks}
                  disabled={lnSaving}
                  className={cn(
                    'h-9 px-4 rounded-lg text-sm font-semibold transition-all flex items-center gap-2',
                    'bg-primary text-primary-foreground hover:opacity-90 active:scale-[0.98] shadow-sm',
                    lnSaving && 'opacity-60 cursor-not-allowed',
                  )}
                >
                  {lnSaving && <Loader2 className="w-4 h-4 animate-spin" />}
                  Save
                </button>
                {lnSaveMsg && (
                  <span className={cn('text-xs', lnSaveMsg.startsWith('Error') ? 'text-destructive' : 'text-primary')}>
                    {lnSaveMsg}
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ── Database Tab ── */}
        {activeTab === 'database' && (
          <div className="space-y-6">
            {/* Card A: Log Retention */}
            <div className="rounded-2xl border border-border bg-card p-5 space-y-4">
              <h3 className="text-sm font-semibold text-card-foreground flex items-center gap-2">
                <Trash2 className="w-4 h-4 text-primary" /> Log Retention
              </h3>
              <label className="flex items-center gap-3 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={retEnabled}
                  onChange={(e) => setRetEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-border accent-primary"
                />
                Automatically delete old logs
              </label>
              <div className="flex items-center gap-3">
                <label className="text-sm text-muted-foreground">Keep logs for</label>
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={retDays}
                  onChange={(e) => setRetDays(Math.max(1, Math.min(365, Number(e.target.value) || 1)))}
                  className="h-9 w-20 rounded-lg border border-border bg-input px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring/50"
                />
                <span className="text-sm text-muted-foreground">days</span>
              </div>
              <div className="flex items-center gap-3 pt-1">
                <button
                  type="button"
                  onClick={handleSaveRetention}
                  disabled={saving}
                  className={cn(
                    'h-9 px-4 rounded-lg text-sm font-semibold transition-all flex items-center gap-2',
                    'bg-primary text-primary-foreground hover:opacity-90 active:scale-[0.98] shadow-sm',
                    saving && 'opacity-60 cursor-not-allowed',
                  )}
                >
                  {saving && <Loader2 className="w-4 h-4 animate-spin" />}
                  Save
                </button>
                <button
                  type="button"
                  onClick={handleRunCleanup}
                  disabled={cleanupRunning}
                  className={cn(
                    'h-9 px-4 rounded-lg text-sm font-medium transition-all flex items-center gap-2 border border-border bg-card hover:bg-muted',
                    cleanupRunning && 'opacity-60 cursor-not-allowed',
                  )}
                >
                  {cleanupRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                  Run cleanup now
                </button>
                {saveMsg && (
                  <span className={cn('text-xs', saveMsg.startsWith('Error') ? 'text-destructive' : 'text-primary')}>
                    {saveMsg}
                  </span>
                )}
              </div>
              {cleanupMsg && (
                <div className="text-xs bg-muted/60 rounded-lg px-3 py-2 text-muted-foreground">
                  {cleanupMsg}
                </div>
              )}
            </div>

            {/* Card B: Database Stats */}
            <div className="rounded-2xl border border-border bg-card p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-card-foreground flex items-center gap-2">
                  <Database className="w-4 h-4 text-primary" /> Database Stats
                </h3>
                <button
                  type="button"
                  onClick={() => refetchDbStats()}
                  disabled={dbStatsLoading}
                  className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 transition-colors"
                >
                  <RefreshCw className={cn('w-3.5 h-3.5', dbStatsLoading && 'animate-spin')} />
                  Refresh
                </button>
              </div>
              {dbStats ? (
                <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                  <span className="text-muted-foreground">DB type</span>
                  <span className="font-medium text-foreground">{dbStats.db_type ?? '—'}</span>

                  <span className="text-muted-foreground">Raw logs count</span>
                  <span className="font-medium text-foreground tabular-nums">{(dbStats.raw_logs_count ?? 0).toLocaleString()}</span>

                  <span className="text-muted-foreground">Events count</span>
                  <span className="font-medium text-foreground tabular-nums">{(dbStats.events_count ?? 0).toLocaleString()}</span>

                  <span className="text-muted-foreground">Oldest event</span>
                  <span className="text-foreground">{fmtTs(dbStats.oldest_event_ts)}</span>

                  <span className="text-muted-foreground">Newest event</span>
                  <span className="text-foreground">{fmtTs(dbStats.newest_event_ts)}</span>

                  <span className="text-muted-foreground">Oldest raw log</span>
                  <span className="text-foreground">{fmtTs(dbStats.oldest_raw_received_at)}</span>

                  <span className="text-muted-foreground">Newest raw log</span>
                  <span className="text-foreground">{fmtTs(dbStats.newest_raw_received_at)}</span>

                  {dbStats.db_file_size_bytes != null && (
                    <>
                      <span className="text-muted-foreground">DB file size</span>
                      <span className="font-medium text-foreground">{fmtBytes(dbStats.db_file_size_bytes)}</span>
                    </>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-xs text-muted-foreground py-3">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading…
                </div>
              )}

              {/* Last cleanup summary */}
              {lastCleanup && (
                <div className="pt-3 border-t border-border space-y-2">
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Last Cleanup</h4>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
                    <span className="text-muted-foreground">Ran at</span>
                    <span className="text-foreground">{fmtTs(lastCleanup.last_run)}</span>

                    <span className="text-muted-foreground">Deleted events</span>
                    <span className="font-medium text-foreground tabular-nums">{(lastCleanup.deleted_events ?? 0).toLocaleString()}</span>

                    <span className="text-muted-foreground">Deleted raw logs</span>
                    <span className="font-medium text-foreground tabular-nums">{(lastCleanup.deleted_raw_logs ?? 0).toLocaleString()}</span>

                    <span className="text-muted-foreground">Duration</span>
                    <span className="text-foreground">{(lastCleanup.duration_ms ?? 0).toLocaleString()} ms</span>

                    <span className="text-muted-foreground">Vacuum ran</span>
                    <span className="text-foreground">{lastCleanup.vacuum_ran ? 'Yes' : 'No'}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── useDebounce hook ── */
function useDebounce<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  React.useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(id);
  }, [value, delayMs]);
  return debounced;
}

/* ── Sortable column header ── */
type SortDir = 'asc' | 'desc';
type SortKey = 'name' | 'ip' | 'mac' | 'vendor' | 'type' | 'os' | 'seen_count' | 'first_seen' | 'last_seen';

function SortableHeader({
  label,
  sortKey,
  activeSortBy,
  activeSortDir,
  onSort,
  className,
}: {
  label: string;
  sortKey: SortKey;
  activeSortBy: string;
  activeSortDir: SortDir;
  onSort: (key: SortKey) => void;
  className?: string;
}) {
  const isActive = activeSortBy === sortKey;
  return (
    <th
      className={cn('px-3 py-2.5 font-medium', className)}
      aria-sort={isActive ? (activeSortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex items-center gap-1 hover:text-foreground transition-colors group"
      >
        {label}
        {isActive ? (
          activeSortDir === 'asc' ? (
            <ChevronUp className="w-3 h-3 text-primary" />
          ) : (
            <ChevronDown className="w-3 h-3 text-primary" />
          )
        ) : (
          <ArrowUpDown className="w-3 h-3 opacity-0 group-hover:opacity-50 transition-opacity" />
        )}
      </button>
    </th>
  );
}

function SortableHeaderStr({
  label,
  sortKey,
  activeSortBy,
  activeSortDir,
  onSort,
  className,
}: {
  label: string;
  sortKey: string;
  activeSortBy: string;
  activeSortDir: SortDir;
  onSort: (key: string) => void;
  className?: string;
}) {
  const isActive = activeSortBy === sortKey;
  return (
    <th className={cn('px-3 py-2.5 font-medium', className)} aria-sort={isActive ? (activeSortDir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" onClick={() => onSort(sortKey)} className="inline-flex items-center gap-1 hover:text-foreground transition-colors group">
        {label}
        {isActive ? (activeSortDir === 'asc' ? <ChevronUp className="w-3 h-3 text-primary" /> : <ChevronDown className="w-3 h-3 text-primary" />) : <ArrowUpDown className="w-3 h-3 opacity-0 group-hover:opacity-50 transition-opacity" />}
      </button>
    </th>
  );
}

/* ── Firewall source badges ── */
type ActiveImportJob = { job_id: string; filename?: string; progress?: number; status?: string };
function FirewallSourceBadges({
  source,
  isImporting,
  activeImportJobs,
  onOpenImportStatus,
  onOpenFirewallDetails,
}: {
  source?: { syslog: boolean; import: boolean; last_import_ts?: string | null; source_display?: string[] };
  isImporting?: boolean;
  activeImportJobs?: ActiveImportJob[];
  onOpenImportStatus?: (jobId: string) => void;
  onOpenFirewallDetails?: () => void;
}) {
  const firstJobId = activeImportJobs?.[0]?.job_id;
  const progressPct = activeImportJobs?.[0]?.progress != null ? Math.round(activeImportJobs[0].progress * 100) : null;
  const display = source?.source_display && source.source_display.length > 0 ? source.source_display : null;
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {isImporting && (firstJobId || onOpenFirewallDetails) && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            if (onOpenFirewallDetails) onOpenFirewallDetails();
            else if (firstJobId) onOpenImportStatus?.(firstJobId);
          }}
          className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/40 hover:bg-amber-500/30 transition-colors"
          title="View import progress"
        >
          <span className="animate-pulse">PROCESSING</span>
          {progressPct != null && <span className="opacity-80">({progressPct}%)</span>}
        </button>
      )}
      {source && (
        <>
          {display ? (
            display.map((label) =>
              label === 'IMPORT' ? (
                <span
                  key={label}
                  className="inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium bg-violet-500/15 text-violet-700 dark:text-violet-300 border border-violet-500/40"
                >
                  IMPORT
                </span>
              ) : label === 'SYSLOG' ? (
                <span
                  key={label}
                  className="inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium bg-primary/15 text-primary border border-primary/30"
                >
                  SYSLOG
                </span>
              ) : (
                <span key={label} className="text-muted-foreground text-xs">
                  {label}
                </span>
              )
            )
          ) : (
            <>
              {source.syslog && (
                <span className="inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium bg-primary/15 text-primary border border-primary/30">
                  SYSLOG
                </span>
              )}
              {source.import && (
                <span className="inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium bg-violet-500/15 text-violet-700 dark:text-violet-300 border border-violet-500/40">
                  IMPORT
                </span>
              )}
            </>
          )}
          {!display && !source.syslog && !source.import && !isImporting && <span className="text-muted-foreground text-xs">—</span>}
          {(display?.includes('IMPORT') || (source.import && !source.syslog)) && (
            <span className="text-[10px] text-muted-foreground italic" title="Not removed by log retention">
              Retention excluded
            </span>
          )}
        </>
      )}
      {!source && !isImporting && <span className="text-muted-foreground text-xs">—</span>}
    </span>
  );
}

/* ── Firewall Inventory Page ── */
type FirewallRow = {
  device_key: string;
  display_name: string;
  members: string[];
  oldest_log: string | null;
  latest_log: string | null;
  event_count: number;
  source?: { syslog: boolean; import: boolean; last_import_ts?: string | null; source_display?: string[] };
  is_importing?: boolean;
  active_import_jobs?: Array<{ job_id: string; filename?: string; progress?: number; status?: string }>;
};

function FirewallInventoryPage({ onOpenImportStatus }: { onOpenImportStatus?: (jobId: string) => void }) {
  const queryClient = useQueryClient();
  const { data: listRaw, isFetching } = useQuery({
    queryKey: ['firewalls'],
    queryFn: async () => {
      const res = await fetch(`${API}/firewalls`);
      if (!res.ok) throw new Error('Failed to load firewalls');
      return res.json();
    },
    refetchInterval: 5000,
  });
  const { data: activeJobsRaw } = useQuery({
    queryKey: ['ingest-jobs', 'active'],
    queryFn: async () => {
      const res = await fetch(`${API}/ingest/jobs?state=queued,running&limit=50`);
      if (!res.ok) return [];
      const json = await res.json();
      return (json?.jobs ?? []) as Array<{
        job_id: string;
        filename?: string | null;
        status?: string;
        phase?: string;
        progress?: number;
        lines_processed?: number;
        lines_total?: number;
        events_inserted?: number;
        discarded?: number;
        created_at?: string | null;
        device_key?: string | null;
      }>;
    },
    refetchInterval: 2000,
  });
  const pendingImportJobs = (activeJobsRaw ?? []).filter((j) => !j.device_key);
  const list = Array.isArray(listRaw) ? listRaw : (listRaw as { firewalls?: FirewallRow[] })?.firewalls ?? [];
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 250);
  const [sortBy, setSortBy] = useState<string>('latest_log');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [pageSize] = useState(20);
  const [currentPage, setCurrentPage] = useState(1);
  const [selected, setSelected] = useState<FirewallRow | null>(null);
  const [purgeConfirm, setPurgeConfirm] = useState<FirewallRow | null>(null);
  const [purgeJobId, setPurgeJobId] = useState<string | null>(null);
  const [appToast, setAppToast] = useState<string | null>(null);

  const filtered = React.useMemo(() => {
    let rows: FirewallRow[] = Array.isArray(list) ? list : [];
    if (debouncedSearch.trim()) {
      const q = debouncedSearch.trim().toLowerCase();
      rows = rows.filter(
        (r) =>
          (r.display_name || '').toLowerCase().includes(q) ||
          (r.members || []).some((m) => m.toLowerCase().includes(q)),
      );
    }
    return rows;
  }, [list, debouncedSearch]);

  const sorted = React.useMemo(() => {
    const s = [...filtered];
    const key = sortBy || 'latest_log';
    const dir = sortDir === 'asc' ? 1 : -1;
    s.sort((a, b) => {
      let va: string | number = (a as any)[key];
      let vb: string | number = (b as any)[key];
      if (key === 'event_count') {
        va = Number(va) ?? 0;
        vb = Number(vb) ?? 0;
        return dir * (va - vb);
      }
      if (key === 'members') {
        va = (Array.isArray(va) ? va : []).join(', ');
        vb = (Array.isArray(vb) ? vb : []).join(', ');
      }
      va = (va ?? '').toString();
      vb = (vb ?? '').toString();
      return dir * va.localeCompare(vb, undefined, { sensitivity: 'base' });
    });
    return s;
  }, [filtered, sortBy, sortDir]);

  const total = sorted.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const paginated = sorted.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  React.useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(1);
  }, [currentPage, totalPages]);

  const handleSort = React.useCallback((key: string) => {
    setSortBy((prev) => {
      if (prev === key) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        return prev;
      }
      setSortDir(key === 'latest_log' ? 'desc' : 'asc');
      return key;
    });
  }, []);

  const fmtTs = (iso: string | null | undefined) => {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
      return iso;
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-56px)] min-h-[320px]">
      <div className="m-3 mb-0">
        <div className="rounded-2xl border border-border bg-card p-4">
          <h2 className="text-lg font-semibold text-foreground">Firewall Inventory</h2>
          <p className="text-sm text-muted-foreground mt-0.5">Known firewalls and log coverage.</p>
          <div className="flex items-center gap-4 flex-wrap mt-3">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
              <input
                type="text"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Filter by name or members…"
                className="h-9 pl-8 pr-3 w-full rounded-lg border border-border bg-input text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/50 focus:border-ring"
              />
            </div>
            {isFetching && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
            <span className="text-xs text-muted-foreground">{total} firewall{total !== 1 ? 's' : ''}</span>
          </div>
        </div>
      </div>
      {pendingImportJobs.length > 0 && (
        <div className="mx-3 mt-3 rounded-2xl border border-border bg-card p-4">
          <h3 className="text-sm font-medium text-foreground mb-2">Pending imports (firewall not detected yet)</h3>
          <ul className="space-y-3">
            {pendingImportJobs.map((j) => {
              const pct = j.progress != null ? Math.round(j.progress * 100) : null;
              return (
                <li key={j.job_id} className="rounded-lg border border-border bg-muted/20 p-2.5 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-foreground truncate max-w-[240px]" title={j.filename ?? j.job_id}>{j.filename ?? j.job_id}</span>
                    <span className="text-xs text-muted-foreground">
                      {j.created_at ? new Date(j.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                    </span>
                    <span className="text-xs px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-700 dark:text-amber-300">{j.status ?? 'queued'}</span>
                    {j.phase && <span className="text-xs text-muted-foreground">{j.phase}</span>}
                  </div>
                  {(j.status === 'running' && (pct != null || (j.lines_processed != null && j.lines_processed > 0))) && (
                    <div className="flex items-center gap-2 mt-1.5">
                      <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden min-w-[80px]">
                        <div
                          className="h-full bg-primary transition-all duration-200"
                          style={{ width: `${pct != null ? Math.min(100, Math.max(0, pct)) : 0}%` }}
                        />
                      </div>
                      <span className="text-xs text-muted-foreground shrink-0">
                        {pct != null ? `${pct}%` : `${j.lines_processed ?? 0} lines`}
                      </span>
                    </div>
                  )}
                  {j.status === 'queued' && <div className="mt-1 text-xs text-muted-foreground">Queued — will start when the current job finishes</div>}
                </li>
              );
            })}
          </ul>
        </div>
      )}
      <div className="flex-1 flex flex-col mx-3 mt-3 overflow-hidden">
        <div className="flex-1 overflow-auto rounded-2xl border border-border bg-card">
          <table className="w-full text-sm border-collapse">
            <thead className="sticky top-0 z-10 bg-card border-b border-border">
              <tr className="text-left text-xs text-muted-foreground">
                <SortableHeaderStr label="Firewall(s)" sortKey="display_name" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                <SortableHeaderStr label="Members" sortKey="members" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 font-medium text-muted-foreground">Source</th>
                <SortableHeaderStr label="Oldest log" sortKey="oldest_log" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                <SortableHeaderStr label="Latest log" sortKey="latest_log" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                <SortableHeaderStr label="Events" sortKey="event_count" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} className="text-right" />
                <th className="px-3 py-2.5 font-medium text-right w-[80px]">Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginated.map((r) => (
                <tr
                  key={r.device_key}
                  className="border-b border-border/50 hover:bg-muted/30 cursor-pointer transition-colors"
                  onClick={() => setSelected(r)}
                >
                  <td className="px-3 py-2 font-medium text-foreground truncate max-w-[220px]" title={r.display_name}>{r.display_name}</td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {Array.isArray(r.members) && r.members.length > 0 ? r.members.join(', ') : '—'}
                  </td>
                  <td className="px-3 py-2">
                    <FirewallSourceBadges
                      source={r.source}
                      isImporting={r.is_importing}
                      activeImportJobs={r.active_import_jobs}
                      onOpenImportStatus={onOpenImportStatus}
                      onOpenFirewallDetails={() => setSelected(r)}
                    />
                  </td>
                  <td className="px-3 py-2 text-muted-foreground whitespace-nowrap">{fmtTs(r.oldest_log)}</td>
                  <td className="px-3 py-2 text-muted-foreground whitespace-nowrap">{fmtTs(r.latest_log)}</td>
                  <td className="px-3 py-2 text-muted-foreground text-right">{typeof r.event_count === 'number' ? r.event_count.toLocaleString() : '—'}</td>
                  <td className="px-3 py-2 text-right" onClick={(e) => e.stopPropagation()}>
                    <button
                      type="button"
                      disabled={!!purgeJobId}
                      onClick={() => setPurgeConfirm(r)}
                      className="p-1.5 rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 disabled:opacity-50 disabled:pointer-events-none transition-colors"
                      title="Purge firewall data"
                      aria-label="Purge firewall data"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && (
          <div className="flex items-center justify-between gap-2 pt-2 px-1">
            <button
              type="button"
              disabled={currentPage <= 1}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              className="h-8 px-3 rounded-md text-sm border border-border bg-background text-foreground disabled:opacity-50"
            >
              Previous
            </button>
            <span className="text-xs text-muted-foreground">
              Page {currentPage} of {totalPages}
            </span>
            <button
              type="button"
              disabled={currentPage >= totalPages}
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              className="h-8 px-3 rounded-md text-sm border border-border bg-background text-foreground disabled:opacity-50"
            >
              Next
            </button>
          </div>
        )}
      </div>
      {selected && (
        <FirewallOverrideModal
          firewall={selected}
          onClose={() => setSelected(null)}
          onSaved={() => {
            queryClient.invalidateQueries({ queryKey: ['firewalls'] });
            queryClient.invalidateQueries({ queryKey: ['devices/groups'] });
            setSelected(null);
          }}
        />
      )}
      {purgeConfirm && (
        <PurgeConfirmModal
          firewall={purgeConfirm}
          onClose={() => setPurgeConfirm(null)}
          onConfirm={(jobId) => {
            setPurgeConfirm(null);
            setPurgeJobId(jobId);
          }}
          onBusy={() => {
            setPurgeConfirm(null);
            setAppToast('Database busy (import/cleanup running). Try again later.');
            setTimeout(() => setAppToast(null), 5000);
          }}
        />
      )}
      {purgeJobId && (
        <PurgeProgressModal
          jobId={purgeJobId}
          onClose={() => {
            setPurgeJobId(null);
            queryClient.invalidateQueries({ queryKey: ['firewalls'] });
            queryClient.invalidateQueries({ queryKey: ['devices/groups'] });
          }}
        />
      )}
      {appToast && (
        <div className="fixed bottom-4 right-4 z-[100] px-4 py-2 rounded-lg bg-destructive/90 text-destructive-foreground text-sm font-medium shadow-lg">
          {appToast}
        </div>
      )}
    </div>
  );
}

type FirewallImportJob = {
  job_id: string;
  filename?: string | null;
  status: string;
  phase?: string;
  progress?: number;
  lines_processed?: number;
  lines_total?: number;
  parse_ok?: number;
  parse_err?: number;
  raw_logs_inserted?: number;
  events_inserted?: number;
  time_min?: string | null;
  time_max?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  error_message?: string | null;
};

function FirewallOverrideModal({
  firewall,
  onClose,
  onSaved,
}: {
  firewall: FirewallRow;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [displayName, setDisplayName] = useState(firewall.display_name || '');
  const [comment, setComment] = useState('');
  const [loading, setLoading] = useState(false);
  const [overrideData, setOverrideData] = useState<{ display_name: string | null; comment: string | null } | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: importJobs = [], refetch: refetchImportJobs } = useQuery({
    queryKey: ['firewalls', firewall.device_key, 'import-jobs'],
    queryFn: async () => {
      const res = await fetch(`${API}/firewalls/${encodeURIComponent(firewall.device_key)}/import-jobs`);
      if (!res.ok) return [];
      const json = await res.json();
      return (Array.isArray(json) ? json : json?.jobs ?? []) as FirewallImportJob[];
    },
  });
  const handleCancelImport = React.useCallback(async (jobId: string) => {
    try {
      await fetch(`${API}/ingest/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' });
      refetchImportJobs();
    } catch (_) {}
  }, [refetchImportJobs]);

  React.useEffect(() => {
    setDisplayName(firewall.display_name || '');
    let cancelled = false;
    setLoading(true);
    fetch(`${API}/firewalls/${encodeURIComponent(firewall.device_key)}`)
      .then((res) => res.json())
      .then((data) => {
        if (!cancelled) {
          setOverrideData(data);
          if (data?.display_name != null) setDisplayName(data.display_name || '');
          if (data?.comment != null) setComment(data.comment || '');
        }
      })
      .catch(() => { if (!cancelled) setOverrideData({ display_name: null, comment: null }); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [firewall.device_key, firewall.display_name]);

  const handleSave = React.useCallback(async () => {
    const name = displayName.trim();
    if (!name) {
      setError('Display name is required');
      return;
    }
    setError(null);
    setSaving(true);
    try {
      const res = await fetch(`${API}/firewalls/${encodeURIComponent(firewall.device_key)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ display_name: name, comment: comment.trim() || '' }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.detail ?? res.statusText);
      }
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  }, [firewall.device_key, displayName, comment, onSaved]);

  const fmtTs = (iso: string | null | undefined) => {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
      return iso;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-card border border-border rounded-2xl shadow-xl max-w-md w-full mx-3 max-h-[90vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-border">
          <h3 className="text-lg font-semibold text-foreground">Edit firewall</h3>
        </div>
        <div className="px-6 py-4 overflow-y-auto flex-1 space-y-4">
          {loading ? (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          ) : (
            <>
              <div>
                <label className="text-xs text-muted-foreground">Firewall key</label>
                <p className="text-sm font-mono text-foreground mt-0.5">{firewall.device_key}</p>
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Members</label>
                <p className="text-sm text-foreground mt-0.5">
                  {Array.isArray(firewall.members) && firewall.members.length > 0 ? firewall.members.join(', ') : '—'}
                </p>
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Oldest / Latest log</label>
                <p className="text-sm text-foreground mt-0.5">{fmtTs(firewall.oldest_log)} — {fmtTs(firewall.latest_log)}</p>
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Display name</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Override display name"
                  className="w-full h-9 rounded-lg border border-border bg-input px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring/50"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Comment</label>
                <textarea
                  value={comment}
                  onChange={(e) => setComment(e.target.value.slice(0, 2000))}
                  placeholder="Optional comment"
                  rows={3}
                  className="w-full rounded-lg border border-border bg-input px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring/50 resize-y"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Import jobs</label>
                {importJobs.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No import jobs for this firewall.</p>
                ) : (
                  <ul className="space-y-2 max-h-48 overflow-y-auto">
                    {importJobs.map((j) => (
                      <li key={j.job_id} className="rounded-lg border border-border bg-muted/20 p-2 text-sm">
                        <div className="flex justify-between items-start gap-2">
                          <span className="font-medium text-foreground truncate">{j.filename ?? j.job_id}</span>
                          <span className="text-xs text-muted-foreground shrink-0">{j.status}</span>
                        </div>
                        {j.created_at && (
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {new Date(j.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                          </p>
                        )}
                        {(j.status === 'running' || j.status === 'queued') && (
                          <>
                            {j.status === 'running' && j.progress != null && (
                              <div className="flex items-center gap-2 mt-1">
                                <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                                  <div className="h-full bg-primary" style={{ width: `${Math.round((j.progress ?? 0) * 100)}%` }} />
                                </div>
                                <span className="text-xs">{Math.round((j.progress ?? 0) * 100)}%</span>
                              </div>
                            )}
                            <div className="flex flex-wrap gap-2 mt-1 text-xs text-muted-foreground">
                              {(j.lines_processed ?? 0) > 0 && <span>Lines: {j.lines_processed}</span>}
                              {(j.raw_logs_inserted ?? 0) > 0 && <span>Inserted: {j.raw_logs_inserted}</span>}
                              {(j.parse_err ?? 0) > 0 && <span>Parse err: {j.parse_err}</span>}
                            </div>
                            {(j.time_min || j.time_max) && (
                              <p className="text-xs text-muted-foreground mt-0.5">
                                {j.time_min ?? '…'} → {j.time_max ?? '…'}
                              </p>
                            )}
                            <button
                              type="button"
                              onClick={() => handleCancelImport(j.job_id)}
                              className="mt-2 h-7 px-2 rounded text-xs font-medium border border-destructive/50 text-destructive hover:bg-destructive/10"
                            >
                              Cancel import
                            </button>
                          </>
                        )}
                        {j.status === 'done' && (
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {j.raw_logs_inserted ?? 0} raw logs, {j.events_inserted ?? 0} events
                            {j.time_min && j.time_max ? ` · ${j.time_min} → ${j.time_max}` : ''}
                          </p>
                        )}
                        {j.status === 'error' && j.error_message && (
                          <p className="text-xs text-destructive mt-0.5 truncate" title={j.error_message}>{j.error_message}</p>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
            </>
          )}
        </div>
        <div className="px-6 py-4 border-t border-border flex justify-end gap-2">
          <button type="button" onClick={onClose} className="h-9 px-4 rounded-lg text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted">
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving || loading}
            className="h-9 px-4 rounded-lg text-sm font-medium bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-60"
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin inline mr-1.5" /> : null}
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

const PURGE_CONFIRM_TEXT = 'PURGE';

function PurgeConfirmModal({
  firewall,
  onClose,
  onConfirm,
  onBusy,
}: {
  firewall: FirewallRow;
  onClose: () => void;
  onConfirm: (jobId: string) => void;
  onBusy: () => void;
}) {
  const [typed, setTyped] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const canConfirm = typed.trim().toUpperCase() === PURGE_CONFIRM_TEXT;

  const handlePurge = React.useCallback(async () => {
    if (!canConfirm) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch(`${API}/firewalls/${encodeURIComponent(firewall.device_key)}/purge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409) {
        onBusy();
        return;
      }
      if (!res.ok) {
        setError(data?.detail ?? res.statusText ?? 'Purge failed');
        return;
      }
      if (data?.ok && data?.job_id) {
        onConfirm(data.job_id);
      } else {
        setError('Invalid response');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Request failed');
    } finally {
      setSubmitting(false);
    }
  }, [canConfirm, firewall.device_key, onBusy, onConfirm]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-card border border-border rounded-2xl shadow-xl max-w-md w-full mx-3" onClick={(e) => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-border">
          <h3 className="text-lg font-semibold text-foreground">Purge firewall data?</h3>
        </div>
        <div className="px-6 py-4 space-y-4">
          <p className="text-sm text-foreground font-medium">{firewall.display_name}</p>
          <p className="text-sm text-muted-foreground">
            This will permanently delete all logs and derived data for this firewall.
          </p>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">
              Type <strong>{PURGE_CONFIRM_TEXT}</strong> to confirm
            </label>
            <input
              type="text"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={PURGE_CONFIRM_TEXT}
              className="w-full h-9 rounded-lg border border-border bg-input px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring/50 font-mono"
              autoComplete="off"
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <div className="px-6 py-4 border-t border-border flex justify-end gap-2">
          <button type="button" onClick={onClose} className="h-9 px-4 rounded-lg text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted">
            Cancel
          </button>
          <button
            type="button"
            onClick={handlePurge}
            disabled={!canConfirm || submitting}
            className="h-9 px-4 rounded-lg text-sm font-medium bg-destructive text-destructive-foreground hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? <Loader2 className="w-4 h-4 animate-spin inline mr-1.5" /> : null}
            Purge
          </button>
        </div>
      </div>
    </div>
  );
}

function PurgeProgressModal({ jobId, onClose }: { jobId: string; onClose: () => void }) {
  const [job, setJob] = useState<{ status: string; result_counts?: Record<string, number>; error_message?: string | null } | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetch(`${API}/maintenance/jobs/${encodeURIComponent(jobId)}`);
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setJob(data);
        if (data?.status === 'done' || data?.status === 'error') return;
      } catch {
        if (!cancelled) setJob((prev) => prev || { status: 'error' });
        return;
      }
    };
    poll();
    const interval = setInterval(poll, 1000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [jobId]);

  const counts = job?.result_counts ?? {};
  const isDone = job?.status === 'done';
  const isError = job?.status === 'error';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-card border border-border rounded-2xl shadow-xl max-w-md w-full mx-3" onClick={(e) => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-border">
          <h3 className="text-lg font-semibold text-foreground">
            {isDone ? 'Purge complete' : isError ? 'Purge failed' : 'Purging…'}
          </h3>
        </div>
        <div className="px-6 py-4 space-y-3">
          {!job && (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          )}
          {job?.status === 'running' && (
            <p className="text-sm text-muted-foreground">Deleting firewall data…</p>
          )}
          {isError && job?.error_message && (
            <p className="text-sm text-destructive">{job.error_message}</p>
          )}
          {isDone && Object.keys(counts).length > 0 && (
            <div className="text-sm space-y-1">
              {Object.entries(counts).map(([k, v]) => (
                <div key={k} className="flex justify-between gap-4">
                  <span className="text-muted-foreground">{k.replace(/_/g, ' ')}</span>
                  <span className="font-medium text-foreground">{Number(v).toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="px-6 py-4 border-t border-border flex justify-end">
          <button type="button" onClick={onClose} className="h-9 px-4 rounded-lg text-sm font-medium bg-primary text-primary-foreground hover:opacity-90">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Device details sheet (Device Inventory) — right-side panel ── */
function DeviceDetailsModal({
  open,
  onClose,
  mac,
  device,
  deviceLabel: deviceLabelProp,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  mac: string;
  device: string;
  /** Display label for firewall (e.g. "gw-mand (HA)"). Prefer from device/groups API. */
  deviceLabel?: string;
  onSaved: () => void;
}) {
  const { data, isFetching } = useQuery({
    queryKey: ['device-inventory', mac, device],
    queryFn: async () => {
      const res = await fetch(`${API}/device-inventory/${encodeURIComponent(mac)}?device=${encodeURIComponent(device)}`);
      if (!res.ok) throw new Error('Failed to load device details');
      return res.json();
    },
    enabled: open && !!mac && !!device,
  });

  const [vendor, setVendor] = useState('');
  const [typeName, setTypeName] = useState('');
  const [osName, setOsName] = useState('');
  const [brand, setBrand] = useState('');
  const [model, setModel] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  React.useEffect(() => {
    if (!data) return;
    const ov = data.override || {};
    setVendor(ov.vendor ?? '');
    setTypeName(ov.type_name ?? '');
    setOsName(ov.os_name ?? '');
    setBrand(ov.brand ?? '');
    setModel(ov.model ?? '');
    setComment(ov.comment ?? '');
  }, [data]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`${API}/device-inventory/${encodeURIComponent(mac)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device,
          override: {
            vendor: vendor.trim() || null,
            type_name: typeName.trim() || null,
            os_name: osName.trim() || null,
            brand: brand.trim() || null,
            model: model.trim() || null,
            comment: comment.trim() || null,
          },
        }),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || 'Save failed');
      }
      onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleClearOverrides = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`${API}/device-inventory/${encodeURIComponent(mac)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device,
          override: { vendor: null, type_name: null, os_name: null, brand: null, model: null, comment: null },
        }),
      });
      if (!res.ok) throw new Error('Clear failed');
      onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const fmtTs = (iso: string | null | undefined) => {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }); } catch { return iso; }
  };

  // Firewall(s) must show full name: e.g. ha:gw-mand → "gw-mand (HA)" (never drop first char).
  // Prefer device/groups label; fallback: strip exactly "ha:" (3 chars) from id.
  const firewallDisplayLabel =
    deviceLabelProp != null && deviceLabelProp.trim() !== ''
      ? deviceLabelProp
      : device.startsWith('ha:')
        ? `${device.slice(3)} (HA)`
        : device;
  const auto = data?.auto || {};
  const ov = data?.override || {};
  const hasAnyOverride = !!(ov.vendor || ov.type_name || ov.os_name || ov.brand || ov.model || (ov.comment && String(ov.comment).trim()));
  const merged = {
    vendor: (ov.vendor || auto.vendor) || null,
    type_name: (ov.type_name || auto.type_name) || null,
    os_name: (ov.os_name || auto.os_name) || null,
    brand: (ov.brand || auto.brand) || null,
    model: (ov.model || auto.model) || null,
  };
  const displayTitle = data?.device_name || data?.ip || '—';
  const autoRows = [
    { label: 'Vendor', value: auto.vendor },
    { label: 'Type', value: auto.type_name },
    { label: 'OS', value: auto.os_name },
    { label: 'Brand', value: auto.brand },
    { label: 'Model', value: auto.model },
  ].filter((r) => r.value);

  const overrideFields = [
    { key: 'vendor' as const, label: 'Vendor', value: vendor, set: setVendor },
    { key: 'type_name' as const, label: 'Type', value: typeName, set: setTypeName },
    { key: 'os_name' as const, label: 'OS', value: osName, set: setOsName },
    { key: 'brand' as const, label: 'Brand', value: brand, set: setBrand },
    { key: 'model' as const, label: 'Model', value: model, set: setModel },
  ];

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex justify-end">
      {/* Overlay */}
      <div
        className="absolute inset-0 bg-black/30 transition-opacity"
        onClick={onClose}
        aria-hidden
      />
      {/* Sheet panel */}
      <div
        className="relative z-10 w-full max-w-xl sm:w-[520px] h-full bg-card shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Fixed header */}
        <div className="flex-shrink-0 flex items-start justify-between gap-4 border-b border-border px-6 py-4">
          <div className="min-w-0">
            <h2 className="text-xl font-bold text-foreground truncate">{displayTitle}</h2>
            <p className="text-sm text-muted-foreground font-mono mt-0.5">
              {data?.device_name && data?.ip ? `${data.ip} · ` : ''}{data?.mac ?? mac}
            </p>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {merged.vendor && <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-muted text-foreground">{merged.vendor}</span>}
              {merged.type_name && <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-muted text-foreground">{merged.type_name}</span>}
              {merged.os_name && <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-muted text-foreground">{merged.os_name}</span>}
              {hasAnyOverride && <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded text-xs font-medium bg-primary/15 text-primary">Edited</span>}
            </div>
          </div>
          <button type="button" onClick={onClose} className="p-2 rounded-lg hover:bg-muted text-muted-foreground flex-shrink-0" aria-label="Close">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {isFetching && !data && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground py-8">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          )}

          {data && (
            <>
              {/* Overview */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-foreground">Overview</h3>
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  <span className="text-muted-foreground">First seen</span>
                  <span className="font-medium text-foreground">{fmtTs(data.first_seen)}</span>
                  <span className="text-muted-foreground">Last seen</span>
                  <span className="font-medium text-foreground">{fmtTs(data.last_seen)}</span>
                  <span className="text-muted-foreground">Seen</span>
                  <span className="font-medium text-foreground">{(data.seen_count ?? 0).toLocaleString()}</span>
                  <span className="text-muted-foreground">Firewall(s)</span>
                  <span className="font-medium text-foreground">{firewallDisplayLabel}</span>
                </div>
              </div>

              <div className="h-px bg-border" />

              {/* Automatic Identification */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-foreground">Automatic Identification</h3>
                {autoRows.length > 0 ? (
                  <div className="rounded-lg bg-muted/30 border border-border/50 overflow-hidden">
                    <table className="w-full text-sm">
                      <tbody>
                        {autoRows.map(({ label, value }) => (
                          <tr key={label} className="border-b border-border/50 last:border-0">
                            <td className="py-2 px-3 text-muted-foreground w-[100px]">{label}</td>
                            <td className="py-2 px-3 font-medium text-foreground">{value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No automatic identification available</p>
                )}
              </div>

              <div className="h-px bg-border" />

              {/* Manual Override */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-foreground">Manual Override</h3>
                <p className="text-xs text-muted-foreground">Leave fields empty to use automatic identification.</p>
                <div className="rounded-lg bg-muted/40 border border-border/50 p-4 space-y-3">
                  {overrideFields.map(({ key, label, value, set }) => (
                    <div key={key} className="flex gap-2 items-center">
                      <div className="flex-1 min-w-0">
                        <label className="flex items-center gap-1.5 text-xs text-muted-foreground mb-0.5">
                          {label}
                          {value.trim() && <span className="text-[10px] font-medium text-primary bg-primary/10 px-1 rounded">Override</span>}
                        </label>
                        <input
                          type="text"
                          value={value}
                          onChange={(e) => set(e.target.value)}
                          className={cn(
                            'w-full h-9 rounded-lg border bg-background/80 px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring/50',
                            value.trim() ? 'border-primary/50' : 'border-border',
                          )}
                        />
                      </div>
                      <button
                        type="button"
                        onClick={() => set('')}
                        className="p-2 rounded-lg hover:bg-muted text-muted-foreground flex-shrink-0"
                        title="Reset"
                        aria-label={`Reset ${label}`}
                      >
                        <RotateCcw className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="h-px bg-border" />

              {/* Notes */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-foreground">Notes</h3>
                <div className="rounded-lg bg-muted/40 border border-border/50 overflow-hidden">
                  <textarea
                    value={comment}
                    onChange={(e) => setComment(e.target.value.slice(0, 2000))}
                    placeholder="Optional note…"
                    rows={5}
                    className="w-full rounded-t-lg bg-transparent px-3 py-2.5 pb-8 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/50 resize-y border-0"
                  />
                  <div className="flex justify-end px-3 py-1.5 border-t border-border/50">
                    <p className="text-[11px] text-muted-foreground">{comment.length}/2000</p>
                  </div>
                </div>
              </div>

              {error && (
                <p className="text-sm text-destructive">{error}</p>
              )}
            </>
          )}
        </div>

        {/* Sticky footer */}
        {data && (
          <div className="flex-shrink-0 border-t border-border bg-card px-6 py-4 flex items-center justify-between gap-4">
            <button type="button" onClick={onClose} className="h-9 px-4 rounded-lg text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted">
              Cancel
            </button>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleClearOverrides}
                disabled={saving}
                className="h-9 px-4 rounded-lg text-sm font-medium border border-destructive/50 text-destructive hover:bg-destructive/10"
              >
                Clear all overrides
              </button>
              <button
                type="button"
                onClick={handleSave}
                disabled={saving}
                className={cn(
                  'h-9 px-4 rounded-lg text-sm font-semibold bg-primary text-primary-foreground hover:opacity-90',
                  saving && 'opacity-60 cursor-not-allowed',
                )}
              >
                {saving ? <Loader2 className="w-4 h-4 animate-spin inline mr-1.5" /> : null}
                Save changes
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Device Inventory Page ── */
function EndpointsPage() {
  const { data: deviceGroups = [] } = useQuery({
    queryKey: ['devices/groups'],
    queryFn: async () => {
      const res = await fetch(`${API}/devices/groups`);
      if (!res.ok) throw new Error('Failed to load device groups');
      return res.json();
    },
  });

  // Fetch local_networks setting for default toggle state
  const { data: lnSettingData } = useQuery({
    queryKey: ['settings/local-networks'],
    queryFn: async () => {
      const res = await fetch(`${API}/settings/local-networks`);
      if (!res.ok) return { enabled: true, cidrs: [] };
      return res.json();
    },
  });

  const queryClient = useQueryClient();
  const [device, setDevice] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(20);
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 250);
  const [sortBy, setSortBy] = useState<string>('');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [localOnly, setLocalOnly] = useState<boolean | null>(null); // null = not yet initialised from setting
  const [selectedForModal, setSelectedForModal] = useState<{ mac: string; device: string } | null>(null);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  // Initialise localOnly from setting once fetched
  React.useEffect(() => {
    if (localOnly === null && lnSettingData) {
      setLocalOnly(lnSettingData.enabled ?? true);
    }
  }, [lnSettingData, localOnly]);

  // Reset page when device, search, sort, or localOnly changes
  React.useEffect(() => { setCurrentPage(1); }, [device, debouncedSearch, sortBy, sortDir, localOnly]);
  // Clear search when device changes
  React.useEffect(() => { setSearchInput(''); }, [device]);

  const handleSort = React.useCallback((key: SortKey) => {
    if (key === sortBy) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(key);
      setSortDir('asc');
    }
  }, [sortBy]);

  const effectiveLocalOnly = localOnly ?? true;

  const { data, isFetching } = useQuery({
    queryKey: ['endpoints/known', device, currentPage, pageSize, debouncedSearch, sortBy, sortDir, effectiveLocalOnly],
    queryFn: async () => {
      const params = new URLSearchParams({
        device,
        page: String(currentPage),
        page_size: String(pageSize),
        local_only: String(effectiveLocalOnly),
      });
      if (debouncedSearch) params.set('q', debouncedSearch);
      if (sortBy) {
        params.set('sort_by', sortBy);
        params.set('sort_dir', sortDir);
      }
      const res = await fetch(`${API}/endpoints/known?${params}`);
      if (!res.ok) throw new Error('Failed to load device inventory');
      return res.json();
    },
    enabled: !!device,
    placeholderData: keepPreviousData,
  });

  const items: any[] = data?.items ?? [];
  const total: number = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const fmtTs = (iso: string | null | undefined) => {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); } catch { return iso; }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-56px)] min-h-[320px]">
      {/* Filter bar */}
      <div className="m-3 mb-0">
        <div className="rounded-2xl border border-border bg-card p-4">
          <div className="flex items-center gap-4 flex-wrap">
            <FieldLabel label="Firewall">
              <StyledSelect value={device} onChange={setDevice} className="min-w-[200px]">
                <option value="">Select firewall</option>
                {(deviceGroups as { id: string; label: string }[]).map((g) => (
                  <option key={g.id} value={g.id}>{g.label}</option>
                ))}
              </StyledSelect>
            </FieldLabel>
            {device && (
              <FieldLabel label="Quick filter">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
                  <input
                    type="text"
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    placeholder="Filter by name, IP, MAC, vendor, type, OS…"
                    className="h-9 pl-8 pr-3 w-56 rounded-lg border border-border bg-input text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/50 focus:border-ring"
                  />
                </div>
              </FieldLabel>
            )}
            {device && (
              <label className="flex items-center gap-2 self-end pb-0.5 cursor-pointer select-none" title="Show only devices within configured local CIDR ranges">
                <span className="text-xs text-muted-foreground whitespace-nowrap">Local only</span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={effectiveLocalOnly}
                  onClick={() => setLocalOnly((prev) => !(prev ?? true))}
                  className={cn(
                    'relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer',
                    effectiveLocalOnly ? 'bg-primary' : 'bg-muted',
                  )}
                >
                  <span
                    className={cn(
                      'pointer-events-none inline-block h-4 w-4 rounded-full bg-background shadow-lg ring-0 transition-transform',
                      effectiveLocalOnly ? 'translate-x-4' : 'translate-x-0',
                    )}
                  />
                </button>
              </label>
            )}
            <div className="flex items-center gap-2 self-end pb-0.5 ml-auto">
              {device && !isFetching && (
                <span className="text-xs text-muted-foreground">
                  {total.toLocaleString()} device{total !== 1 ? 's' : ''}
                </span>
              )}
              {isFetching && (
                <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
              )}
            </div>
          </div>
        </div>
      </div>

      {/* No device */}
      {!device && (
        <div className="flex-1 flex items-center justify-center m-3">
          <div className="flex flex-col items-center gap-3 text-muted-foreground text-center max-w-sm">
            <Network className="w-12 h-12 opacity-40" />
            <p className="text-sm font-medium text-foreground">Select a Firewall</p>
            <p className="text-xs">Choose a firewall to view its device inventory.</p>
          </div>
        </div>
      )}

      {/* Table */}
      {device && items.length > 0 && (
        <div className="flex-1 flex flex-col mx-3 mt-3 overflow-hidden">
          <div className="flex-1 overflow-auto rounded-2xl border border-border bg-card">
            <table className="w-full text-sm border-collapse">
              <thead className="sticky top-0 z-10 bg-card border-b border-border">
                <tr className="text-left text-xs text-muted-foreground">
                  <SortableHeader label="Name" sortKey="name" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="IP" sortKey="ip" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="MAC" sortKey="mac" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Vendor" sortKey="vendor" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Type" sortKey="type" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="OS" sortKey="os" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Seen" sortKey="seen_count" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} className="text-right" />
                  <SortableHeader label="First seen" sortKey="first_seen" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Last seen" sortKey="last_seen" activeSortBy={sortBy} activeSortDir={sortDir} onSort={handleSort} />
                </tr>
              </thead>
              <tbody>
                {items.map((ep: any, i: number) => (
                  <tr
                    key={ep.endpoint_id ?? i}
                    className={cn(
                      'border-b border-border/50 transition-colors',
                      ep.mac ? 'cursor-pointer hover:bg-muted/30' : '',
                    )}
                    onClick={() => {
                      if (ep.mac && device) {
                        setSelectedForModal({ mac: ep.mac, device });
                      }
                    }}
                  >
                    <td className="px-3 py-2 text-foreground font-medium truncate max-w-[180px]">
                      <span className="inline-flex items-center gap-1.5">
                        {ep.hostname || ep.device_name || <span className="text-muted-foreground">—</span>}
                        {ep.has_override && (
                          <span className="inline-flex items-center gap-0.5 text-[10px] font-normal text-primary bg-primary/10 px-1.5 py-0.5 rounded" title="Manually edited">
                            <Pencil className="w-3 h-3" /> Edited
                          </span>
                        )}
                        {ep.comment && (
                          <span className="text-muted-foreground" title={ep.comment}>
                            <MessageSquare className="w-3.5 h-3.5" />
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-foreground">{ep.ip}</td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {ep.mac ? <span className="text-foreground">{ep.mac}</span> : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 truncate max-w-[140px]">
                      {ep.vendor ? <span className="text-foreground">{ep.vendor}</span> : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 truncate max-w-[120px]">
                      {ep.type_name ? <span className="text-foreground">{ep.type_name}</span> : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 truncate max-w-[100px]">
                      {ep.os_name ? <span className="text-foreground">{ep.os_name}</span> : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-foreground">
                      {(ep.seen_count ?? 0).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground whitespace-nowrap">{fmtTs(ep.first_seen)}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground whitespace-nowrap">{fmtTs(ep.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-1 py-2.5 text-xs text-muted-foreground">
              <span>Page {currentPage} of {totalPages}</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage <= 1}
                  className={cn(
                    'h-8 px-3 rounded-lg border border-border text-sm font-medium transition-colors',
                    currentPage > 1
                      ? 'bg-card text-foreground hover:bg-muted'
                      : 'bg-muted/50 text-muted-foreground cursor-not-allowed',
                  )}
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage >= totalPages}
                  className={cn(
                    'h-8 px-3 rounded-lg border border-border text-sm font-medium transition-colors',
                    currentPage < totalPages
                      ? 'bg-card text-foreground hover:bg-muted'
                      : 'bg-muted/50 text-muted-foreground cursor-not-allowed',
                  )}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty after loading */}
      {device && !isFetching && items.length === 0 && (
        <div className="flex-1 flex items-center justify-center m-3">
          <div className="flex flex-col items-center gap-3 text-muted-foreground">
            <Inbox className="w-12 h-12 opacity-40" />
            <p className="text-sm">{debouncedSearch ? 'No devices match your filter.' : 'No devices found for this firewall.'}</p>
          </div>
        </div>
      )}

      {/* Device details modal */}
      {selectedForModal && (
        <DeviceDetailsModal
          open={!!selectedForModal}
          onClose={() => setSelectedForModal(null)}
          mac={selectedForModal.mac}
          device={selectedForModal.device}
          deviceLabel={(deviceGroups as { id: string; label: string }[]).find((g) => g.id === selectedForModal.device)?.label}
          onSaved={() => {
            queryClient.invalidateQueries({ queryKey: ['endpoints/known'] });
            setToastMsg('Device updated');
            setTimeout(() => setToastMsg(null), 2000);
          }}
        />
      )}

      {/* Toast */}
      {toastMsg && (
        <div className="fixed bottom-4 right-4 z-[101] px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium shadow-lg">
          {toastMsg}
        </div>
      )}
    </div>
  );
}

/* ── Import summary (upload response) ── */
type ImportSummary = {
  ok: boolean;
  filename?: string;
  bytes?: number;
  device_detected?: string;
  device_key?: string;
  device_display?: string;
  lines_total?: number;
  records_total?: number;
  raw_logs_inserted?: number;
  events_inserted?: number;
  parse_ok?: number;
  parse_err?: number;
  filtered_id?: number;
  time_min?: string | null;
  time_max?: string | null;
};

function formatImportTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
  } catch {
    return iso;
  }
}

/** Convert ISO timestamp to datetime-local input value (YYYY-MM-DDTHH:mm) in local time. */
function isoToDatetimeLocal(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/* ── Job status (polling response) ── */
type JobStatus = {
  job_id: string;
  status: 'queued' | 'uploading' | 'running' | 'processing' | 'done' | 'error' | 'canceled';
  state?: string;
  phase?: string;
  progress?: number;
  filename?: string;
  bytes_total?: number;
  bytes_received?: number;
  bytes_processed?: number;
  lines_total?: number;
  lines_processed?: number;
  parse_ok?: number;
  parse_err?: number;
  filtered_id?: number;
  raw_logs_inserted?: number;
  events_inserted?: number;
  imported?: number;
  discarded?: number;
  time_min?: string | null;
  time_max?: string | null;
  device_detected?: string | null;
  device_key?: string | null;
  device_display?: string | null;
  firewall_display?: string | null;
  error_message?: string | null;
  error_type?: string | null;
  error_stage?: string | null;
};

/* ── Error hint by type (optional UX) ── */
function getErrorHint(errorType: string | null | undefined): string | null {
  if (!errorType) return null;
  const t = errorType.toLowerCase();
  if (t.includes('integrity')) return 'Database constraint issue. This may indicate duplicate flow or endpoint entries.';
  if (t.includes('operational')) return 'Database schema mismatch or missing unique index.';
  if (t.includes('valueerror') || t.includes('parse')) return 'Log format not recognized. Check if this is a valid InControl syslog export.';
  return null;
}

function ImportErrorBlock({
  jobStatus,
  onClose,
  onRefresh,
}: {
  jobStatus: JobStatus | null;
  onClose: () => void;
  onRefresh?: () => Promise<void>;
}) {
  const [copied, setCopied] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);
  const jobId = jobStatus?.job_id ?? null;
  const stage = jobStatus?.error_stage ?? 'processing';
  const errorType = jobStatus?.error_type ?? 'Error';
  const message = jobStatus?.error_message?.trim() || 'Import failed. No error details were recorded.';
  const hint = getErrorHint(jobStatus?.error_type);
  const isGeneric = (errorType === 'Error' && !(jobStatus?.error_message?.trim())) || !jobStatus?.error_type;
  const copyLines = [
    jobId ? `Job ID: ${jobId}` : null,
    `Stage: ${stage}`,
    `Error: ${errorType}`,
    `Message: ${message}`,
  ].filter(Boolean) as string[];
  if (isGeneric && jobId) {
    copyLines.push('', 'No detailed error was recorded. Check server logs for the full traceback (search for the job ID above).');
  } else {
    copyLines.push('', 'Check server logs for the full traceback.');
  }
  const copyText = copyLines.join('\n');

  const handleCopy = React.useCallback(() => {
    navigator.clipboard.writeText(copyText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [copyText]);

  const handleRefresh = React.useCallback(async () => {
    if (!onRefresh) return;
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  }, [onRefresh]);

  return (
    <div className="space-y-3 text-sm">
      <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 space-y-2">
        {jobId && (
          <div>
            <span className="text-muted-foreground">Job ID: </span>
            <span className="font-mono text-xs text-foreground break-all">{jobId}</span>
          </div>
        )}
        <div>
          <span className="text-muted-foreground">Stage: </span>
          <span className="font-medium text-foreground">{stage}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Error: </span>
          <span className="font-medium text-foreground">{errorType}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Message: </span>
          <span className="text-destructive break-words">{message}</span>
        </div>
      </div>
      {isGeneric && (
        <p className="text-xs text-muted-foreground bg-muted/50 rounded-md px-2 py-1.5">
          No detailed error was recorded. Click Refresh to fetch the latest status from the server, or check server logs (search for the job ID).
        </p>
      )}
      {hint && (
        <p className="text-xs text-muted-foreground bg-muted/50 rounded-md px-2 py-1.5">{hint}</p>
      )}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={handleCopy}
          className="flex items-center gap-2 h-8 px-3 rounded-md text-xs font-medium border border-border bg-background text-foreground hover:bg-muted/60"
        >
          <Copy className="w-3.5 h-3.5" />
          {copied ? 'Copied' : 'Copy error details'}
        </button>
        {jobId && onRefresh && (
          <button
            type="button"
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 h-8 px-3 rounded-md text-xs font-medium border border-border bg-background text-foreground hover:bg-muted/60 disabled:opacity-50"
          >
            {refreshing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Refresh
          </button>
        )}
      </div>
    </div>
  );
}

/* ── Upload status modal (phases: uploading → processing → done | error) ── */
function formatFileSize(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function UploadStatusModal({
  open: openModal,
  phase,
  uploadPct,
  fileSize,
  jobStatus,
  summary,
  pollReconnecting,
  onClose,
  onApplyToDashboard,
  onRefresh,
  refreshFirewalls,
  getDeviceGroups,
  onToast,
}: {
  open: boolean;
  phase: 'uploading' | 'upload_complete' | 'processing' | 'done' | 'error';
  uploadPct: number;
  fileSize?: number | null;
  jobStatus: JobStatus | null;
  summary: ImportSummary | null;
  pollReconnecting?: boolean;
  onClose: () => void;
  onApplyToDashboard?: (deviceId: string, deviceLabel: string, timeMin?: string, timeMax?: string) => void;
  onRefresh?: () => Promise<void>;
  refreshFirewalls?: () => Promise<void>;
  getDeviceGroups?: () => Array<{ id: string }>;
  onToast?: (msg: string) => void;
}) {
  if (!openModal) return null;
  const deviceDisplay = summary?.device_display ?? summary?.device_detected ?? jobStatus?.device_display ?? jobStatus?.device_detected ?? '—';
  const deviceKey = summary?.device_key ?? jobStatus?.device_key ?? summary?.device_detected ?? jobStatus?.device_detected ?? '';
  const timeRange =
    (summary ?? jobStatus)?.time_min != null && (summary ?? jobStatus)?.time_max != null
      ? `${formatImportTime((summary ?? jobStatus)!.time_min)} → ${formatImportTime((summary ?? jobStatus)!.time_max)}`
      : '—';
  const canApply = (summary ?? jobStatus) && (deviceKey || (summary ?? jobStatus)?.device_display) && onApplyToDashboard;

  const [applying, setApplying] = React.useState(false);
  const handleApplyToDashboardClick = React.useCallback(async () => {
    if (!onApplyToDashboard || !refreshFirewalls || !getDeviceGroups) {
      onApplyToDashboard?.(deviceKey.trim(), deviceDisplay, (summary ?? jobStatus)?.time_min ?? undefined, (summary ?? jobStatus)?.time_max ?? undefined);
      onClose();
      return;
    }
    const keyToUse = deviceKey?.trim() || (summary?.device_detected ?? jobStatus?.device_detected)?.trim();
    if (!keyToUse) {
      onToast?.('No firewall to apply.');
      return;
    }
    setApplying(true);
    try {
      await refreshFirewalls();
      const list = getDeviceGroups() ?? [];
      const exists = list.some((g: { id: string }) => g.id === keyToUse);
      const fallback = (summary?.device_detected ?? jobStatus?.device_detected)?.trim();
      const existsFallback = !!fallback && list.some((g: { id: string }) => g.id === fallback);
      const selectedKey = exists ? keyToUse : existsFallback ? fallback : null;
      if (!selectedKey) {
        onToast?.('Imported firewall not available yet. Please wait and try again.');
        return;
      }
      onApplyToDashboard(selectedKey, deviceDisplay, (summary ?? jobStatus)?.time_min ?? undefined, (summary ?? jobStatus)?.time_max ?? undefined);
      onClose();
    } finally {
      setApplying(false);
    }
  }, [deviceKey, deviceDisplay, summary, jobStatus, onApplyToDashboard, onClose, refreshFirewalls, getDeviceGroups, onToast]);

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" aria-hidden onClick={onClose} />
      <div
        className="relative w-full max-w-md rounded-xl border border-border bg-card shadow-xl p-6 flex flex-col gap-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="upload-status-title"
      >
        <div>
          <h2 id="upload-status-title" className="text-lg font-semibold text-foreground">
            {phase === 'uploading' && 'Uploading…'}
            {phase === 'upload_complete' && 'Upload complete'}
            {phase === 'processing' && 'Processing…'}
            {phase === 'done' && 'Import complete'}
            {phase === 'error' && 'Import failed'}
          </h2>
          <p className="text-sm text-muted-foreground mt-0.5">InControl syslog upload</p>
        </div>

        {phase === 'upload_complete' && (
          <div className="space-y-2 text-sm">
            <p className="text-foreground">Import has been queued for processing.</p>
            {summary?.filename && <p className="text-muted-foreground truncate">File: {summary.filename}</p>}
            {jobStatus?.job_id && <p className="text-muted-foreground font-mono text-xs break-all">Job: {jobStatus.job_id}</p>}
          </div>
        )}

        {phase === 'uploading' && (
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Upload progress</span>
              <span className="font-medium">{Math.round(uploadPct)}%</span>
            </div>
            {fileSize != null && (
              <p className="text-xs text-muted-foreground">File size: {formatFileSize(fileSize)}</p>
            )}
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full bg-primary transition-all duration-200"
                style={{ width: `${Math.min(100, Math.max(0, uploadPct))}%` }}
              />
            </div>
          </div>
        )}

        {(phase === 'processing' || phase === 'uploading') && jobStatus && (
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div>
                <span className="text-muted-foreground">Imported</span>
                <div className="font-medium text-foreground">{jobStatus.raw_logs_inserted ?? jobStatus.imported ?? 0}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Discarded</span>
                <div className="font-medium text-foreground">{jobStatus.discarded ?? (jobStatus.filtered_id ?? 0) + (jobStatus.parse_err ?? 0)}</div>
                <div className="text-xs text-muted-foreground">
                  Filtered: {jobStatus.filtered_id ?? 0} · Parse errors: {jobStatus.parse_err ?? 0}
                </div>
              </div>
            </div>
            {phase === 'processing' && (
              <>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Processed: {jobStatus.lines_processed ?? 0} lines</span>
                  {((jobStatus.lines_total ?? 0) > 0 || jobStatus.progress != null) && (
                    <span>
                      {jobStatus.lines_total != null && jobStatus.lines_total > 0
                        ? Math.round(((jobStatus.lines_processed ?? 0) / jobStatus.lines_total) * 100)
                        : jobStatus.progress != null
                          ? Math.round(jobStatus.progress * 100)
                          : 0}%
                    </span>
                  )}
                </div>
                <div className="h-2 rounded-full bg-muted overflow-hidden">
                  {(jobStatus.lines_total ?? 0) > 0 ? (
                    <div
                      className="h-full bg-primary transition-all duration-200"
                      style={{ width: `${Math.min(100, ((jobStatus.lines_processed ?? 0) / jobStatus.lines_total!) * 100)}%` }}
                    />
                  ) : jobStatus.progress != null ? (
                    <div
                      className="h-full bg-primary transition-all duration-200"
                      style={{ width: `${Math.min(100, jobStatus.progress * 100)}%` }}
                    />
                  ) : (
                    <div className="h-full w-1/3 bg-primary animate-pulse rounded-full" style={{ animationDirection: 'alternate' }} />
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {(phase === 'processing' || phase === 'uploading') && pollReconnecting && (
          <p className="text-xs text-amber-600 dark:text-amber-400 bg-amber-500/10 rounded-md px-2 py-1.5">
            Still importing… reconnecting.
          </p>
        )}
        {phase === 'error' && (
          <>
            {jobStatus?.error_message && (
              <p className="text-xs text-muted-foreground bg-muted/50 rounded-md px-2 py-1.5">
                Upload succeeded but processing failed. See details below.
              </p>
            )}
            <ImportErrorBlock jobStatus={jobStatus} onClose={onClose} onRefresh={onRefresh} />
          </>
        )}

        {(phase === 'done' && (summary || jobStatus)) && (
          <div className="grid gap-3 text-sm">
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-0.5">Firewall</div>
              <div className="text-foreground font-medium">{deviceDisplay}</div>
            </div>
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-0.5">Processed</div>
              <div className="text-foreground">{(summary ?? jobStatus)?.lines_total ?? jobStatus?.lines_processed ?? 0} logs</div>
            </div>
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-0.5">Added to database</div>
              <div className="text-foreground">
                {(summary ?? jobStatus)?.raw_logs_inserted ?? 0} raw logs, {(summary ?? jobStatus)?.events_inserted ?? 0} events
              </div>
            </div>
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-0.5">Time range</div>
              <div className="text-foreground">{timeRange}</div>
            </div>
          </div>
        )}

        <div className="flex flex-wrap gap-2 justify-end pt-2">
          {phase === 'done' && canApply && (
            <button
              type="button"
              onClick={handleApplyToDashboardClick}
              disabled={applying}
              className="h-9 px-4 rounded-lg text-sm font-medium bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-60 flex items-center gap-2"
            >
              {applying ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              Apply to dashboard
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            className="h-9 px-4 rounded-lg text-sm font-medium border border-border bg-background text-foreground hover:bg-muted/60"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Import queue badge + popover ── */
type IngestJobRow = {
  job_id: string;
  status: string;
  phase?: string;
  progress?: number;
  filename?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  error_message?: string | null;
};
function ImportQueueBadgeAndPopover({
  onOpenUploadModal,
  onToast,
}: {
  onOpenUploadModal: () => void;
  onToast?: (msg: string) => void;
}) {
  const [popoverOpen, setPopoverOpen] = useState(false);
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['ingest-jobs', popoverOpen],
    queryFn: async () => {
      const res = await fetch(`${API}/ingest/jobs?state=queued,running,done,error,canceled&limit=50`);
      if (!res.ok) throw new Error('Failed to load jobs');
      const json = await res.json();
      return (json?.jobs ?? []) as IngestJobRow[];
    },
    refetchInterval: popoverOpen ? 2000 : 8000,
    enabled: true,
  });
  const jobs = data ?? [];
  const activeCount = jobs.filter((j) => j.status === 'queued' || j.status === 'running').length;

  const handleCancel = React.useCallback(
    async (jobId: string) => {
      try {
        const res = await fetch(`${API}/ingest/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          onToast?.(data?.detail ?? res.statusText ?? 'Cancel failed');
          return;
        }
        refetch();
      } catch {
        onToast?.('Request failed');
      }
    },
    [refetch, onToast]
  );

  const handleDelete = React.useCallback(
    async (jobId: string) => {
      try {
        const res = await fetch(`${API}/ingest/jobs/${encodeURIComponent(jobId)}`, { method: 'DELETE' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          onToast?.(data?.detail ?? res.statusText ?? 'Delete failed');
          return;
        }
        refetch();
      } catch {
        onToast?.('Request failed');
      }
    },
    [refetch, onToast]
  );

  const sorted = React.useMemo(() => {
    const order = (a: IngestJobRow, b: IngestJobRow) => {
      const rank = (s: string) => (s === 'running' ? 0 : s === 'queued' ? 1 : 2);
      return rank(a.status) - rank(b.status);
    };
    return [...jobs].sort(order);
  }, [jobs]);

  return (
    <div className="relative flex items-center">
      {activeCount > 0 && (
        <button
          type="button"
          onClick={() => setPopoverOpen((o) => !o)}
          className="h-8 min-w-[28px] px-1.5 rounded-md text-xs font-medium border border-border bg-muted/60 text-foreground hover:bg-muted transition-colors flex items-center justify-center"
          title="Import queue"
        >
          {activeCount}
        </button>
      )}
      {popoverOpen && (
        <>
          <div className="fixed inset-0 z-40" aria-hidden onClick={() => setPopoverOpen(false)} />
          <div className="absolute right-0 top-full mt-1 z-50 w-[360px] max-h-[320px] overflow-auto rounded-lg border border-border bg-card shadow-xl p-2">
            <div className="flex items-center justify-between mb-2 px-1">
              <span className="text-sm font-medium text-foreground">Import queue</span>
              <button type="button" onClick={() => setPopoverOpen(false)} className="p-1 rounded hover:bg-muted">
                <X className="w-4 h-4" />
              </button>
            </div>
            {isLoading && jobs.length === 0 ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
                <Loader2 className="w-4 h-4 animate-spin" /> Loading…
              </div>
            ) : sorted.length === 0 ? (
              <p className="text-sm text-muted-foreground py-4">No import jobs.</p>
            ) : (
              <ul className="space-y-1">
                {sorted.map((j) => (
                  <li
                    key={j.job_id}
                    className="flex flex-col gap-1 rounded-md border border-border bg-muted/30 p-2 text-sm"
                  >
                    <div className="flex justify-between items-start gap-2">
                      <span className="font-medium text-foreground truncate flex-1" title={j.filename ?? j.job_id}>
                        {j.filename ?? j.job_id}
                      </span>
                      <span className="text-xs text-muted-foreground shrink-0">{j.status}</span>
                    </div>
                    {j.created_at && (
                      <div className="text-xs text-muted-foreground">
                        {new Date(j.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </div>
                    )}
                    {(j.status === 'running' && j.progress != null) && (
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                          <div className="h-full bg-primary" style={{ width: `${Math.round((j.progress ?? 0) * 100)}%` }} />
                        </div>
                        <span className="text-xs">{Math.round((j.progress ?? 0) * 100)}%</span>
                      </div>
                    )}
                    <div className="flex gap-1 mt-1">
                      {(j.status === 'queued' || j.status === 'running') && (
                        <button
                          type="button"
                          onClick={() => handleCancel(j.job_id)}
                          className="h-6 px-2 rounded text-xs font-medium border border-border bg-background hover:bg-muted"
                        >
                          Cancel
                        </button>
                      )}
                      {['done', 'error', 'canceled'].includes(j.status) && (
                        <button
                          type="button"
                          onClick={() => handleDelete(j.job_id)}
                          className="h-6 px-2 rounded text-xs font-medium border border-destructive/50 text-destructive hover:bg-destructive/10"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/* ── Upload syslog button (header) ── */
function UploadSyslogButton({
  onToast,
  onUploadStart,
  onUploadProgress,
  onUploadJobCreated,
  onUploadError,
  device,
  isUploading,
}: {
  onToast?: (msg: string) => void;
  onUploadStart?: (fileSize?: number) => void;
  onUploadProgress?: (pct: number) => void;
  onUploadJobCreated?: (jobId: string, filename?: string | null, sizeBytes?: number) => void;
  onUploadError?: (message: string) => void;
  device?: string;
  isUploading?: boolean;
}) {
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const MAX_UPLOAD_BYTES = 1024 * 1024 * 1024; // 1 GB
  const handleFileSelect = React.useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const f = e.target.files?.[0];
      e.target.value = '';
      if (!f) return;
      if (f.size > MAX_UPLOAD_BYTES) {
        onToast?.('File too large (max 1 GB)');
        return;
      }
      onUploadStart?.(f.size);
      const form = new FormData();
      form.append('file', f);
      if (device) form.append('device', device);
      const xhr = new XMLHttpRequest();
      xhr.upload.addEventListener('progress', (ev) => {
        if (ev.lengthComputable && ev.total > 0) {
          onUploadProgress?.(Math.round((ev.loaded / ev.total) * 100));
        }
      });
      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const data = JSON.parse(xhr.responseText || '{}');
            if (data?.ok === true && data?.job_id) {
              onUploadJobCreated?.(data.job_id, data?.filename ?? null, data?.size_bytes);
            } else {
              onUploadError?.('Invalid response');
            }
          } catch {
            onUploadError?.('Invalid response');
          }
        } else {
          try {
            const data = JSON.parse(xhr.responseText || '{}');
            const msg = data?.detail ?? xhr.statusText ?? 'Upload failed';
            onUploadError?.(typeof msg === 'string' ? msg : JSON.stringify(msg));
          } catch {
            onUploadError?.(xhr.statusText || 'Upload failed');
          }
        }
      });
      xhr.addEventListener('error', () => onUploadError?.('Network error'));
      xhr.addEventListener('abort', () => onUploadError?.('Upload cancelled'));
      xhr.open('POST', `${API}/ingest/upload`);
      xhr.send(form);
    },
    [device, onToast, onUploadStart, onUploadProgress, onUploadJobCreated, onUploadError]
  );
  return (
    <>
      <input
        ref={fileInputRef}
        type="file"
        accept=".log,.txt,.gz,text/plain,application/gzip"
        className="hidden"
        onChange={handleFileSelect}
      />
      <button
        type="button"
        onClick={() => fileInputRef.current?.click()}
        disabled={!!isUploading}
        title="Upload a syslog file to ingest (e.g. exported from InControl)"
        className={cn(
          'h-8 px-3 rounded-md text-sm font-medium border border-border bg-background text-foreground hover:bg-muted/60 transition-colors flex items-center gap-2 flex-shrink-0 focus:outline-none focus:ring-2 focus:ring-ring',
          isUploading && 'opacity-60 cursor-not-allowed',
        )}
      >
        {isUploading ? <Loader2 className="w-4 h-4 flex-shrink-0 animate-spin" /> : <Upload className="w-4 h-4 flex-shrink-0" />}
        <span className="hidden md:inline">Upload from InControl</span>
      </button>
    </>
  );
}

/* ── App Shell ── */
function App() {
  const [page, setPage] = useState<'dashboard' | 'endpoints' | 'firewalls' | 'settings'>('dashboard');
  const [appToast, setAppToast] = useState<string | null>(null);
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [uploadPhase, setUploadPhase] = useState<'uploading' | 'upload_complete' | 'processing' | 'done' | 'error'>('error'); // 'error' = idle
  const [uploadPct, setUploadPct] = useState(0);
  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null);
  const [uploadSummary, setUploadSummary] = useState<ImportSummary | null>(null);
  const [uploadFileSize, setUploadFileSize] = useState<number | null>(null);
  const [pendingAnalyzeDeviceId, setPendingAnalyzeDeviceId] = useState<string | null>(null);
  const [pendingTimeRange, setPendingTimeRange] = useState<{ timeMin: string; timeMax: string } | null>(null);

  // Reset upload state on mount so we never start with a stuck "spinning" state (e.g. after backend restart or HMR).
  React.useEffect(() => {
    setUploadModalOpen(false);
    setUploadPhase('error');
    setJobId(null);
    setJobStatus(null);
    setUploadSummary(null);
    setUploadPct(0);
    setUploadFileSize(null);
  }, []);

  const isUploading = uploadPhase === 'uploading';

  const handleUploadStart = React.useCallback((fileSize?: number) => {
    setUploadModalOpen(true);
    setUploadPhase('uploading');
    setUploadPct(0);
    setUploadFileSize(fileSize ?? null);
    setJobId(null);
    setJobStatus(null);
    setUploadSummary(null);
  }, []);

  const handleUploadProgress = React.useCallback((pct: number) => {
    setUploadPct(pct);
  }, []);

  const handleUploadJobCreated = React.useCallback((id: string, filename?: string | null, _sizeBytes?: number) => {
    setJobId(id);
    setJobStatus({ job_id: id, status: 'queued', filename: filename ?? undefined } as JobStatus);
    setUploadSummary(filename ? { ok: true, filename } as ImportSummary : null);
    setUploadPhase('upload_complete');
    setUploadPct(100);
  }, []);

  const handleUploadError = React.useCallback((message: string) => {
    setUploadPhase('error');
    setJobStatus({ status: 'error', error_message: message, job_id: '' } as JobStatus);
  }, []);

  const [pollReconnecting, setPollReconnecting] = React.useState(false);
  // No polling in upload modal: import runs in background; user sees status via queue popover or firewall details.

  const handleUploadModalClose = React.useCallback(() => {
    setUploadModalOpen(false);
    // Do not reset job state: import continues in background; user can reopen via "Import status"
  }, []);

  const handleApplyToDashboard = React.useCallback((deviceId: string, _label: string, timeMin?: string, timeMax?: string) => {
    if (deviceId?.trim()) setPendingAnalyzeDeviceId(deviceId.trim());
    if (timeMin && timeMax) setPendingTimeRange({ timeMin, timeMax });
    setPage('dashboard');
  }, []);

  const handleRefreshImportStatus = React.useCallback(async () => {
    const id = jobStatus?.job_id ?? jobId;
    if (!id) return;
    try {
      const res = await fetch(`${API}/ingest/upload/status?job_id=${encodeURIComponent(id)}`);
      if (!res.ok) return;
      const data: JobStatus = await res.json();
      setJobStatus(data);
    } catch (_) {}
  }, [jobStatus?.job_id, jobId]);

  return (
    <QueryClientProvider client={queryClient}>
      <div className="min-h-screen bg-background">
        {/* Top App Bar */}
        <nav className="sticky top-0 z-50 h-14 px-4 flex items-center justify-between border-b border-border bg-background/80 backdrop-blur-md">
          <div className="flex items-center gap-4">
            <h1
              className="text-base font-semibold text-foreground tracking-tight cursor-pointer hover:opacity-80 transition-opacity"
              onClick={() => setPage('dashboard')}
            >
              NetWall Flow Analyzer
            </h1>
            <div className="hidden sm:flex items-center gap-1 ml-2">
              {([
                { id: 'dashboard', label: 'Dashboard' },
                { id: 'endpoints', label: 'Device Inventory' },
                { id: 'firewalls', label: 'Firewall Inventory' },
              ] as const).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setPage(tab.id)}
                  className={cn(
                    'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
                    page === tab.id
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted/60',
                  )}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ImportQueueBadgeAndPopover
              onOpenUploadModal={() => setUploadModalOpen(true)}
              onToast={(msg) => { setAppToast(msg); setTimeout(() => setAppToast(null), 4000); }}
            />
            <UploadSyslogButton
              onToast={(msg) => {
                setAppToast(msg);
                setTimeout(() => setAppToast(null), 4000);
              }}
              onUploadStart={handleUploadStart}
              onUploadProgress={handleUploadProgress}
              onUploadJobCreated={handleUploadJobCreated}
              onUploadError={handleUploadError}
              isUploading={isUploading}
            />
            <HeaderStatsStrip />
            <button
              type="button"
              onClick={() => setPage(page === 'settings' ? 'dashboard' : 'settings')}
              className={cn(
                'p-1.5 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-ring',
                page === 'settings'
                  ? 'text-primary bg-primary/10'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted/60',
              )}
              title="Settings"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </nav>
        {page === 'dashboard' && (
          <DashboardPage
            initialDeviceId={pendingAnalyzeDeviceId}
            onConsumeInitialDevice={() => setPendingAnalyzeDeviceId(null)}
            initialTimeRange={pendingTimeRange}
            onConsumeInitialTimeRange={() => setPendingTimeRange(null)}
          />
        )}
        {page === 'endpoints' && <EndpointsPage />}
        {page === 'firewalls' && (
          <FirewallInventoryPage
            onOpenImportStatus={(jobId) => {
              setJobId(jobId);
              setUploadPhase('processing');
              setUploadModalOpen(true);
              setJobStatus(null);
            }}
          />
        )}
        {page === 'settings' && <SettingsPage onBack={() => setPage('dashboard')} />}
        <UploadStatusModal
          open={uploadModalOpen}
          phase={uploadPhase}
          uploadPct={uploadPct}
          fileSize={uploadFileSize}
          jobStatus={jobStatus}
          summary={uploadSummary}
          pollReconnecting={pollReconnecting}
          onClose={handleUploadModalClose}
          onApplyToDashboard={handleApplyToDashboard}
          onRefresh={handleRefreshImportStatus}
          refreshFirewalls={async () => {
            await queryClient.invalidateQueries({ queryKey: ['devices/groups'] });
            await queryClient.refetchQueries({ queryKey: ['devices/groups'] });
          }}
          getDeviceGroups={() => (queryClient.getQueryData(['devices/groups']) as Array<{ id: string }>) ?? []}
          onToast={(msg) => { setAppToast(msg); setTimeout(() => setAppToast(null), 4000); }}
        />
        {appToast && (
          <div className="fixed bottom-4 right-4 z-[101] px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium shadow-lg">
            {appToast}
          </div>
        )}
      </div>
    </QueryClientProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
