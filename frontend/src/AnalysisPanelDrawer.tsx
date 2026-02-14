import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  SlidersHorizontal,
  ChevronDown,
  Loader2,
  Router,
  Pencil,
} from 'lucide-react';

type FilterKind = 'zone' | 'interface' | 'endpoint' | 'any';

function cn(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(' ');
}

function FieldLabel({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

const StyledSelect = React.forwardRef<
  HTMLSelectElement,
  {
    value: string;
    onChange: (v: string) => void;
    disabled?: boolean;
    children: React.ReactNode;
    className?: string;
  }
>(function StyledSelect({ value, onChange, disabled, children, className }, ref) {
  return (
    <select
      ref={ref}
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
});

export type AnalysisPanelDrawerProps = {
  device: string;
  setDevice: (v: string) => void;
  deviceLabel: string;
  deviceGroups: { id: string; label: string }[];
  srcKind: FilterKind;
  setSrcKind: (v: FilterKind) => void;
  srcValue: string;
  setSrcValue: (v: string) => void;
  handleSrcKindChange: (v: FilterKind) => void;
  destView: 'endpoints' | 'services';
  setDestView: (v: 'endpoints' | 'services') => void;
  dstKind: FilterKind;
  setDstKind: (v: FilterKind) => void;
  dstValue: string;
  setDstValue: (v: string) => void;
  handleDstKindChange: (v: FilterKind) => void;
  timeFrom: string;
  setTimeFrom: (v: string) => void;
  timeTo: string;
  setTimeTo: (v: string) => void;
  view: 'original' | 'translated';
  setView: (v: 'original' | 'translated') => void;
  onAnalyze: () => Promise<void>;
  isAnalyzing: boolean;
  analyzeError: string | null;
  hasDeviceSelected: boolean;
  hasDeviceAndTime: boolean;
  canAnalyze: boolean;
  srcOptions: string[] | { id: number; label: string; device_name?: string; ip: string }[];
  dstOptions: string[] | { id: number; label: string; device_name?: string; ip: string }[];
  endpointList: { id: number; label: string; device_name?: string; ip: string }[];
  showInventory: boolean;
  setShowInventory: (v: boolean | ((prev: boolean) => boolean)) => void;
  routerMacCount: number;
};

function getSummary(p: AnalysisPanelDrawerProps): string {
  const parts: string[] = [];
  parts.push(p.deviceLabel || '—');
  const srcLabel =
    p.srcKind === 'zone'
      ? `Zone: ${p.srcValue || '—'}`
      : p.srcKind === 'interface'
        ? `IF: ${p.srcValue || '—'}`
        : p.srcKind === 'endpoint'
          ? `Device: ${p.srcValue ? '…' : '—'}`
          : '—';
  parts.push(srcLabel);
  parts.push('→');
  parts.push(p.destView === 'services' ? 'Services' : 'Endpoints');
  if (p.timeFrom && p.timeTo) {
    const from = p.timeFrom.replace('T', ' ');
    const to = p.timeTo.replace('T', ' ');
    const today = new Date().toISOString().slice(0, 10);
    const fromDate = p.timeFrom.slice(0, 10);
    const toDate = p.timeTo.slice(0, 10);
    if (fromDate === today && toDate === today) {
      parts.push('Today');
    } else {
      parts.push(`${from.slice(0, 16)} – ${to.slice(0, 16)}`);
    }
  } else {
    parts.push('—');
  }
  parts.push(p.view === 'translated' ? 'Translated' : 'Original');
  return parts.join(' | ');
}

export function AnalysisPanelDrawer(props: AnalysisPanelDrawerProps) {
  const [open, setOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const firstInputRef = useRef<HTMLSelectElement>(null);

  const hasDeviceSelected = props.hasDeviceSelected;

  useEffect(() => {
    if (!hasDeviceSelected) setOpen(true);
  }, [hasDeviceSelected]);

  const handleAnalyze = useCallback(async () => {
    if (!props.canAnalyze || props.isAnalyzing) return;
    try {
      await props.onAnalyze();
      setOpen(false);
    } catch (_) {
      // Error state already set by parent
    }
  }, [props.onAnalyze, props.canAnalyze, props.isAnalyzing]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open && hasDeviceSelected) {
        e.preventDefault();
        setOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, hasDeviceSelected]);

  useEffect(() => {
    if (open) {
      const t = setTimeout(() => {
        if (firstInputRef.current) {
          firstInputRef.current.focus();
        } else {
          const firstFocusable = panelRef.current?.querySelector<HTMLSelectElement>(
            'select:not([disabled])'
          );
          firstFocusable?.focus();
        }
      }, 50);
      return () => clearTimeout(t);
    }
  }, [open]);

  const summary = getSummary(props);
  const canCollapse = hasDeviceSelected;

  return (
    <div className="flex flex-col">
      {/* Collapsed: summary bar */}
      {!open && (
        <div
          className={cn(
            'flex items-center justify-between gap-3 px-4 h-14 shrink-0',
            'rounded-2xl border border-border bg-card shadow-sm',
            'mx-3 mt-3 mb-0',
          )}
        >
          <div className="flex items-center gap-2 min-w-0 flex-1">
            <SlidersHorizontal className="w-4 h-4 text-muted-foreground flex-shrink-0" />
            <span className="text-sm text-muted-foreground truncate" title={summary}>
              {summary}
            </span>
          </div>
          <button
            type="button"
            onClick={() => canCollapse && setOpen(true)}
            disabled={!canCollapse}
            className={cn(
              'flex items-center gap-1.5 h-9 px-3 rounded-lg text-sm font-medium border transition-colors',
              canCollapse
                ? 'border-border bg-card text-foreground hover:bg-muted/60'
                : 'border-transparent text-muted-foreground cursor-default',
            )}
          >
            <Pencil className="w-3.5 h-3.5" />
            Edit
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Expanded: full configuration panel */}
      {open && (
        <div
          ref={panelRef}
          className="mx-3 mt-3 mb-0 rounded-2xl border border-border bg-card p-4 shadow-sm"
        >
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6">
            {/* Row 1: Source Firewall */}
            <div className="lg:col-span-2">
              <FieldLabel label="Source firewall">
                <StyledSelect
                  ref={firstInputRef}
                  value={props.device}
                  onChange={(v) => props.setDevice(v)}
                  className="w-full max-w-sm"
                >
                  <option value="">Select firewall</option>
                  {props.deviceGroups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.label}
                    </option>
                  ))}
                </StyledSelect>
              </FieldLabel>
            </div>

            {/* Row 2: Source + Destination view + Dest (when Endpoints) */}
            <div className="flex flex-wrap items-end gap-4">
              <FieldLabel label="Source type">
                <StyledSelect
                  value={props.srcKind}
                  onChange={(v) => props.handleSrcKindChange(v as FilterKind)}
                  disabled={!hasDeviceSelected}
                >
                  <option value="zone">Zone</option>
                  <option value="interface">Interface</option>
                  <option value="endpoint" disabled={!props.hasDeviceAndTime}>
                    Device
                  </option>
                </StyledSelect>
              </FieldLabel>
              <FieldLabel label="Source">
                <StyledSelect
                  value={props.srcValue}
                  onChange={props.setSrcValue}
                  disabled={
                    !hasDeviceSelected ||
                    (props.srcKind === 'endpoint' && !props.hasDeviceAndTime)
                  }
                  className="min-w-[120px]"
                >
                  <option value="">Select</option>
                  {props.srcKind === 'endpoint' &&
                  props.endpointList.length === 0 &&
                  props.hasDeviceAndTime ? (
                    <option value="" disabled>
                      No devices with MAC
                    </option>
                  ) : props.srcKind === 'endpoint' ? (
                    (props.srcOptions as { id: number; label: string; device_name?: string; ip: string }[]).map(
                      (e) => {
                        const name = (e.device_name ?? e.label ?? '').toString().trim();
                        const displayLabel = name ? `${name} (${e.ip})` : e.ip ?? '';
                        return (
                          <option key={e.id} value={String(e.id)}>
                            {displayLabel}
                          </option>
                        );
                      }
                    )
                  ) : (
                    (props.srcOptions as string[]).map((o: string) => (
                      <option key={o} value={o}>
                        {o}
                      </option>
                    ))
                  )}
                </StyledSelect>
              </FieldLabel>
            </div>

            <div className="flex flex-wrap items-end gap-4">
              <FieldLabel label="Destination view">
                <StyledSelect
                  value={props.destView}
                  onChange={(v) => props.setDestView(v as 'endpoints' | 'services')}
                  disabled={!hasDeviceSelected}
                >
                  <option value="endpoints">Endpoints</option>
                  <option value="services">Services</option>
                </StyledSelect>
              </FieldLabel>
              <FieldLabel label="Dest type">
                <StyledSelect
                  value={props.dstKind}
                  onChange={(v) => props.handleDstKindChange(v as FilterKind)}
                  disabled={!hasDeviceSelected}
                >
                  <option value="any">Any</option>
                  <option value="zone">Zone</option>
                  <option value="interface">Interface</option>
                  <option value="endpoint" disabled={!props.hasDeviceAndTime}>
                    Device
                  </option>
                </StyledSelect>
              </FieldLabel>
              <FieldLabel label="Destination">
                <StyledSelect
                  value={props.dstKind === 'any' ? '' : props.dstValue}
                  onChange={props.setDstValue}
                  disabled={
                    !hasDeviceSelected ||
                    props.dstKind === 'any' ||
                    (props.dstKind === 'endpoint' && !props.hasDeviceAndTime)
                  }
                  className="min-w-[120px]"
                >
                  {props.dstKind === 'any' ? (
                    <option value="">All destinations</option>
                  ) : (
                    <>
                      <option value="">Select</option>
                      {props.dstKind === 'endpoint' &&
                      props.endpointList.length === 0 &&
                      props.hasDeviceAndTime ? (
                        <option value="" disabled>
                          No devices with MAC
                        </option>
                      ) : props.dstKind === 'endpoint' ? (
                        (
                          props.dstOptions as {
                            id: number;
                            label: string;
                            device_name?: string;
                            ip: string;
                          }[]
                        ).map((e) => {
                          const name = (e.device_name ?? e.label ?? '').toString().trim();
                          const displayLabel = name ? `${name} (${e.ip})` : e.ip ?? '';
                          return (
                            <option key={e.id} value={String(e.id)}>
                              {displayLabel}
                            </option>
                          );
                        })
                      ) : (
                        (props.dstOptions as string[]).map((o: string) => (
                          <option key={o} value={o}>
                            {o}
                          </option>
                        ))
                      )}
                    </>
                  )}
                </StyledSelect>
              </FieldLabel>
            </div>

            {/* Row 3: Time + View */}
            <div className="flex flex-wrap items-end gap-4 lg:col-span-2">
              <FieldLabel label="From">
                <input
                  type="datetime-local"
                  value={props.timeFrom}
                  onChange={(e) => props.setTimeFrom(e.target.value)}
                  className="h-9 rounded-lg border border-border bg-input px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring/50 focus:border-ring"
                />
              </FieldLabel>
              <FieldLabel label="To">
                <input
                  type="datetime-local"
                  value={props.timeTo}
                  onChange={(e) => props.setTimeTo(e.target.value)}
                  className="h-9 rounded-lg border border-border bg-input px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring/50 focus:border-ring"
                />
              </FieldLabel>
              <FieldLabel label="View">
                <StyledSelect
                  value={props.view}
                  onChange={(v) => props.setView(v as 'original' | 'translated')}
                >
                  <option value="original">Original</option>
                  <option value="translated">Translated</option>
                </StyledSelect>
              </FieldLabel>
            </div>

            {/* Row 4: Actions + error */}
            <div className="flex flex-wrap items-center gap-3 lg:col-span-2 pt-1">
              <button
                type="button"
                onClick={handleAnalyze}
                disabled={!hasDeviceSelected || props.isAnalyzing}
                className={cn(
                  'h-9 px-5 rounded-lg text-sm font-semibold transition-all duration-150 flex items-center gap-2',
                  hasDeviceSelected && !props.isAnalyzing && props.canAnalyze
                    ? 'bg-primary text-primary-foreground hover:opacity-90 active:scale-[0.98] shadow-sm'
                    : 'bg-muted text-muted-foreground cursor-not-allowed',
                )}
              >
                {props.isAnalyzing && <Loader2 className="w-4 h-4 animate-spin" />}
                {props.isAnalyzing ? 'Analyzing…' : 'Analyze'}
              </button>
              {canCollapse && (
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="h-9 px-3 rounded-lg text-sm font-medium border border-border bg-card text-foreground hover:bg-muted/60 transition-colors"
                >
                  Collapse
                </button>
              )}
              <button
                type="button"
                onClick={() => props.setShowInventory((v) => !v)}
                disabled={!hasDeviceSelected}
                className={cn(
                  'h-9 px-3 rounded-lg text-sm font-medium transition-all duration-150 flex items-center gap-1.5 border',
                  props.showInventory
                    ? 'border-primary/50 bg-primary/10 text-primary'
                    : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-muted-foreground/40',
                  !hasDeviceSelected && 'opacity-50 cursor-not-allowed',
                )}
                title="Device Inventory — detect and manage router MACs"
              >
                <Router className="w-4 h-4" />
                MACs
                {props.routerMacCount > 0 && (
                  <span className="inline-flex items-center justify-center rounded-full bg-primary/15 text-primary text-[10px] font-semibold px-1.5 py-0.5 min-w-[18px]">
                    {props.routerMacCount}
                  </span>
                )}
              </button>
              {props.analyzeError && (
                <span className="text-sm text-destructive">
                  Failed to analyze: {props.analyzeError}
                </span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
