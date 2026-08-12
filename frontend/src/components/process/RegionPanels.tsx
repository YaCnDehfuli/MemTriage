import { useState } from "react";
import type { ExtractedString, PatternHit, RegionAnalysis } from "../../types";
import { bytes } from "../../lib/format";
import { Chip } from "../primitives";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-risk-critical ring-risk-critical/30 bg-risk-critical/10",
  high: "text-risk-high ring-risk-high/30 bg-risk-high/10",
  medium: "text-risk-medium ring-risk-medium/30 bg-risk-medium/10",
  low: "text-risk-low ring-risk-low/30 bg-risk-low/10",
  info: "text-mist-400 ring-ink-600 bg-ink-800/40",
};

const CATEGORY_TONE: Record<string, "accent" | "default" | "mono"> = {
  url: "accent",
  ipv4: "accent",
  domain: "accent",
  command: "accent",
  registry: "accent",
  "unc-path": "accent",
  base64: "accent",
};

/** Windowed entropy as a sparkline: a packed span inside a region shows up here first. */
function EntropySparkline({ windows, peak }: { windows: number[]; peak: number }) {
  if (!windows.length) return null;
  const width = 640;
  const height = 72;
  const step = width / Math.max(windows.length - 1, 1);
  const points = windows
    .map((v, i) => `${(i * step).toFixed(1)},${(height - (v / 8) * height).toFixed(1)}`)
    .join(" ");
  const threshold = height - (7.2 / 8) * height;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-20 w-full" role="img"
         aria-label={`Entropy profile, peak ${peak}`}>
      <line x1="0" y1={threshold} x2={width} y2={threshold}
            stroke="#f2994a" strokeWidth="1" strokeDasharray="4 4" opacity="0.6" />
      <polyline points={points} fill="none" stroke="#38c6d9" strokeWidth="1.5" />
    </svg>
  );
}

export function Structure({ analysis }: { analysis: RegionAnalysis }) {
  const s = analysis.structure;
  const pe = s.pe;
  if (s.error) {
    return (
      <p className="text-[13px] text-mist-400">
        Structural analysis failed for this region ({s.error}).
      </p>
    );
  }
  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-4">
        <Stat label="Size" value={bytes(s.size)} />
        <Stat label="Entropy" value={s.entropy.overall.toFixed(2)} />
        <Stat label="Peak entropy" value={`${s.entropy.peak.toFixed(2)} @ ${s.entropy.peak_offset_hex}`} />
        <Stat label="Printable" value={`${(s.printable_ratio * 100).toFixed(0)}%`} />
      </div>

      <div>
        <div className="eyebrow mb-1">Entropy profile</div>
        <EntropySparkline windows={s.entropy.windows} peak={s.entropy.peak} />
        <p className="text-[11px] text-mist-400">
          {s.entropy.window_bytes} bytes per window. The dashed line is 7.2 — above it,
          contents look packed, compressed or encrypted rather than plain code.
        </p>
      </div>

      <div>
        <div className="eyebrow mb-2">Byte distribution</div>
        <div className="flex h-16 items-end gap-0.5">
          {s.histogram.map((count, i) => {
            const max = Math.max(...s.histogram, 1);
            return (
              <div
                key={i}
                className="flex-1 rounded-sm bg-accent/50"
                style={{ height: `${Math.max(2, (count / max) * 100)}%` }}
                title={`0x${(i * 8).toString(16)}–0x${(i * 8 + 7).toString(16)}: ${count}`}
              />
            );
          })}
        </div>
      </div>

      <div>
        <div className="eyebrow mb-2">PE image</div>
        {pe.present ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-1.5">
              <Chip tone="accent">{pe.machine}</Chip>
              <Chip tone="mono">{pe.is_dll ? "DLL" : "EXE"}</Chip>
              <Chip tone="mono">entry {pe.entry_point}</Chip>
              <Chip tone="mono">base {pe.image_base}</Chip>
              {pe.subsystem && <Chip tone="mono">{pe.subsystem}</Chip>}
              {pe.characteristics.map((c) => <Chip key={c} tone="mono">{c}</Chip>)}
            </div>
            {pe.sections.length > 0 && (
              <table className="w-full font-mono text-[11px]">
                <thead>
                  <tr className="border-b border-ink-700/60 text-left text-mist-400">
                    <th className="py-1 pr-3">Section</th>
                    <th className="py-1 pr-3">RVA</th>
                    <th className="py-1 pr-3">Virtual</th>
                    <th className="py-1 pr-3">Raw</th>
                    <th className="py-1">Entropy</th>
                  </tr>
                </thead>
                <tbody>
                  {pe.sections.map((sec) => (
                    <tr key={sec.name + sec.virtual_address} className="border-b border-ink-800/50">
                      <td className="py-1 pr-3 text-mist-200">{sec.name}</td>
                      <td className="py-1 pr-3 text-mist-400">{sec.virtual_address}</td>
                      <td className="py-1 pr-3 text-mist-400">{sec.virtual_size}</td>
                      <td className="py-1 pr-3 text-mist-400">{sec.raw_size}</td>
                      <td className={`py-1 ${sec.entropy > 7.2 ? "text-risk-medium" : "text-mist-400"}`}>
                        {sec.entropy.toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {pe.imported_dlls.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {pe.imported_dlls.map((dll) => <Chip key={dll} tone="mono">{dll}</Chip>)}
              </div>
            )}
            {pe.parser === "builtin" && (
              <p className="text-[11px] text-mist-400">{pe.reason}</p>
            )}
          </div>
        ) : (
          <p className="text-[12px] text-mist-400">{pe.reason}</p>
        )}
      </div>
    </div>
  );
}

export function HexDump({ analysis }: { analysis: RegionAnalysis }) {
  const rows = analysis.structure.hexdump ?? [];
  if (!rows.length) {
    return <p className="text-[13px] text-mist-400">No bytes to show for this region.</p>;
  }
  return (
    <div className="space-y-2">
      <p className="text-[12px] text-mist-400">
        First {rows.length * 16} bytes. Region contents are shown as a dump only — MemTriage
        never serves the raw bytes for download.
      </p>
      <div className="max-h-[520px] overflow-auto rounded-md border border-ink-700/60">
        <table className="w-full font-mono text-[11px]">
          <tbody>
            {rows.map((row) => (
              <tr key={row.offset} className="border-b border-ink-800/50 last:border-0">
                <td className="whitespace-nowrap px-3 py-0.5 text-mist-400">{row.address}</td>
                <td className="whitespace-nowrap px-3 py-0.5 text-mist-200">
                  {(row.bytes.match(/../g) ?? []).join(" ")}
                </td>
                <td className="whitespace-pre px-3 py-0.5 text-mist-400">{row.ascii}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function Strings({ analysis }: { analysis: RegionAnalysis }) {
  const report = analysis.strings;
  const [onlyInteresting, setOnlyInteresting] = useState(true);
  if (report.error) {
    return <p className="text-[13px] text-mist-400">String extraction failed ({report.error}).</p>;
  }
  const rows: ExtractedString[] = onlyInteresting ? report.interesting : report.strings;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone="mono">{report.total_found} found</Chip>
        {Object.entries(report.by_category).slice(0, 6).map(([k, v]) => (
          <Chip key={k} tone="mono">{k} {v}</Chip>
        ))}
        <label className="ml-auto flex items-center gap-2 text-[12px] text-mist-300">
          <input
            type="checkbox"
            checked={onlyInteresting}
            onChange={(e) => setOnlyInteresting(e.target.checked)}
            className="accent-[#38c6d9]"
          />
          Notable only
        </label>
      </div>
      {rows.length === 0 ? (
        <p className="text-[13px] text-mist-400">
          {onlyInteresting
            ? "No URLs, addresses, paths, registry keys or commands in this region."
            : "No printable strings in this region."}
        </p>
      ) : (
        <ul className="divide-y divide-ink-800/70 rounded-md border border-ink-700/60">
          {rows.map((s, i) => (
            <li key={`${s.offset}-${i}`} className="flex items-baseline gap-3 px-3 py-2">
              <span className="shrink-0 font-mono text-[11px] text-mist-400">{s.offset_hex}</span>
              <Chip tone={CATEGORY_TONE[s.category] ?? "default"}>{s.category}</Chip>
              <span className="min-w-0 flex-1 break-all font-mono text-[12px] text-mist-100">
                {s.value}
              </span>
              <span className="shrink-0 font-mono text-[10px] text-mist-400">{s.encoding}</span>
            </li>
          ))}
        </ul>
      )}
      {report.truncated && (
        <p className="text-[11px] text-mist-400">
          Capped at the string budget; notable categories were kept first.
        </p>
      )}
    </div>
  );
}

export function Patterns({ analysis }: { analysis: RegionAnalysis }) {
  const report = analysis.patterns;
  const hits: PatternHit[] = report.hits ?? [];
  return (
    <div className="space-y-3">
      {report.note && <p className="text-[12px] text-mist-400">{report.note}</p>}
      {hits.length === 0 ? (
        <p className="text-[13px] text-mist-400">
          No catalogued pattern matched this region. That is not a clean bill of health —
          the catalogue covers known shapes only.
        </p>
      ) : (
        <ul className="space-y-2">
          {hits.map((hit) => (
            <li
              key={hit.id}
              className={`rounded-md px-4 py-3 ring-1 ring-inset ${
                SEVERITY_CLASS[hit.severity] ?? SEVERITY_CLASS.info
              }`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] font-semibold uppercase tracking-wider">
                  {hit.severity}
                </span>
                <span className="text-[13px] font-medium text-mist-100">{hit.title}</span>
                {hit.technique && (
                  <Chip tone="mono">
                    {hit.technique}
                    {hit.technique_name ? ` · ${hit.technique_name}` : ""}
                  </Chip>
                )}
                <span className="ml-auto font-mono text-[11px] text-mist-400">
                  {hit.occurrences}×
                </span>
              </div>
              <p className="mt-1.5 text-[12px] text-mist-300">{hit.description}</p>
              {(hit.offsets.length > 0 || hit.evidence) && (
                <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-[11px] text-mist-400">
                  {hit.offsets.slice(0, 8).map((o) => <span key={o}>{o}</span>)}
                  {hit.evidence && <span className="break-all">· {hit.evidence}</span>}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-ink-700/60 px-3 py-2">
      <div className="eyebrow">{label}</div>
      <div className="mt-0.5 font-mono text-[13px] text-mist-100">{value}</div>
    </div>
  );
}
