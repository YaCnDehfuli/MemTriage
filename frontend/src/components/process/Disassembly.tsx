import { useMemo, useState } from "react";
import type { RegionAnalysis } from "../../types";
import { Chip } from "../primitives";

const KIND_CLASS: Record<string, string> = {
  call: "text-accent",
  jump: "text-risk-medium",
  cjump: "text-risk-medium",
  ret: "text-risk-low",
  halt: "text-mist-400",
  syscall: "text-risk-high",
};

const PAGE = 300;

export function Disassembly({ analysis }: { analysis: RegionAnalysis }) {
  const listing = analysis.disassembly;
  const [shown, setShown] = useState(PAGE);
  const [filter, setFilter] = useState("");

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const all = listing.instructions ?? [];
    return needle
      ? all.filter((i) => i.text.toLowerCase().includes(needle) ||
          i.address_hex.includes(needle) || i.bytes_hex.includes(needle))
      : all;
  }, [listing.instructions, filter]);

  if (!listing.available) {
    return <Unavailable reason={listing.reason} />;
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone="accent">{listing.arch}</Chip>
        <Chip tone="mono">{listing.instruction_count} instructions</Chip>
        <Chip tone="mono">coverage {(listing.coverage * 100).toFixed(1)}%</Chip>
        {listing.invalid_bytes > 0 && (
          <Chip tone="mono">{listing.invalid_bytes} undecoded bytes</Chip>
        )}
        {listing.truncated && <Chip tone="mono">truncated at the byte budget</Chip>}
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter mnemonic, address or bytes"
          className="ml-auto w-56 rounded-md border border-ink-600 bg-ink-900 px-2 py-1 font-mono text-[11px] text-mist-200 placeholder:text-mist-400 focus:border-accent/50 focus:outline-none"
        />
      </div>

      <div className="max-h-[560px] overflow-auto rounded-md border border-ink-700/60">
        <table className="w-full font-mono text-[12px]">
          <tbody>
            {rows.slice(0, shown).map((i) => (
              <tr key={i.address} className="border-b border-ink-800/50 last:border-0">
                <td className="whitespace-nowrap px-3 py-1 text-mist-400">{i.address_hex}</td>
                <td className="whitespace-nowrap px-3 py-1 text-mist-400">
                  {i.bytes_hex}
                </td>
                <td className={`px-3 py-1 ${KIND_CLASS[i.kind] ?? "text-mist-200"}`}>
                  <span className="font-semibold">{i.mnemonic}</span>
                  {i.op_str && <span className="text-mist-300"> {i.op_str}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <div className="px-4 py-8 text-center text-[12px] text-mist-400">
            Nothing matches that filter.
          </div>
        )}
      </div>

      {shown < rows.length && (
        <button className="btn-ghost text-[12px]" onClick={() => setShown((n) => n + PAGE)}>
          Show {Math.min(PAGE, rows.length - shown)} more of {rows.length}
        </button>
      )}
    </div>
  );
}

export function Unavailable({ reason }: { reason: string }) {
  return (
    <div className="rounded-md border border-ink-700/60 bg-ink-900/40 px-4 py-6">
      <div className="text-[13px] font-medium text-mist-200">Not available</div>
      <p className="mt-1 max-w-xl text-[12px] text-mist-400">
        {reason || "This representation could not be produced for this region."}
      </p>
    </div>
  );
}
