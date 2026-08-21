import { useCallback, useRef, useState } from "react";
import { useApp } from "../state/store";
import { bytes } from "../lib/format";
import { Meter } from "./primitives";

// Mirrors backend/memtriage/security/limits.py so an obviously-wrong file is
// caught before a multi-gigabyte upload starts, not after.
const ALLOWED = [
  ".raw", ".mem", ".vmem", ".lime", ".dmp", ".core",
  ".elf", ".bin", ".img", ".vmsn", ".vmss", ".dump",
];
const MAX_DUMPS = 5;

function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot === -1 ? "" : name.slice(dot).toLowerCase();
}

export function UploadPanel() {
  const { uploads, uploadDumps, setStage, loading, investigationId } = useApp();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [rejected, setRejected] = useState<string[]>([]);

  const accept = useCallback(
    (list: FileList | null) => {
      if (!list) return;
      const files = Array.from(list);
      const bad = files.filter((f) => !ALLOWED.includes(extensionOf(f.name)));
      const good = files.filter((f) => ALLOWED.includes(extensionOf(f.name)));
      setRejected(bad.map((f) => f.name));
      if (good.length) void uploadDumps(good.slice(0, MAX_DUMPS));
    },
    [uploadDumps],
  );

  const done = uploads.length > 0 && uploads.every((u) => u.status === "done");

  return (
    <div className="space-y-4 px-4 py-4">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          accept(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
        }}
        className={`grid cursor-pointer place-items-center rounded-lg border border-dashed px-6 py-10 text-center transition-colors ${
          dragging
            ? "border-accent/60 bg-accent/5"
            : "border-ink-600 hover:border-ink-500 hover:bg-ink-800/40"
        }`}
      >
        <div className="text-sm font-medium text-mist-100">
          Drop memory images here, or click to choose
        </div>
        <p className="mt-1 max-w-md text-[12px] text-mist-400">
          Up to {MAX_DUMPS} interval snapshots of the same host. Accepted:{" "}
          <span className="font-mono">{ALLOWED.join(" ")}</span>
        </p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => {
            accept(e.target.files);
            e.target.value = "";
          }}
        />
      </div>

      {rejected.length > 0 && (
        <p className="text-[12px] text-risk-high">
          Skipped {rejected.length} file{rejected.length > 1 ? "s" : ""} with an unsupported
          extension: <span className="font-mono">{rejected.join(", ")}</span>
        </p>
      )}

      {uploads.length > 0 && (
        <ul className="space-y-2">
          {uploads.map((u) => (
            <li key={u.name} className="rounded-md border border-ink-700/60 px-3 py-2">
              <div className="flex items-baseline justify-between gap-3">
                <span className="truncate text-[13px] text-mist-100">{u.name}</span>
                <span className="shrink-0 font-mono text-[11px] text-mist-400">
                  {bytes(u.size)}
                </span>
              </div>
              <div className="mt-2">
                <Meter value={u.progress / 100} />
              </div>
              <div className="mt-1 text-[11px] text-mist-400">
                {u.status === "failed"
                  ? <span className="text-risk-critical">{u.error ?? "Upload failed"}</span>
                  : u.status === "done"
                    ? "Uploaded"
                    : `${u.progress}%`}
              </div>
            </li>
          ))}
        </ul>
      )}

      <button
        className="btn-accent w-full justify-center"
        disabled={loading || !done || !investigationId}
        onClick={() => setStage("triage")}
      >
        {loading ? "Uploading…" : "Configure VolMemLyzer triage →"}
      </button>
    </div>
  );
}
