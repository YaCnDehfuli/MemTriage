import { useEffect, useState } from "react";
import { useApp } from "../state/store";
import type { ModelAccessPolicy, ModelAccessResponse } from "../types";

const EMPTY = {
  full_name: "",
  email: "",
  organization: "",
  role: "",
  country: "",
  intended_use: "research",
  project_description: "",
  expected_publication: "",
  agrees_to_terms: false,
};

/**
 * The trained VADViT weights are released by the author on request rather than
 * shipped. This collects the request and hands back a message to send — nothing
 * is emailed from the application.
 */
export function ModelAccessForm({ onClose }: { onClose(): void }) {
  const { client } = useApp();
  const [policy, setPolicy] = useState<ModelAccessPolicy | null>(null);
  const [form, setForm] = useState(EMPTY);
  const [submitted, setSubmitted] = useState<ModelAccessResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void client
      .getModelAccessPolicy()
      .then((p) => !cancelled && setPolicy(p))
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [client]);

  const set = (patch: Partial<typeof EMPTY>) => setForm((f) => ({ ...f, ...patch }));

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      setSubmitted(await client.requestModelAccess(form));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const contact = policy?.contact ?? submitted?.contact ?? "";

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-ink-950/80 p-4"
         role="dialog" aria-modal="true" aria-label="Request the trained VADViT weights">
      <div className="panel max-h-[90vh] w-full max-w-2xl overflow-y-auto">
        <div className="panel-head sticky top-0 z-10 bg-ink-850">
          <div>
            <div className="eyebrow">VADViT</div>
            <h2 className="text-sm font-semibold text-mist-100">
              Request the trained weights
            </h2>
          </div>
          <button className="btn-ghost text-[12px]" onClick={onClose}>Close</button>
        </div>

        {submitted ? (
          <div className="space-y-4 p-5">
            <p className="text-[13px] text-mist-200">{submitted.note}</p>
            <div>
              <div className="eyebrow mb-1">Subject</div>
              <p className="font-mono text-[12px] text-mist-200">{submitted.email_subject}</p>
            </div>
            <div>
              <div className="eyebrow mb-1">Message</div>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md border border-ink-700/60 bg-ink-900/60 p-3 font-mono text-[11px] text-mist-300">
                {submitted.email_body}
              </pre>
            </div>
            <div className="flex flex-wrap gap-2">
              <a className="btn-accent text-[12px]" href={submitted.mailto}>
                Open in mail client
              </a>
              <button
                className="btn-ghost text-[12px]"
                onClick={() => {
                  void navigator.clipboard
                    ?.writeText(`${submitted.email_subject}\n\n${submitted.email_body}`)
                    .then(() => setCopied(true));
                }}
              >
                {copied ? "Copied" : "Copy request"}
              </button>
              <span className="self-center font-mono text-[11px] text-mist-400">{contact}</span>
            </div>
          </div>
        ) : (
          <div className="space-y-4 p-5">
            {policy && <p className="text-[12px] text-mist-300">{policy.policy}</p>}

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Full name" value={form.full_name}
                     onChange={(v) => set({ full_name: v })} />
              <Field label="Email" value={form.email} type="email"
                     onChange={(v) => set({ email: v })} />
              <Field label="Organization" value={form.organization}
                     onChange={(v) => set({ organization: v })} />
              <Field label="Role" value={form.role}
                     onChange={(v) => set({ role: v })} placeholder="PhD candidate, analyst…" />
              <Field label="Country" value={form.country}
                     onChange={(v) => set({ country: v })} />
              <label className="block">
                <span className="eyebrow">Intended use</span>
                <select
                  value={form.intended_use}
                  onChange={(e) => set({ intended_use: e.target.value })}
                  className="mt-1 w-full rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-[13px] text-mist-100 focus:border-accent/50 focus:outline-none"
                >
                  {(policy?.intended_use_options ?? []).map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </label>
            </div>

            <label className="block">
              <span className="eyebrow">What would you use the model for?</span>
              <textarea
                value={form.project_description}
                onChange={(e) => set({ project_description: e.target.value })}
                rows={5}
                placeholder="Is this for your research, a thesis, a course, an evaluation? What are you trying to find out, and on what data?"
                className="mt-1 w-full resize-y rounded-md border border-ink-600 bg-ink-900 px-3 py-2 text-[13px] text-mist-100 placeholder:text-mist-400 focus:border-accent/50 focus:outline-none"
              />
              <span className="mt-1 block text-[11px] text-mist-400">
                {form.project_description.trim().length} / 30 characters minimum
              </span>
            </label>

            <Field label="Expected publication (optional)" value={form.expected_publication}
                   onChange={(v) => set({ expected_publication: v })}
                   placeholder="Conference, journal, thesis, or none" />

            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                checked={form.agrees_to_terms}
                onChange={(e) => set({ agrees_to_terms: e.target.checked })}
                className="mt-0.5 accent-[#38c6d9]"
              />
              <span className="text-[12px] text-mist-300">
                {policy?.terms ??
                  "Requested weights are for the stated use only and are not redistributed."}
              </span>
            </label>

            {error && <p className="text-[12px] text-risk-critical">{error}</p>}

            <div className="flex items-center justify-between gap-3">
              <span className="text-[11px] text-mist-400">
                Recorded locally, then sent by you — MemTriage cannot send mail.
              </span>
              <button
                className="btn-accent"
                disabled={busy || !form.agrees_to_terms}
                onClick={() => void submit()}
              >
                {busy ? "Preparing…" : "Prepare request"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
}: {
  label: string;
  value: string;
  onChange(value: string): void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <label className="block">
      <span className="eyebrow">{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 w-full rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-[13px] text-mist-100 placeholder:text-mist-400 focus:border-accent/50 focus:outline-none"
      />
    </label>
  );
}
