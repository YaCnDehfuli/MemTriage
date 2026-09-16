import { useEffect, useState } from "react";

import { useApp } from "../../state/store";
import { useReport } from "../../state/reportStore";
import type { AssistantProviders, DraftedNarrative } from "../../types";

/**
 * Drafting the connective narrative.
 *
 * Deliberately an explicit act with a visible result, not something that
 * happens on the way to rendering a page. The document is complete and
 * defensible without it; what a model adds is the prose that connects one
 * finding to the next and says what would settle each one. The analyst chooses
 * where that is sent, sees what is stored, and can throw it away.
 *
 * The key lives in component state only: it is held for as long as this panel is
 * mounted, so loading models and then drafting does not mean typing it twice,
 * and it is never persisted — not to localStorage, not to the investigation,
 * not to a log. Navigating away discards it.
 */
export function DraftNarrativePanel() {
  const { client, investigationId } = useApp();
  const { doc, refresh } = useReport();

  const [catalogue, setCatalogue] = useState<AssistantProviders | null>(null);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  // Model ids the key actually reaches, once asked for. Empty until then, and
  // reset whenever the provider changes so one provider's list is never offered
  // for another's endpoint.
  const [liveModels, setLiveModels] = useState<string[] | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DraftedNarrative | null>(null);

  useEffect(() => {
    let live = true;
    void client
      .listAssistantProviders()
      .then((data) => {
        if (!live) return;
        setCatalogue(data);
        const first = data.providers[0];
        if (first) {
          setProvider(first.id);
          setModel(first.default_model);
        }
      })
      .catch((e: Error) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [client]);

  const selected = catalogue?.providers.find((p) => p.id === provider);
  const modelOptions = liveModels ?? selected?.models ?? [];

  async function loadModels() {
    setLoadingModels(true);
    setError(null);
    try {
      const out = await client.listProviderModels({ provider, api_key: apiKey });
      setLiveModels(out.models);
      if (out.models.length > 0 && !out.models.includes(model)) {
        setModel(out.models[0]);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingModels(false);
    }
  }
  const findingCount = doc?.findings.length ?? 0;
  const drafted = doc?.narration?.attached ?? 0;

  async function draft() {
    if (!investigationId) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const out = await client.draftNarrative(investigationId, {
        provider,
        model,
        api_key: apiKey,
      });
      setResult(out);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    if (!investigationId) return;
    setBusy(true);
    setError(null);
    try {
      await client.clearDraftedNarrative(investigationId);
      setResult(null);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3 rounded border border-surface-700 bg-surface-900 p-3">
      <div>
        <h3 className="text-[13px] font-medium text-ink-100">Drafted narrative</h3>
        <p className="mt-0.5 text-[11px] leading-relaxed text-ink-400">
          Writes the connective prose the rule engine cannot: why a lead matters,
          how it relates to the one before it, and what would confirm or rule it
          out. Each passage is stored against the finding it explains and renders
          beside that evidence in the report, labelled as drafted. It never
          changes a score, a rule result or an ATT&amp;CK mapping.
        </p>
      </div>

      {catalogue && (
        <p className="rounded border border-surface-700 bg-surface-950 px-2.5 py-2 text-[11px] leading-relaxed text-ink-300">
          {catalogue.consent_notice}
        </p>
      )}

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1">
          <span className="text-[10px] uppercase tracking-wide text-ink-400">Provider</span>
          <select
            className="rounded border border-surface-600 bg-surface-950 px-2 py-1 text-[12px] text-ink-200"
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value);
              const next = catalogue?.providers.find((p) => p.id === e.target.value);
              setModel(next?.default_model ?? "");
              setLiveModels(null);
            }}
          >
            {(catalogue?.providers ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-[10px] uppercase tracking-wide text-ink-400">Model</span>
          {/* A free-text input with suggestions, not a select: the list below
              is only ever a starting point, and any id the provider accepts —
              a fine-tune, a preview model — has to be typeable. */}
          <input
            className="w-56 rounded border border-surface-600 bg-surface-950 px-2 py-1 font-mono text-[12px] text-ink-200"
            list="draft-model-options"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder={selected?.default_model ?? ""}
          />
          <datalist id="draft-model-options">
            {modelOptions.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        </label>

        {selected?.needs_key && (
          <label className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wide text-ink-400">
              API key
            </span>
            <input
              type="password"
              autoComplete="off"
              className="w-56 rounded border border-surface-600 bg-surface-950 px-2 py-1 font-mono text-[12px] text-ink-200"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="used for this request only"
            />
          </label>
        )}

        <button
          type="button"
          className="text-[12px] text-ink-400 underline hover:text-ink-200"
          disabled={loadingModels || !provider || (selected?.needs_key === true && !apiKey)}
          onClick={() => void loadModels()}
          title="Ask this provider which models the key can reach"
        >
          {loadingModels ? "Loading…" : "Load models"}
        </button>

        <button
          type="button"
          className="btn-accent text-xs"
          disabled={busy || !provider || findingCount === 0 || (selected?.needs_key === true && !apiKey)}
          onClick={() => void draft()}
        >
          {busy ? "Drafting…" : drafted > 0 ? "Re-draft" : "Draft narrative"}
        </button>

        {drafted > 0 && (
          <button
            type="button"
            className="text-[12px] text-ink-400 underline hover:text-ink-200"
            disabled={busy}
            onClick={() => void clear()}
          >
            Clear draft
          </button>
        )}
      </div>

      {findingCount === 0 && (
        <p className="text-[11px] text-ink-400">
          Triage scored nothing for this investigation, so there is no narrative to
          write.
        </p>
      )}

      {drafted > 0 && !result && (
        <p className="text-[11px] text-ink-400">
          {drafted} passage(s) in this report were drafted
          {doc?.narration?.model ? ` by ${doc.narration.model}` : ""}.
        </p>
      )}

      {result && (
        <div className="space-y-1 text-[11px] text-ink-300">
          <p>
            Stored {result.stored} passage(s) from{" "}
            <span className="font-mono">{result.model}</span>. They appear in the
            preview beside the findings they explain.
          </p>
          {result.unmatched.length > 0 && (
            <p className="text-risk-medium">
              {result.unmatched.length} passage(s) were discarded because they
              referred to findings this report does not contain.
            </p>
          )}
        </div>
      )}

      {liveModels && (
        <p className="text-[11px] text-ink-400">
          {liveModels.length} model(s) available to this key.
          {selected?.note ? ` ${selected.note}` : ""}
        </p>
      )}

      {error && (
        <p className="text-[11px] text-risk-high">{error}</p>
      )}
    </div>
  );
}
