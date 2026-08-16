import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../../state/store";
import type {
  AssistantCatalogue,
  AssistantProvider,
  ChatTurn,
  ContextPackSummary,
} from "../../types";
import { Chip, EmptyState, Panel } from "../primitives";

const CACHE_LABEL: Record<string, string> = {
  explicit: "The briefing is sent as an explicitly cached block and re-read from cache on later turns.",
  automatic: "This provider caches long prefixes automatically; the briefing is sent first so it qualifies.",
  none: "This provider does not cache prompts, so the briefing is re-sent each turn.",
};

export function AssistantView() {
  const { client, investigationId, demo, triage } = useApp();
  const id = investigationId ?? "demo-investigation";

  const [catalogue, setCatalogue] = useState<AssistantCatalogue | null>(null);
  const [pack, setPack] = useState<ContextPackSummary | null>(null);
  const [providerId, setProviderId] = useState("anthropic");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [consented, setConsented] = useState(false);
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [showPack, setShowPack] = useState(false);
  const [cacheHits, setCacheHits] = useState<number | null>(null);
  const transcriptEnd = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const [providers, context] = await Promise.all([
          client.getAssistantProviders(),
          client.getContextPack(id),
        ]);
        if (cancelled) return;
        setCatalogue(providers);
        setPack(context);
        if (providers.providers.length) {
          const first = providers.providers[0];
          setProviderId(first.id);
          setModel(first.default_model);
        }
      } catch (e) {
        if (!cancelled) setNotice((e as Error).message);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, id]);

  useEffect(() => {
    transcriptEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [turns, busy]);

  const provider: AssistantProvider | undefined = useMemo(
    () => catalogue?.providers.find((p) => p.id === providerId),
    [catalogue, providerId],
  );

  const keyMissing = Boolean(provider?.needs_key) && !apiKey.trim();
  const canSend = Boolean(draft.trim()) && !busy && consented && !keyMissing;

  const ask = useCallback(
    async (question: string) => {
      if (!question.trim()) return;
      const next: ChatTurn[] = [...turns, { role: "user", content: question.trim() }];
      setTurns(next);
      setDraft("");
      setBusy(true);
      setNotice(null);
      try {
        const reply = await client.askAssistant(id, {
          provider: providerId,
          model: model || provider?.default_model || "",
          api_key: apiKey,
          messages: next,
        });
        setTurns([...next, { role: "assistant", content: reply.text }]);
        setCacheHits(reply.usage.cache_read_input_tokens);
      } catch (e) {
        setNotice((e as Error).message);
        setTurns(next);
      } finally {
        setBusy(false);
      }
    },
    [turns, client, id, providerId, model, apiKey, provider],
  );

  const downloadScript = useCallback(
    async (language: "python" | "curl") => {
      try {
        const generated = await client.generateScript(id, { provider: providerId, model, language });
        for (const [name, body] of [
          [generated.filename, generated.script],
          [generated.briefing_filename, generated.briefing],
        ] as const) {
          const url = URL.createObjectURL(new Blob([body], { type: "text/plain" }));
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = name;
          anchor.click();
          URL.revokeObjectURL(url);
        }
        setNotice(generated.instructions);
      } catch (e) {
        setNotice((e as Error).message);
      }
    },
    [client, id, providerId, model],
  );

  if (!triage) {
    return (
      <Panel eyebrow="Phase 3 · Assistant" title="Ask about this investigation">
        <EmptyState
          title="Nothing to brief yet"
          hint="Run triage first. The assistant answers from what phases 1 and 2 produced — it never reads the memory image itself."
        />
      </Panel>
    );
  }

  return (
    <div className="space-y-5">
      <header>
        <div className="eyebrow">Phase 3 · Assistant</div>
        <h1 className="text-lg font-semibold text-mist-100">Ask about this investigation</h1>
        <p className="mt-1 max-w-2xl text-sm text-mist-400">
          Everything phases 1 and 2 produced is packed into one briefing and cached as the
          prefix of the conversation. The assistant reasons over that text — it cannot read
          the memory image or measure anything new.
        </p>
      </header>

      <div className="grid gap-5 lg:grid-cols-[1fr_340px]">
        <Panel
          eyebrow="Conversation"
          title={provider ? `${provider.label} · ${model || provider.default_model}` : "Assistant"}
          right={
            cacheHits ? (
              <span className="font-mono text-[11px] text-mist-400">
                {cacheHits.toLocaleString()} cached input tokens
              </span>
            ) : undefined
          }
        >
          <div className="max-h-[520px] space-y-4 overflow-y-auto px-4 py-4">
            {turns.length === 0 && (
              <div className="space-y-3">
                <p className="text-[13px] text-mist-400">
                  Start with one of these, or ask your own:
                </p>
                <div className="flex flex-col items-start gap-1.5">
                  {(catalogue?.suggested_questions ?? []).map((q) => (
                    <button
                      key={q}
                      className="btn-ghost text-left text-[12px]"
                      disabled={!consented || keyMissing || busy}
                      onClick={() => void ask(q)}
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {turns.map((turn, index) => (
              <div key={index} className={turn.role === "user" ? "text-right" : ""}>
                <div
                  className={`inline-block max-w-[92%] whitespace-pre-wrap rounded-lg px-3 py-2 text-left text-[13px] ${
                    turn.role === "user"
                      ? "bg-accent/15 text-mist-100 ring-1 ring-inset ring-accent/25"
                      : "bg-ink-800/60 text-mist-200 ring-1 ring-inset ring-ink-700"
                  }`}
                >
                  {turn.content}
                </div>
              </div>
            ))}
            {busy && <p className="text-[12px] text-mist-400">Thinking…</p>}
            <div ref={transcriptEnd} />
          </div>

          {notice && (
            <div className="border-t border-ink-800/70 px-4 py-2 text-[12px] text-risk-high">
              {notice}
            </div>
          )}

          <div className="border-t border-ink-800/70 p-4">
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) void ask(draft);
              }}
              rows={3}
              placeholder="Ask about a process, a region, a rule that fired, or what is still missing…"
              className="w-full resize-y rounded-md border border-ink-600 bg-ink-900 px-3 py-2 text-[13px] text-mist-100 placeholder:text-mist-400 focus:border-accent/50 focus:outline-none"
            />
            <div className="mt-2 flex items-center justify-between gap-3">
              <span className="text-[11px] text-mist-400">
                {keyMissing
                  ? "An API key is needed for this provider."
                  : !consented
                    ? "Acknowledge what gets sent before asking."
                    : "⌘/Ctrl + Enter to send"}
              </span>
              <button className="btn-accent" disabled={!canSend} onClick={() => void ask(draft)}>
                {busy ? "Asking…" : "Ask"}
              </button>
            </div>
          </div>
        </Panel>

        <div className="space-y-5">
          <Panel eyebrow="Provider" title="Where this goes">
            <div className="space-y-3 px-4 py-4">
              <label className="block">
                <span className="eyebrow">Provider</span>
                <select
                  value={providerId}
                  onChange={(e) => {
                    setProviderId(e.target.value);
                    const next = catalogue?.providers.find((p) => p.id === e.target.value);
                    setModel(next?.default_model ?? "");
                    setCacheHits(null);
                  }}
                  className="mt-1 w-full rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-[13px] text-mist-100 focus:border-accent/50 focus:outline-none"
                >
                  {(catalogue?.providers ?? []).map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                      {p.local ? " — stays on this machine" : ""}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="eyebrow">Model</span>
                <input
                  list="assistant-models"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="mt-1 w-full rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 font-mono text-[12px] text-mist-100 focus:border-accent/50 focus:outline-none"
                />
                <datalist id="assistant-models">
                  {(provider?.models ?? []).map((m) => <option key={m} value={m} />)}
                </datalist>
              </label>

              {provider?.needs_key && (
                <label className="block">
                  <span className="eyebrow">API key</span>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    autoComplete="off"
                    placeholder={provider.key_env}
                    className="mt-1 w-full rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 font-mono text-[12px] text-mist-100 placeholder:text-mist-400 focus:border-accent/50 focus:outline-none"
                  />
                  <span className="mt-1 block text-[11px] text-mist-400">
                    Held in this tab only — never written to storage, never persisted or
                    logged by the API.
                  </span>
                </label>
              )}

              {provider?.note && <p className="text-[12px] text-mist-400">{provider.note}</p>}
              {provider && (
                <p className="text-[11px] text-mist-400">
                  {CACHE_LABEL[provider.prompt_cache]}
                </p>
              )}

              <label className="flex items-start gap-2 rounded-md border border-risk-medium/30 bg-risk-medium/5 px-3 py-2">
                <input
                  type="checkbox"
                  checked={consented}
                  onChange={(e) => setConsented(e.target.checked)}
                  className="mt-0.5 accent-[#38c6d9]"
                />
                <span className="text-[12px] text-mist-300">
                  {catalogue?.consent_notice ?? pack?.consent_notice}
                </span>
              </label>

              <div className="flex gap-2">
                <button className="btn-ghost flex-1 justify-center text-[12px]"
                        onClick={() => void downloadScript("python")}>
                  Script (Python)
                </button>
                <button className="btn-ghost flex-1 justify-center text-[12px]"
                        onClick={() => void downloadScript("curl")}>
                  Script (curl)
                </button>
              </div>
            </div>
          </Panel>

          <Panel
            eyebrow="Briefing"
            title="Exactly what gets sent"
            right={
              pack ? (
                <span className="font-mono text-[11px] text-mist-400">
                  ~{pack.approx_tokens.toLocaleString()} tokens
                </span>
              ) : undefined
            }
          >
            <div className="space-y-3 px-4 py-4">
              {pack ? (
                <>
                  <div className="flex flex-wrap gap-1.5">
                    {pack.sections.map((section) => <Chip key={section}>{section}</Chip>)}
                  </div>
                  {pack.truncated_sections.length > 0 && (
                    <p className="text-[11px] text-mist-400">
                      Capped for length: {pack.truncated_sections.join("; ")}.
                    </p>
                  )}
                  <p className="font-mono text-[10px] text-mist-400">
                    sha256 {pack.sha256.slice(0, 24)}…
                  </p>
                  <button className="btn-ghost text-[12px]" onClick={() => setShowPack((v) => !v)}>
                    {showPack ? "Hide briefing" : "Read the briefing"}
                  </button>
                  {showPack && (
                    <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-md border border-ink-700/60 bg-ink-900/60 p-3 font-mono text-[11px] text-mist-300">
                      {pack.markdown}
                    </pre>
                  )}
                </>
              ) : (
                <p className="text-[12px] text-mist-400">Building the briefing…</p>
              )}
              {demo && (
                <p className="text-[11px] text-mist-400">
                  Demo mode answers from fixtures and makes no network request.
                </p>
              )}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
