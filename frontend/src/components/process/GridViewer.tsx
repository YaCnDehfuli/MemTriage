import { useState } from "react";

export function GridViewer({ gridUrl, attentionUrl }: { gridUrl: string; attentionUrl: string | null }) {
  const [showAttention, setShowAttention] = useState(true);
  return (
    <div>
      <div className="relative mx-auto aspect-square w-full max-w-[320px] overflow-hidden rounded-lg ring-1 ring-inset ring-ink-600">
        <img
          src={gridUrl}
          alt="VADViT region grid"
          className="absolute inset-0 h-full w-full [image-rendering:pixelated]"
        />
        {attentionUrl && (
          <img
            src={attentionUrl}
            alt="Attention overlay"
            className={`absolute inset-0 h-full w-full transition-opacity duration-300 ${
              showAttention ? "opacity-100" : "opacity-0"
            }`}
          />
        )}
      </div>
      <div className="mt-3 flex items-center justify-center gap-2">
        <button
          className={`btn text-xs ring-1 ring-inset ${
            !showAttention ? "bg-accent/15 text-accent ring-accent/30" : "text-mist-300 ring-ink-600"
          }`}
          onClick={() => setShowAttention(false)}
        >
          Region grid
        </button>
        <button
          disabled={!attentionUrl}
          className={`btn text-xs ring-1 ring-inset disabled:opacity-30 ${
            showAttention ? "bg-accent/15 text-accent ring-accent/30" : "text-mist-300 ring-ink-600"
          }`}
          onClick={() => setShowAttention(true)}
        >
          Attention overlay
        </button>
      </div>
      <p className="mt-2 text-center text-[11px] text-mist-400">
        Each patch is one VAD region (R=tag/prot, G=entropy, B=byte-transition). The overlay is the
        model's last-block CLS→patch attention.
      </p>
    </div>
  );
}
