"""The MemTriage analysis pipeline.

Stages (each a step in the Celery task, emitting progress):

    extract  → VolMemLyzer IoC inventory + per-object suspicion (volmemlyzer_adapter)
    select   → rank candidate processes (candidates)
    dump     → Volatility ``vadinfo --dump`` per candidate (region_dump)
    render   → reproduce VADViT grid images exactly (grid_render)
    infer    → VADViT classification (vadvit_model / inference)
    explain  → attention overlay + patch→VAD attribution (explain)
    report   → consolidate into one investigation report (report)

Every stage treats dump-derived data as untrusted and sanitizes before it
reaches persisted output.
"""
