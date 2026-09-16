"""Kernel-symbol resolution must not race when plugins run concurrently.

Volatility resolves a Windows image's symbol table the first time a windows.*
plugin runs, and every plugin process does it independently. A concurrent batch
against a cold cache therefore loses a random subset of plugins to an unsatisfied
``symbol_table_name`` requirement. These tests model that cache and prove the
batch comes out whole.
"""
from __future__ import annotations

from types import SimpleNamespace

from memtriage.pipeline import volmemlyzer_adapter as vml

SYMBOL_ERROR = (
    "Volatility could not resolve the kernel symbol table. It tried to download "
    "the PDB from the Microsoft symbol server."
)
BATCH = {"info", "pslist", "cmdline", "malfind", "handles", "threads"}


class FakeVolatility:
    """A symbol cache with Volatility's failure mode.

    Cold, a concurrent pass loses every plugin but the first to the download
    race. A serial pass always resolves the cache. ``flaky`` symbol failures can
    still strike a warm concurrent pass, standing in for a proxy blip.
    """

    def __init__(self, *, resolvable=True, flaky=frozenset(), sticky=frozenset()):
        self.warm = False
        self.resolvable = resolvable
        self.flaky = set(flaky)
        self.sticky = set(sticky)
        self.calls: list[tuple[frozenset, int, bool]] = []
        self.registry = SimpleNamespace(has=lambda name: True)

    def run(self, enable, workers, cached):
        self.calls.append((frozenset(enable), workers, cached))
        failed = {}
        if not self.resolvable:
            failed = dict.fromkeys(enable, SYMBOL_ERROR)
        elif not self.warm and workers > 1:
            winner = sorted(enable)[0]
            failed = {n: SYMBOL_ERROR for n in enable if n != winner}
            self.warm = True
        else:
            self.warm = True
            if workers > 1:
                failed = dict.fromkeys(self.flaky & set(enable), SYMBOL_ERROR)
                self.flaky.clear()
        failed.update(dict.fromkeys(self.sticky & set(enable), SYMBOL_ERROR))
        return SimpleNamespace(failed_plugins=failed)


def _run(fake, *, concurrency=4, use_cache=False, selected=BATCH):
    return vml.run_symbol_resilient(
        fake, fake.run, lambda r: r.failed_plugins, selected,
        concurrency=concurrency, use_cache=use_cache,
    )


def test_the_unprotected_concurrent_pass_is_what_loses_plugins():
    """Pins the failure mode the fix exists for, so the model stays honest."""
    fake = FakeVolatility()
    result = fake.run(BATCH, 4, False)
    assert len(result.failed_plugins) == len(BATCH) - 1


def test_symbols_are_resolved_alone_before_the_concurrent_batch():
    fake = FakeVolatility()
    result = _run(fake)

    assert result.failed_plugins == {}
    probe, batch = fake.calls[0], fake.calls[1]
    assert probe == (frozenset({"info"}), 1, False), "probe runs alone, serially"
    assert batch[0] == BATCH and batch[1] == 4, "batch keeps its concurrency"
    assert len(fake.calls) == 2, "nothing to retry once the cache is warm"


def test_a_transient_symbol_failure_is_retried_serially_from_cache():
    fake = FakeVolatility(flaky={"handles", "threads"})
    result = _run(fake)

    assert result.failed_plugins == {}
    retry = fake.calls[2]
    assert retry[1] == 1, "the retry must not race again"
    assert retry[2] is True, "successes must come back as cache hits, not re-run"


def test_retries_are_bounded():
    fake = FakeVolatility(sticky={"threads"})
    result = _run(fake)

    assert set(result.failed_plugins) == {"threads"}
    # probe + batch + SYMBOL_RETRY_PASSES serial passes, and no more
    assert len(fake.calls) == 2 + vml.SYMBOL_RETRY_PASSES


def test_genuinely_unavailable_symbols_fail_once_instead_of_retrying_everything():
    fake = FakeVolatility(resolvable=False)
    result = _run(fake)

    assert set(result.failed_plugins) == BATCH, "reported, not hidden"
    probes = [c for c in fake.calls if c[0] == frozenset({"info"})]
    batches = [c for c in fake.calls if c[0] == BATCH]
    assert len(probes) == vml.SYMBOL_RETRY_PASSES + 1
    assert len(batches) == 1, "no point re-running every plugin against no symbols"


def test_a_non_symbol_failure_is_left_alone():
    fake = FakeVolatility()
    original = fake.run

    def run(enable, workers, cached):
        result = original(enable, workers, cached)
        if "malfind" in enable:
            result.failed_plugins["malfind"] = "The plugin exceeded its timeout."
        return result

    result = vml.run_symbol_resilient(
        fake, run, lambda r: r.failed_plugins, BATCH, concurrency=4, use_cache=False,
    )
    assert result.failed_plugins == {"malfind": "The plugin exceeded its timeout."}
    assert len(fake.calls) == 2, "a timeout is not a symbol race; do not re-run it"


def test_a_serial_batch_needs_no_probe():
    fake = FakeVolatility()
    result = _run(fake, concurrency=1)
    assert result.failed_plugins == {}
    assert fake.calls == [(frozenset(BATCH), 1, False)]


def test_symbol_failures_only_matches_symbol_resolution():
    assert vml.symbol_failures({
        "a": SYMBOL_ERROR,
        "b": "Unsatisfied requirement plugins.CmdLine.kernel.symbol_table_name",
        "c": "The plugin exceeded its timeout.",
        "d": "Volatility rejected the plugin's requirements for this image.",
    }) == {"a", "b"}


def test_the_manual_workbench_batch_is_protected_too():
    """Analyst-picked plugin runs hit the same race on a fresh worker."""
    from memtriage.pipeline.plugin_runner import run_selected_plugins

    fake = FakeVolatility()

    class Pipe:
        registry = SimpleNamespace(has=lambda name: True,
                                   topo_layers=lambda names: [sorted(names)])

        def run_plugin_raw(self, *, image_path, enable, outdir, concurrency, use_cache):
            result = fake.run(enable, concurrency, use_cache)
            ok = {n: f"{outdir}/{n}.json" for n in enable if n not in result.failed_plugins}
            return SimpleNamespace(artifacts={"plugins": ok,
                                              "failed_plugins": result.failed_plugins})

    out = run_selected_plugins(Pipe(), "img", "/tmp/out", ["cmdline", "handles", "threads"],
                               4, lambda event: None)
    assert out["failed_plugins"] == {}
    assert fake.calls[0] == (frozenset({"info"}), 1, True)


def test_a_crashing_probe_does_not_abort_the_analysts_batch():
    from memtriage.pipeline.plugin_runner import run_selected_plugins

    class Pipe:
        registry = SimpleNamespace(has=lambda name: True,
                                   topo_layers=lambda names: [sorted(names)])
        def __init__(self):
            self.calls: list[set[str]] = []

        def run_plugin_raw(self, *, image_path, enable, outdir, concurrency, use_cache):
            self.calls.append(set(enable))
            if enable == {"info"}:
                raise RuntimeError("probe blew up")
            return SimpleNamespace(artifacts={
                "plugins": {n: f"{outdir}/{n}.json" for n in enable},
                "failed_plugins": {},
            })

    pipe = Pipe()
    out = run_selected_plugins(pipe, "img", "/tmp/out", ["cmdline", "handles"], 4,
                               lambda event: None)
    assert set(out["plugins"]) == {"cmdline", "handles"}
    assert pipe.calls[-1] == {"cmdline", "handles"}
