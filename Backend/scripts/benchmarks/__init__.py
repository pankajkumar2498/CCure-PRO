"""
Backend.scripts.benchmarks — hardening benchmark tooling.

``load_benchmark``       loads a benchmark pack into the compliance catalogue
``build_baseline_packs`` regenerates the shipped CCURE baseline packs from the
                         built-in rules in ``core/config_audit/builtin/``

Both are runnable as modules from ``Backend/``:

    python -m scripts.benchmarks.load_benchmark --dir data/benchmarks
    python -m scripts.benchmarks.build_baseline_packs --check

The format, and how to convert a licensed CIS Benchmark export into it, is
documented in ``Backend/data/benchmarks/README.md``. No CIS Benchmark content
ships in this repository.
"""
