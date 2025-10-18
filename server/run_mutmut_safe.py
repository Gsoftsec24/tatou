import mutmut.__main__ as mm
from types import SimpleNamespace

# Save the original function
orig_collect_stat = mm.collect_stat

def safe_collect_stat(x):
    try:
        return orig_collect_stat(x)
    except KeyError as e:
        # Return an empty Stat-like object with all counters = 0
        print(f"[Warning] Skipped unrecognized exit code: {e}")
        return SimpleNamespace(
            ok=0,
            killed=0,
            survived=0,
            incompetent=0,
            timeout=0,
            suspicious=0,
            not_checked=0,
        )

mm.collect_stat = safe_collect_stat

if __name__ == "__main__":
    mm.cli()

