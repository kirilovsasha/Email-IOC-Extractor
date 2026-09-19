"""README for the golden verdict corpus (~40 cases).

Add a new case
--------------
1. Drop a ``.eml`` (or extend ``scripts/gen_corpus.py``) into this folder.
2. Run::

     set PYTHONPATH=.
     python -c "from reliquary.core.pipeline import analyze_file; r=analyze_file('samples/corpus/YOUR.eml'); print(r.verdict.level, r.verdict.score, r.verdict.reasons)"

3. Add an entry to ``expected.json`` (or ``python scripts/regen_expected.py``)::

     "YOUR.eml": {"level": "suspicious", "score_min": 30, "score_max": 59, "reason_substrings": ["optional"]}

4. ``pytest tests/test_corpus_verdicts.py`` and ``python scripts/corpus_metrics.py`` must pass.

Levels: ``benign`` (<10), ``unknown`` (10–29), ``suspicious`` (30–59), ``malicious`` (≥60).
Tuning: ``docs/TUNING.md``. Offline inbox calibration: ``python scripts/corpus_metrics.py --inbox DIR``.
"""
