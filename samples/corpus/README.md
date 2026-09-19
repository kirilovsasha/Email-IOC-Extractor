"""README for the golden verdict corpus.

Add a new case
--------------
1. Drop a ``.eml`` (or copy from phishing fixtures) into this folder.
2. Run::

     set PYTHONPATH=.
     python -c "from reliquary.core.pipeline import analyze_file; r=analyze_file('samples/corpus/YOUR.eml'); print(r.verdict.level, r.verdict.score, r.verdict.reasons)"

3. Add an entry to ``expected.json``::

     "YOUR.eml": {"level": "suspicious", "score_min": 30, "score_max": 59, "reason_substrings": ["optional"]}

4. ``pytest tests/test_corpus_verdicts.py`` must pass.

Levels: ``benign`` (<10), ``unknown`` (10–29), ``suspicious`` (30–59), ``malicious`` (≥60)
with built-in weights (override via ``verdict_extra.json`` is tested separately).
"""
