"""README golden verdict corpus (85 cases).

Добавить кейс
--------------
1. Положите ``.eml`` (или расширьте ``scripts/gen_corpus.py``) в эту папку.
2. Запустите::

     set PYTHONPATH=.
     python -c "from reliquary.core.pipeline import analyze_file; r=analyze_file('samples/corpus/YOUR.eml'); print(r.verdict.level, r.verdict.score, r.verdict.reasons)"

3. Добавьте запись в ``expected.json`` (или ``python scripts/regen_expected.py``)::

     "YOUR.eml": {"level": "suspicious", "score_min": 30, "score_max": 59, "reason_substrings": ["optional"]}

4. ``pytest tests/test_corpus_verdicts.py`` и ``python scripts/corpus_metrics.py`` должны пройти.

Уровни: ``benign`` (<10), ``unknown`` (10–29), ``suspicious`` (30–59), ``malicious`` (≥60).
Тюнинг: ``docs/TUNING.md``. Калибровка offline inbox: ``python scripts/corpus_metrics.py --inbox DIR``.
"""
