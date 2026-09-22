"""README golden verdict corpus (103 cases).

Добавить кейс
--------------
1. Положите ``.eml`` (или расширьте ``scripts/gen_corpus.py``) в эту папку.
2. Запустите::

     set PYTHONPATH=.
     python -c "from reliquary.core.pipeline import analyze_file; r=analyze_file('samples/corpus/YOUR.eml'); print(r.verdict.level, r.verdict.score, r.verdict.reasons)"

3. Добавьте запись в ``expected.json`` (или ``python scripts/regen_expected.py``)::

     "YOUR.eml": {"level": "suspicious", "score_min": 40, "score_max": 55, "reason_substrings": ["optional"]}

   ``regen_expected.py`` пишет **узкие** окна (±8 unknown / ±10 suspicious·malicious)
   внутри полосы уровня — так ловятся регрессии весов.

4. ``pytest tests/test_corpus_verdicts.py`` и ``python scripts/corpus_metrics.py`` должны пройти.

Уровни: ``benign`` (<10), ``unknown`` (10–29), ``suspicious`` (30–59), ``malicious`` (≥60).
Тюнинг: ``docs/TUNING.md``. Калибровка offline inbox: ``python scripts/corpus_metrics.py --inbox DIR``.

BY (РБ): ``suspicious_display_spoof_belarusbank.eml``, ``suspicious_display_spoof_mns_by.eml``,
``suspicious_bec_by_erip.eml``, ``benign_portal_gov_by.eml`` + пресет ``org_profile.example/by_gov/``.

2.16+: messenger/QR lure, ISO exe, remote template, HTML polyglot, RAR scrape, KZ/UA spoof.
2.17+: wrap-lure, ARC fail, office DDE, CID phishing, OLE package, form action.
"""
