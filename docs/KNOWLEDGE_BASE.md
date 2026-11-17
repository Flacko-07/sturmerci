# Knowledge Base

Knowledge ingestion, provenance metadata, full-text retrieval, CVE records,
and reference validation are implemented under `src/sentinel/knowledge/`.
Source documents live under `knowledge/` and use per-file frontmatter. The
corpus contains varied labels including Creative Commons, IETF Trust,
public-domain claims, proprietary summaries, internal material, and GPL/LGPL
documentation labels.

The corpus is not automatically covered by the root Apache licence. Files with
unclear or restrictive redistribution rights are quarantined in
[Licensing Review](LICENSING_REVIEW.md). Do not distribute the entire knowledge
directory until every source, attribution, derivative-work right, and licence
condition has been checked. Bulk NVD/CWE/CAPEC/ATT&CK ingestion remains
deferred.
