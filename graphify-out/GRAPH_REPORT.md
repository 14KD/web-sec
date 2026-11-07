# Graph Report - webtester  (2026-11-06)

## Corpus Check
- 67 files · ~21,278 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 2 file(s) not represented in the graph (top: (none) 2)

## Summary
- 499 nodes · 1533 edges · 32 communities (7 shown, 25 thin omitted)
- Extraction: 75% EXTRACTED · 25% INFERRED · 0% AMBIGUOUS · INFERRED: 383 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- models.py
- respx
- ScanConfig
- cli.py
- SafeHttpClient
- steps
- test_fuzz_properties.py
- ExposedFilesModule
- Finding
- websec-auditor

## God Nodes (most connected - your core abstractions)
1. `ScanConfig` - 107 edges
2. `Target` - 107 edges
3. `SafeHttpClient` - 106 edges
4. `CrawledPage` - 77 edges
5. `Finding` - 71 edges
6. `Severity` - 49 edges
7. `BaseModule` - 48 edges
8. `SecurityScanner` - 27 edges
9. `LightCrawler` - 16 edges
10. `SecurityScorer` - 15 edges

## Surprising Connections (you probably didn't know these)
- `run_programmatic_audit()` --uses--> `ScanConfig`  [INFERRED]
  web test/examples/sample_scan.py → web test/src/websec/config.py
- `scan_command()` --uses--> `ScanConfig`  [INFERRED]
  web test/src/websec/cli.py → web test/src/websec/config.py
- `scan_command()` --uses--> `Target`  [INFERRED]
  web test/src/websec/cli.py → web test/src/websec/core/models.py
- `scan_command()` --uses--> `SecurityScanner`  [INFERRED]
  web test/src/websec/cli.py → web test/src/websec/core/scanner.py
- `LightCrawler` --uses--> `ScanConfig`  [INFERRED]
  web test/src/websec/core/crawler.py → web test/src/websec/config.py

## Import Cycles
- None detected.

## Communities (32 total, 25 thin omitted)

### Community 1 - "respx"
Cohesion: 0.06
Nodes (16): TlsModule, sample_config(), sample_target(), test_chaos_connection_drop_resilience(), test_chaos_internal_server_errors_across_all_modules(), test_chaos_massive_response_body(), test_chaos_total_timeout_resilience(), get_free_port() (+8 more)

### Community 2 - "ScanConfig"
Cohesion: 0.06
Nodes (36): ScanConfig, CrawledPage, FormInfo, FormInput, Target, ClickjackingModule, CorsModule, CsrfModule (+28 more)

### Community 3 - "cli.py"
Cohesion: 0.07
Nodes (6): list_modules_command(), main(), scan_command(), update_db_command(), version_callback(), test_cli_scan_successful()

### Community 4 - "SafeHttpClient"
Cohesion: 0.06
Nodes (12): LightCrawler, OutOfScopeError, SafeHttpClient, ContentDiscoveryModule, HttpMethodsModule, XssModule, test_chaos_infinite_redirect_loop(), test_content_discovery_phpinfo_and_admin() (+4 more)

### Community 5 - "steps"
Cohesion: 0.08
Nodes (24): jobs, test, python-version, name, on, pull_request, push, branches (+16 more)

### Community 9 - "test_fuzz_properties.py"
Cohesion: 0.06
Nodes (22): api_user(), debug_error(), env_file(), git_head(), index(), login(), open_redirect(), product() (+14 more)

### Community 13 - "Finding"
Cohesion: 0.07
Nodes (14): run_programmatic_audit(), Finding, ScanResult, ScanStats, ScoreResult, SecurityScanner, SecurityScorer, test_property_scorer_monotonicity() (+6 more)

## Knowledge Gaps
- **1 isolated node(s):** `websec-auditor`
  These have ≤1 connection - possible missing edges. (Counts symbols only; 235 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **25 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Target` connect `ScanConfig` to `models.py`, `respx`, `cli.py`, `SafeHttpClient`, `test_fuzz_properties.py`, `ExposedFilesModule`, `Finding`?**
  _High betweenness centrality (0.125) - this node is a cross-community bridge._
- **Are the 61 inferred relationships involving `ScanConfig` (e.g. with `run_programmatic_audit()` and `scan_command()`) actually correct?**
  _`ScanConfig` has 61 INFERRED edges - model-reasoned connections that need verification._
- **What connects `websec-auditor` to the rest of the system?**
  _1 weakly-connected nodes found - possible missing edges._
- **Should `models.py` be split into smaller, more focused modules?**
  _Cohesion score 0.05763239875389408 - nodes in this community are weakly interconnected._
- **Why does `ScanConfig` connect `ScanConfig` to `models.py`, `respx`, `cli.py`, `SafeHttpClient`, `ExposedFilesModule`, `Finding`?**
  _High betweenness centrality (0.113) - this node is a cross-community bridge._
- **Are the 58 inferred relationships involving `Target` (e.g. with `scan_command()` and `LightCrawler`) actually correct?**
  _`Target` has 58 INFERRED edges - model-reasoned connections that need verification._
- **Should `respx` be split into smaller, more focused modules?**
  _Cohesion score 0.061683599419448475 - nodes in this community are weakly interconnected._