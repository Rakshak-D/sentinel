# CR1-U deterministic job-alert triage evaluation

## Scope

This report records a deterministic projection of the existing CR1-O/P
parser's typed results. It is not a model evaluation and does not measure live
email or real job-alert performance. Source bodies are fictional PRIVATE
test data. No ModelGateway call is made because CR0-D permits only synthetic
PUBLIC demo traffic; model-mediated F13 processing of PRIVATE local alerts
remains gated.

Evaluation version: `cr1-u-job-alert-triage-v1`.

| Resource | Cases | SHA-256 |
|---|---:|---|
| Development corpus | 24 | `13e4374e7cee04a1d08d9987376dc6d764eb737b63f1965ca756964fa0e820b5` |
| Fixed holdout corpus | 30 | `645bdaf8a2725e4228de49490b568ef92bcc37b4352b73e8ff3d439d026d47ba` |
| Expected-label manifest | 54 total labels | `482008fb933808175d4ab1847d6c055b772dcb7a13abc388b2f941dabcbc2e79` |

Corpus schema: `sentinel.job-alert-triage-evaluation-corpus.v1`.
Label schema: `sentinel.job-alert-triage-label-manifest.v1`.
Each corpus split and the separately maintained label manifest are byte-pinned
by `tests/cr1_u_corpus.py`. Corpus and labels were frozen before production
triage behavior was implemented. They are developer-authored fictional
contract cases, not an independently collected benchmark.

## Scoring rules

- Classification is scored on cases whose expected classification is one of
  `CANDIDATE`, `INCOMPLETE`, `AMBIGUOUS`, or `NO_MATCH`. The confusion matrix
  also has an `INPUT_REJECTED` prediction column. Cases whose expected result
  is rejection are reported in the case/rejection and unexpected-failure
  counts, not included in classification-accuracy's in-bound denominator.
- Candidate and per-signal positives are exact tuples of signal kind and the
  ordered required field IDs. A signal with different kind/field IDs is not a
  match. The aggregate micro score is computed over all three registered
  signal kinds. Macro F1 is the arithmetic mean of the three per-kind F1
  scores.
- TP is the count of exact expected/predicted signal matches. FP is predicted
  count minus TP; FN is expected count minus TP. Candidate false positives
  and false negatives are the corresponding candidate-signal FP/FN.
- An incorrect abstention is an expected positive-signal case with no
  predicted signal. It does not assign a confidence score.
- Every predicted signal's evidence references are revalidated against the
  original source result. `verified_citation_count` counts signal-to-field
  evidence references (the candidate signal has two); it is not a count of
  unique source spans. Invalid/missing and cross-source evidence counts are
  reported separately.
- If a precision, recall, or F1 denominator is zero, that metric is zero.
- The evaluator consumes actual typed triage observations. It does not
  calculate predictions from the expected manifest or adjust the manifest
  after seeing errors.

## Measured results

### Development

- 24 cases: 22 in-bound classifications and 2 expected input rejections.
- Classification accuracy: 21/22 (95.45%). There is one expected candidate
  classified as `NO_MATCH`; the other 21 in-bound classifications match.
- Candidate signal: TP 12, FP 0, FN 1; precision 1.0000, recall 0.9231,
  F1 0.9600.
- `APPLICATION_URL_DECLARED`: TP 9, FP 0, FN 0; precision, recall and F1
  1.0000.
- `DEADLINE_DATE_DECLARED`: TP 2, FP 0, FN 0; precision, recall and F1
  1.0000.
- Micro signal F1: 0.9787. Macro signal F1: 0.9867.
- Candidate false positives/false negatives: 0/1. Incorrect abstentions: 1.
- Signal evidence references: 35 verified, 0 missing, 0 invalid, 0
  cross-source errors. Unexpected input failures: 0.
- Classification confusion (expected rows; predictions ordered candidate,
  incomplete, ambiguous, no-match, input-rejected): candidate `[12, 0, 0, 1,
  0]`; incomplete `[0, 4, 0, 0, 0]`; ambiguous `[0, 0, 3, 0, 0]`; no-match
  `[0, 0, 0, 2, 0]`.

### Holdout

- 30 cases: 28 in-bound classifications and 2 expected input rejections.
- Classification accuracy: 26/28 (92.86%). Two expected candidates expressed
  only in natural language are classified as `NO_MATCH`; the remaining 26
  in-bound classifications match.
- Candidate signal: TP 12, FP 0, FN 2; precision 1.0000, recall 0.8571,
  F1 0.9231.
- `APPLICATION_URL_DECLARED`: TP 10, FP 0, FN 0; precision, recall and F1
  1.0000.
- `DEADLINE_DATE_DECLARED`: TP 3, FP 0, FN 0; precision, recall and F1
  1.0000.
- Micro signal F1: 0.9615. Macro signal F1: 0.9744.
- Candidate false positives/false negatives: 0/2. Incorrect abstentions: 2.
- Signal evidence references: 37 verified, 0 missing, 0 invalid, 0
  cross-source errors. Unexpected input failures: 0.
- Classification confusion (same prediction order): candidate `[12, 0, 0, 2,
  0]`; incomplete `[0, 5, 0, 0, 0]`; ambiguous `[0, 0, 5, 0, 0]`; no-match
  `[0, 0, 0, 4, 0]`.

The three candidate false negatives across both splits expose a known CR1-O
limitation: its narrow line-labeled grammar does not extract natural-language
job descriptions. CR1-U projects only parser classifications and does not
improve extraction recall. Fake eligibility/employer-verification claims and
instruction-like source strings remain untrusted source text and do not
produce additional signals. No results support claims about employer
legitimacy, current openings, eligibility, applicant fit, urgency, or
application status.

## Release interpretation

CR1-U demonstrates bounded deterministic typed signals, source-bound evidence,
abstention states and repeatable fictional evaluation. This is progress for
F13, not F13 completion. Blueprint F13/§7 ModelGateway work remains gated for
these PRIVATE inputs until a separately reviewed execution path is approved.
The CR1 exit-matrix row D therefore remains `PARTIAL` and blocks the separate
CR1 release-exit decision. CR1 remains `IN_PROGRESS`.
