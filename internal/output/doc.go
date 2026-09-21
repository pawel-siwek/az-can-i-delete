// Package output is the schemaVersion 2 report trust boundary.
//
// Build accepts Input containing a normalized verdict.Input plus report metadata
// and calls verdict.Evaluate itself. It does not collect, classify, infer missing
// signals, or add verdict gates. An evaluation or boundary failure returns no
// Report. Report has private immutable storage; JSON, MarshalJSON and Value expose
// only the sanitized representation, with Value returning a detached copy using
// json.Number to preserve integer precision.
//
// Config and SignalPolicy are trusted code/embedded-rule definitions, NEVER
// provider data. Policies authorize each detail key and representation separately
// and supply curated summaries, human questions, caveats, next steps and exact
// notEvaluated text. Without policy, closed rule-ID/status templates apply. Raw
// summaries, next steps and provider error messages are not templates. Undeclared
// scalar details are omitted with quarantine notices; undeclared non-sensitive
// structures fail explicitly. Setting/tag containers and unclassified legacy
// metadata are omitted, including their keys. Numeric custom marshalers cannot
// cross the boundary.
//
// Azure freeform text exists only under untrusted. Sanitization drops invalid
// UTF-8 bytes and Cc/Cf/Cs/Co/Cn, normalizes NFC, then caps at 128 Unicode runes,
// including the ellipsis. URLs are replaced with a fixed marker. Typed ARM IDs
// are parsed strictly without portal URLs or queries; relative operation paths
// need explicit trusted suffixes. IDs remain untrusted instruction content even
// when accepted as identity data. GUIDs and UTC timestamps have separate typed
// validation. Names and resource groups use tool-owned display references.
//
// App-setting values have no input field. Known values smuggled through legacy
// metadata or setting containers are also suppressed from copied metadata.
// Key/value assignments presented as setting keys are omitted. No boundary can
// recover provenance if a caller lies about an otherwise valid key; collectors
// must supply actual keys, never preformatted key/value pairs or secrets.
//
// BuildForMCP forces tag redaction before either JSON or Value is available.
// Redaction also suppresses known values copied into other freeform fields and
// omits quarantine payloads. If a known secret overlaps a typed identity or fixed
// output text, Build fails rather than corrupting identity or emitting the value.
// Legacy tag values are never emitted; non-redacted CLI callers must use
// Metadata.Tags. These deliberately conservative failures require integration
// handling, not a catch-and-default assessment.
//
// Render accepts only sealed Outcomes. JSON/JSONC, YAML, table and TSV contain
// the same complete report; the table is a wrapped field/value view, not a
// verdict-only summary. none suppresses results but returns explicit failures.
// ExitCode implements G3 separately, retaining input order and every outcome.
// Empty input is nothing-evaluable; a zero Report/Outcome is never a verdict.
//
// Dependencies are pinned: x/text v0.41.0 supplies NFC without requiring a newer
// Go toolchain; yaml.v3 v3.0.1 supplies YAML encoding. The CLI uses x/term v0.45.0
// for real terminal detection. All retain Go 1.25; x/sys is transitive to x/term.
// No analyzer, MCP server, Azure client or mutation command is implemented here.
package output
