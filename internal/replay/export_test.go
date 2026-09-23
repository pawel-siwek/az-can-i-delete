package replay

// SanitizedForTest exposes the recorder's sanitizer so a test can hold it to
// the report boundary's, which is the only thing keeping them one rule.
func SanitizedForTest(s string) string { return sanitize(s) }
