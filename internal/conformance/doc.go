// Package conformance holds the decision records' Enforcement sections as
// tests.
//
// Every record in docs/adr names what makes it real. For most of them that is
// a behavioural test elsewhere in the tree. For the rest — the ones that say
// "this must never appear anywhere" — there was nothing but a reviewer's
// attention, which is the least reliable enforcement there is. These tests
// read the source and fail when a constraint stops holding, so a pull request
// does not need anybody's judgement to catch a clock read in the verdict
// engine or a key acquisition in a collector.
//
// They are deliberately literal. A test here reports what it found and names
// the record it comes from, so a genuine exception can be argued for in a
// pull request rather than worked around in silence.
package conformance
