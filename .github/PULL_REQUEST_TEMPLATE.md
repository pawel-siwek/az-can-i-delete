## What this changes

<!-- One or two sentences: what, and why. -->

## Documents

<!-- Which requirement, SPEC section or ADR this implements or touches. If it
changes a normative document or supersedes a record, say so and argue for it. -->

## Checklist

- [ ] `go build ./... && go vet ./... && go test ./... && golangci-lint run ./...` is clean
- [ ] No test reaches Azure
- [ ] `README.md` and `IMPLEMENTATION-PLAN.md` claim nothing the tests do not show
- [ ] Commits are signed off (`git commit -s`, see CONTRIBUTING.md)
