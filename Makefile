.PHONY: build vet fmt unit-tests functional-tests

build:
	go build ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

unit-tests:
	go test ./...

# There is no meaningful distinction yet between "unit" and "functional" tests
# in this codebase — everything lives under `go test ./...`. This target is
# wired to Jenkinsfile's `make functional-tests` step so CI doesn't break; it
# intentionally just re-runs the same suite rather than faking a separate
# functional-test suite that doesn't exist.
functional-tests:
	go test ./...
