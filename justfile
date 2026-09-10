# list available recipes
default:
    @just --list

# build
build:
    go build ./...

# test
test:
    go test ./...

# test with a coverage profile
cover:
    go test -coverprofile=coverage.out -covermode=atomic ./...

# lint
lint:
    golangci-lint run ./...

# format
fmt:
    golangci-lint fmt ./...

# check the package dependency rules in arch-go.yml
arch:
    go run github.com/arch-go/arch-go@v1.7.0

# describe the package dependency rules in prose
arch-describe:
    go run github.com/arch-go/arch-go@v1.7.0 describe

# check that package doc comments live in doc.go
doccheck:
    bash scripts/check-doc-comments.sh

# check prose style: no em-dashes outside the license file
prose:
    #!/usr/bin/env bash
    emdash=$(printf '\342\200\224')
    if git grep -n "$emdash" -- ':!LICENSE'; then
        echo "em-dashes found, replace them (see CLAUDE.md prose rules)"
        exit 1
    fi

# check for known vulnerabilities in reachable code
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# one-time dev setup after cloning: git hooks
setup: hooks

# install the git hooks
hooks:
    lefthook install

# everything that must pass before a push
ci: lint prose doccheck arch build test vuln
