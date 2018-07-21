# Require the Go compiler/toolchain to be installed
ifeq (, $(shell which go 2>/dev/null))
$(error No 'go' found in $(PATH), please install the Go compiler for your system)
endif

.DEFAULT_GOAL: generate

.PHONY: generate
generate:
	go generate

.PHONY: test
test: generate
	go test -v -race ./...

cover: cover.out
cover.out: generate
	go test -coverprofile=cover.out -covermode=atomic ./...
	go tool cover -func=cover.out

.PHONY: coverhtml
coverhtml: cover
	go tool cover -html=cover.out

.PHONY: check
check: test cover
	go vet ./...
	megacheck ./...
	golint -set_exit_status ./...

netfilter-fuzz.zip:
	go-fuzz-build github.com/ti-mo/netfilter
	mkdir -p corpus

.PHONY: fuzz
fuzz: netfilter-fuzz.zip
	go-fuzz -workdir=. -bin=netfilter-fuzz.zip
