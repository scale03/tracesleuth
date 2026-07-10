.PHONY: build test vet policy fmt-policy demo tamper all clean

BIN := bin

build:
	go build -o $(BIN)/tracectl ./cmd/tracectl
	go build -o $(BIN)/verify-chain ./cmd/verify-chain
	go build -o $(BIN)/tracesleuth-mcp ./cmd/tracesleuth-mcp

test:
	TRACESLEUTH_EXECUTOR=mock go test ./... -count=1

vet:
	go vet ./...

policy:
	opa test ./policy/ -v

fmt-policy:
	opa fmt --list policy/   # prints offending files; empty == clean

demo: build
	TRACESLEUTH_EXECUTOR=mock bash scripts/demo.sh

tamper: build
	bash scripts/tamper_test.sh

all: build vet test policy

clean:
	rm -rf $(BIN) data
