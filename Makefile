default: test build
test:
	godep go test ./...
build:
	godep go build
