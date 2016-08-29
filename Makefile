default: test build

test:
	godep go test -v ./...

build:
	godep go build

build-client:
	cd example && godep go build
