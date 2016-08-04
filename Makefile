default: gen-def-files build
gen-def-files:
	make -C ./gui/definitions
build:
	go build
