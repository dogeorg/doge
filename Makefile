default: test

.PHONY: test

test:
	go test -v ./*.go
	go test -v ./bip39/test/*.go
