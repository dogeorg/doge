default: test

.PHONY: test

test:
	go test -v ./*.go
