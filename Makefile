.PHONY: nflog2slack
nflog2slack:
	dep ensure -vendor-only
	GOOS=linux CGO_ENABLED=0 go build -o $@