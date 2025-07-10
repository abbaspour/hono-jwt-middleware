all: build

build:
	npm run build

tsc: build

test:
	npm run test

keypair:
	openssl genrsa -out private.pem 2048
	openssl pkcs8 -topk8 -nocrypt -in private.pem -out pkcs8_private.pem
	openssl pkey -in pkcs8_private.pem -pubout -out public.pem

.PHONY: help tsc test

help:
	@echo "Available targets:"
	@echo "  all (default) - Build the project"
	@echo "  build         - Build the project using webpack"
	@echo "  test          - Run unit test	"
	@echo "  help          - Show this help message"