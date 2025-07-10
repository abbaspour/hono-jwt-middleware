all: build

build:
	npm run build

tsc: build

test:
	npm run test

.PHONY: help tsc test

help:
	@echo "Available targets:"
	@echo "  all (default) - Build the project"
	@echo "  build         - Build the project using webpack"
	@echo "  test          - Run unit test	"
	@echo "  help          - Show this help message"