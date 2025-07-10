all: build

build:
	npm run compile

tsc: build

.PHONY: help dev build all log

help:
	@echo "Available targets:"
	@echo "  all (default) - Build the project"
	@echo "  build         - Build the project using webpack"
	@echo "  help          - Show this help message"