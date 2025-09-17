SHELL=bash
BINPATH ?= build
GIT_PATH=github.com/ONSdigital/dis-vulncheck

.PHONY: build
build: ## Builds a binary to run the code
	go build -o $(BINPATH)/dis-vulncheck

.PHONY: install
install: ## Installs package locally
	go install $(GIT_PATH)

.PHONY: debug
debug: ## Run in debug mode
	go run -race main.go --verbose

.PHONY: test
test: ## Run the go tests
	go test -race -cover ./...

.PHONY: audit 
audit: ## Run audit checks against the code
	dis-vulncheck

.PHONY: lint
lint: ## Run go linter
	golangci-lint run ./...

.PHONY: help
help: ## Show help page for list of make targets
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "    ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)

