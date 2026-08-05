# TYPO3 Scanner — Makefile
# Run `make help` for the target list.

BIN     := t3scan
PKG     := ./cmd/t3scan
DB      := pkg/t3finger/db.json
EXTDB   := pkg/t3finger/data/extension-db.json.gz
WL      := pkg/t3finger/data/extensions.txt
PREFIX  ?= /usr/local
GOFLAGS ?=
MIN     ?= 10.0.0      # oldest major to include in `make db`
EXTC    ?= 14          # concurrent downloads for the extension DB build

.DEFAULT_GOAL := build

## build: compile the t3scan binary (embeds db.json + the extension wordlist)
.PHONY: build
build:
	go build $(GOFLAGS) -o $(BIN) $(PKG)

## install: install t3scan into $(PREFIX)/bin
.PHONY: install
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

## fmt: gofmt all sources
.PHONY: fmt
fmt:
	gofmt -w pkg cmd

## vet: go vet
.PHONY: vet
vet:
	go vet ./...

## test: run unit tests
.PHONY: test
test:
	go test ./...

## check: vet + build + gofmt-clean (CI gate)
.PHONY: check
check: vet build
	@test -z "$$(gofmt -l pkg cmd)" || { echo "gofmt needed:"; gofmt -l pkg cmd; exit 1; }
	@echo "ok"

# ---- data building (writes then re-embed with `make build`) ----

## db: (re)build the version fingerprint DB from official releases (MIN=10.0.0)
.PHONY: db
db:
	go run $(PKG) builddb -min $(MIN) -o $(DB)

## db-full: like db, but hash the whole Resources/Public tree (bigger, deeper)
.PHONY: db-full
db-full:
	go run $(PKG) builddb -min $(MIN) -full -o $(DB)

## wordlist: refresh both bundled extension lists (Packagist names + TER keys)
.PHONY: wordlist
wordlist:
	go run $(PKG) buildwordlist
	go run $(PKG) buildwordlist -keys

## advisories: refresh the bundled TYPO3 core CVE advisory set
.PHONY: advisories
advisories:
	go run $(PKG) buildadvisories

## extdb: (re)build the extension DB for the common seed list (fast, ~1 min)
.PHONY: extdb
extdb:
	go run $(PKG) buildextdb -o $(EXTDB)

## extdb-full: (re)build the COMPLETE extension DB — every TER plugin+theme,
##             all versions, static-file hashes + dependencies (~1h, heavy)
.PHONY: extdb-full
extdb-full:
	go run $(PKG) buildextdb -all -c $(EXTC) -o $(EXTDB)

## extdb-update: resume/extend the existing extension DB (merge new data in)
.PHONY: extdb-update
extdb-update:
	go run $(PKG) buildextdb -all -c $(EXTC) -merge -o $(EXTDB)

## db-rebuild: rebuild the version DB then re-embed it into the binary
.PHONY: db-rebuild
db-rebuild: db build

## data: refresh EVERY bundled dataset, then rebuild the binary to embed them
.PHONY: data
data: wordlist advisories db extdb-full build
	@echo "all datasets rebuilt and embedded"

# ---- convenience ----

## run: detect a target — make run URL=https://example.com/
.PHONY: run
run: build
	@test -n "$(URL)" || { echo "usage: make run URL=https://host/"; exit 2; }
	./$(BIN) -v $(ARGS) $(URL)

## ext: enumerate extensions — make ext URL=https://example.com/
.PHONY: ext
ext: build
	@test -n "$(URL)" || { echo "usage: make ext URL=https://host/"; exit 2; }
	./$(BIN) extensions $(ARGS) $(URL)

## clean: remove the built binary
.PHONY: clean
clean:
	rm -f $(BIN)

## help: list targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
