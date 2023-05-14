SOURCES := $(wildcard *.go cmd/*/*.go pkg/*/*/*.go)

# ==================================================================================== #
# HELPERS
# ==================================================================================== #

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: confirm
confirm:
	@echo -n 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]

# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## startdb: run a postgres db container 
.PHONY: startdb
startdb:
	docker run \
		--name greenlight_db \
		-p 5432:5432 \
		-v chitchat_db-data:/var/lib/postgresql/data \
		-e POSTGRES_USER=postgres \
		-e POSTGRES_PASSWORD=654321 \
		-e POSTGRES_DB=greenlight \
		-d postgres:15-alpine

## createdb: create a database with the username postgres, owner postgres and database name greenlight in the greenlight_db container
.PHONY: createdb
createdb:
	docker exec -it chitchat_db createdb --username=postgres --owner=postgres chitchat

## dropdb: drop a database with the username postgres, owner postgres and database name greenlight in the greenlight_db container
.PHONY:	dropdb
dropdb:
	docker exec -it chitchat_db dropdb chitchat

## migrateup: apply all up database migrations
.PHONY: migrateup
migrateup: confirm
	@echo 'Running up migrations...'
	migrate -path=./migrations -database=${CHITCHAT_DB_DSN} -verbose up

## migratedown: apply all down database migrations
.PHONY: migratedown
migratedown:
	@echo 'Running down migrations...'
	migrate -path=./migrations -database=${CHITCHAT_DB_DSN} -verbose down

## run: run the cmd/api application
.PHONY: run
run:
	@echo 'starting chitchat application'
	@go run ./cmd/api -jwt-secret=${JWT_SECRET}

## docker/compose/up: start containers in chitchat.yaml file
.PHONY: docker/compose/up
docker/compose/up:
	@echo 'starting chitchat containers'
	docker-compose -f chitchat.yaml up -d

## docker/compose/down: stop and remove all running containers in chitchat.yaml file
.PHONY: docker/compose/down
docker/compose/down:
	@echo 'stop and remove chitchat containers'
	docker-compose -f chitchat.yaml down

## migration name=$1: create a new database migration file
.PHONY: migration
migration:
	@echo 'Creating migration files for ${name}...'
	migrate create -seq -ext=.sql -dir=./migrations ${name}

## tests: runs test code coverage
.PHONY: tests
tests:
	@echo 'running tests cover'
	go test ./cmd/api -cover

# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## audit: tidy and vendor dependencies and format, vet and test all code
.PHONY: audit
audit: vendor
	@echo 'Formatting code...'
	go fmt ./...
	@echo 'Vetting code...'
	go vet ./...
	staticcheck ./...
	@echo 'Running tests...'
	go test -race -vet=off ./...

## vendor: tidy and vendor dependencies
.PHONY: vendor
vendor:
	@echo 'Tidying and verifying module dependencies...'
	go mod tidy
	go mod verify
	@echo 'Vendoring dependencies...'
	go mod vendor

# ==================================================================================== #
# BUILD
# ==================================================================================== #

current_time = $(shell date --iso-8601=seconds)
git_description = $(shell git describe --tags --long --dirty --always 2>/dev/null)
ifeq ($(git_description),)
	git_description = UNKNOWN
endif
linker_flags = '-s -X main.buildTime=${current_time} -X main.version=${git_description}'

## build/api: build the cmd/api application
.PHONY: build/api
build/api:
	@echo 'Building cmd/api...'
	go build -ldflags=${linker_flags} -o=./bin/api ./cmd/api
	GOOS=linux GOARCH=amd64 go build -ldflags=${linker_flags} -o=./bin/linux_amd64/api ./cmd/api

# ==================================================================================== #
# Docker
# ==================================================================================== #

## docker: build the docker image
.PHONY: docker
docker: $(SOURCES) Dockerfile
	@echo 'Building docker image...'
	docker build -t chitchat:latest -f Dockerfile --build-arg VERSION=$(git_description) --build-arg BUILDTIME=$(current_time) .

.PHONY: publish
publish:
	docker tag chitchat:latest ifedayoawe/chitchat:latest
	docker push ifedayoawe/chitchat:latest

.PHONY: help startdb createdb dropdb migrateup migratedown confirm run docker/compose/up docker/compose/down migration vendor build/api tests
