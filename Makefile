# Development only: Docker environment for testing (docker/README.md).
# Not part of the published package.

COMPOSE = docker compose -f docker/compose.yml

.PHONY: up up-daemon down build test

up:
	$(COMPOSE) up

up-daemon:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

build:
	$(COMPOSE) build

# all tests including Vault, part: make test t=tests/test_jwt.py args="-k decode"
test:
	$(COMPOSE) run --rm dev pytest $(t) $(args)
