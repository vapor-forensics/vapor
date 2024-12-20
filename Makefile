include custom.mk

setup-env:
	@[ ! -f ./.env ] && cp ./.env.example ./.env || echo ".env file already exists."

start: ## Start the docker containers
	@echo "Starting the docker containers"
	@docker compose up

stop: ## Stop Containers
	@docker compose down

restart: stop start ## Restart Containers

start-bg:  ## Run containers in the background
	@docker compose up -d

build: ## Build Containers
	@docker compose build

ssh: ## SSH into running web container
	docker compose exec web bash

bash: ## Get a bash shell into the web container
	docker compose run --rm --no-deps web bash

manage: ## Run any manage.py command. E.g. `make manage ARGS='createsuperuser'`
	@docker compose run --rm web python manage.py ${ARGS}

migrations: ## Create DB migrations in the container
	@docker compose run --rm web python manage.py makemigrations

migrate: ## Run DB migrations in the container
	@docker compose run --rm web python manage.py migrate

shell: ## Get a Django shell
	@docker compose run --rm web python manage.py shell

dbshell: ## Get a Database shell
	@docker compose exec db psql -U postgres vapor_forensics

test: ## Run Django tests
	@docker compose run --rm web python manage.py test ${ARGS}

init: setup-env start-bg migrations migrate  ## Quickly get up and running (start containers and migrate DB)

pip_compile_cmd = uv pip compile --no-emit-package setuptools --no-strip-extras
pip-compile: ## Compiles your requirements.in file to requirements.txt
	@docker compose run --rm --no-deps web $(pip_compile_cmd) requirements/requirements.in -o requirements/requirements.txt
	@docker compose run --rm --no-deps web $(pip_compile_cmd) requirements/dev-requirements.in -o requirements/dev-requirements.txt
	@docker compose run --rm --no-deps web $(pip_compile_cmd) requirements/prod-requirements.in -o requirements/prod-requirements.txt

requirements: pip-compile build stop start-bg  ## Rebuild your requirements and restart your containers

npm-install: ## Runs npm install in the container
	@docker compose run --rm --no-deps web npm install $(filter-out $@,$(MAKECMDGOALS))

npm-uninstall: ## Runs npm uninstall in the container
	@docker compose run --rm --no-deps web npm uninstall $(filter-out $@,$(MAKECMDGOALS))

npm-build: ## Runs npm build in the container (for production assets)
	@docker compose run --rm --no-deps web npm run build

npm-dev: ## Runs npm dev in the container
	@docker compose run --rm --no-deps web npm run dev

npm-watch: ## Runs npm watch in the container (recommended for dev)
	@docker compose run --rm --no-deps web npm run dev-watch

npm-type-check: ## Runs the type checker on the front end TypeScript code
	@docker compose run --rm --no-deps web npm run type-check

upgrade: requirements migrations migrate npm-install npm-dev

.PHONY: help
.DEFAULT_GOAL := help

help:
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# catch-all for any undefined targets - this prevents error messages
# when running things like make npm-install <package>
%:
	@:
