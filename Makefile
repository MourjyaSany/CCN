# =============================================================================
# NetShield-GNN — convenience targets (thin wrappers over run.sh / scripts/)
# =============================================================================
PYTHON ?= python
SHELL  := /bin/bash

.DEFAULT_GOAL := help
.PHONY: help setup dataset dataset-quick train experiments evaluate fuzz \
        dashboard demo test lint clean all docker docker-run report

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup:         ## Check dependencies, create directories, init the database
	./run.sh setup

dataset:       ## Generate the labelled corpus (~6 min)
	$(PYTHON) scripts/generate_dataset.py --reuse

dataset-quick: ## Generate a reduced corpus for a fast smoke run
	$(PYTHON) scripts/generate_dataset.py --quick

train:         ## Train threshold, Random Forest and GraphSAGE
	$(PYTHON) scripts/train_models.py

experiments:   ## Run Experiments 1-8
	$(PYTHON) scripts/run_experiment.py --all

evaluate:      ## Compute metrics, render figures, write RESULTS.md
	$(PYTHON) scripts/evaluate.py

fuzz:          ## Run a fuzzing campaign (CAMPAIGN=rate_sweep)
	$(PYTHON) scripts/fuzz.py --campaign $(or $(CAMPAIGN),rate_sweep)

dashboard:     ## Serve the API and dashboard on :8000
	./run.sh dashboard

demo:          ## ~2-minute live demonstration
	$(PYTHON) scripts/demo.py

test:          ## Run the automated test suite
	$(PYTHON) -m pytest -q

lint:          ## Lint (requires ruff)
	ruff check src scripts tests || true

report:        ## Open the generated results report
	@cat results/reports/RESULTS.md

all:           ## setup -> dataset -> train -> experiments -> evaluate
	$(MAKE) setup && $(MAKE) dataset && $(MAKE) train \
	  && $(MAKE) experiments && $(MAKE) evaluate

docker:        ## Build the container image
	docker compose build

docker-run:    ## Run the dashboard in Docker
	docker compose up

clean:         ## Remove generated artefacts
	./run.sh clean
