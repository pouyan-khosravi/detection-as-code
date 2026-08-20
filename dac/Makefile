.PHONY: install check test build all clean

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

check:
	sigma check detections/

test:
	pytest tests/ -v

build:
	./scripts/build.sh

all: check test build

clean:
	rm -rf build .pytest_cache tests/__pycache__
