PY ?= python3
export PYTHONPATH := src:tests

.PHONY: test demo clean
test:
	$(PY) -m unittest discover -s tests -v

demo:
	PYTHONPATH=src $(PY) -m sentinel demo --workdir demo_out

clean:
	rm -rf demo_out reports sentinel.db tokens.json data/synthetic
