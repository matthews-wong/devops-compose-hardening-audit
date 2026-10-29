.PHONY: test validate

test:
	python3 -m unittest discover -s tests

# the hardened example must pass; the insecure one must fail
validate: test
	docker compose -f examples/hardened.yml config --format json | python3 audit.py
	! docker compose -f examples/insecure.yml config --format json | python3 audit.py > /dev/null
