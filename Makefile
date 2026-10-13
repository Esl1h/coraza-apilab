# coraza-apilab: nginx + Coraza WAF + OWASP CRS in front of the API
# simulator (rs-http-apilab or v-http-apilab).
#
# APILAB=rs|v picks the simulator (default rs). LAB_TOKEN must match the
# token the containers were started with (default lab-token).

APILAB ?= rs
LAB_TOKEN ?= lab-token
export APILAB LAB_TOKEN

ALLINONE := docker compose -f examples/allinone/compose.yml
SPLIT := docker compose -f examples/split/compose.yml

.PHONY: help build allinone-up allinone-down split-up split-down \
	test-allinone test-split explain-allinone explain-split \
	check audit logs down lint

help:
	@echo "allinone-up | split-up       start an example (APILAB=rs|v)"
	@echo "test-allinone | test-split   run the end-to-end WAF tests"
	@echo "explain-allinone | explain-split [CASE=...]  rules that decided each test"
	@echo "check                        compile the rule set without starting nginx"
	@echo "audit                        follow the Coraza audit log (all-in-one)"
	@echo "down                         stop both examples"
	@echo "lint                         shellcheck the scripts"

build:
	docker build --target allinone --build-arg APILAB=$(APILAB) -t coraza-apilab:allinone-$(APILAB) .
	docker build --target waf -t coraza-apilab:waf .
	docker build --target api --build-arg APILAB=$(APILAB) -t coraza-apilab:api-$(APILAB) .

allinone-up:
	$(ALLINONE) up -d --build --wait

allinone-down:
	$(ALLINONE) down

split-up:
	$(SPLIT) up -d --build --wait

split-down:
	$(SPLIT) down

test-allinone:
	BASE_URL=http://localhost:8080 tests/waf-test.sh

test-split:
	BASE_URL=http://localhost:8090 tests/waf-test.sh

explain-allinone:
	WAF_CONTAINER=coraza-apilab tests/explain.sh $(CASE)

explain-split:
	WAF_CONTAINER=coraza-apilab-waf tests/explain.sh $(CASE)

# Compiles coraza/ from the working tree with the image's libcoraza:
# catches rule syntax errors before a container is started.
check:
	docker build -q --target waf -t coraza-apilab:waf . >/dev/null
	docker run --rm --entrypoint /usr/local/bin/coraza-check coraza-apilab:waf /etc/nginx/coraza/main.conf

audit:
	docker exec coraza-apilab tail -f /var/log/coraza/audit.log | jq -c '{id: .transaction.id, status: .transaction.response.status, uri: .transaction.request.uri, rules: [.messages[]?.data.id]}'

logs:
	docker logs -f coraza-apilab

down: allinone-down split-down

lint:
	shellcheck tests/*.sh docker/*.sh
