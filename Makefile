all: check-license build generate test

GITHUB_URL=github.com/brancz/kube-audience-proxy
GOOS?=$(shell uname -s | tr A-Z a-z)
GOARCH?=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m)))
OUT_DIR=_output
BIN?=kube-audience-proxy
VERSION?=$(shell cat VERSION)
PKGS=$(shell go list ./... | grep -v /vendor/)
DOCKER_REPO?=quay.io/brancz/kube-audience-proxy

check-license:
	@echo ">> checking license headers"
	@./scripts/check_license.sh

crossbuild:
	@GOOS=darwin ARCH=amd64 $(MAKE) -s build
	@GOOS=linux ARCH=amd64 $(MAKE) -s build
	@GOOS=windows ARCH=amd64 $(MAKE) -s build

build:
	@$(eval OUTPUT=$(OUT_DIR)/$(GOOS)/$(GOARCH)/$(BIN))
	@echo ">> building for $(GOOS)/$(GOARCH) to $(OUTPUT)"
	@mkdir -p $(OUT_DIR)/$(GOOS)/$(GOARCH)
	@CGO_ENABLED=0 go build --installsuffix cgo -ldflags "-X $(GITHUB_URL)/pkg/version.Version=$(shell cat VERSION)" -o $(OUTPUT) $(GITHUB_URL)

container:
	docker build -t $(DOCKER_REPO):$(VERSION) .

test:
	@echo ">> running all tests"
	@go test -i $(PKGS)

run-curl:
	kubectl exec `kubectl get pod -lapp=kube-audience-proxy -ojson | jq -r ".items[0].metadata.name"` -c client -- /bin/sh -c "HTTPS_PROXY=http://127.0.0.1:8080/ curl --cacert /shared-ca/ca.crt  -vvvv https://kube-rbac-proxy:8443/metrics?kubernetes-audience=default.kube-rbac-proxy"

generate: build embedmd
	@echo ">> generating docs"
	@./scripts/generate-help-txt.sh
	@$(GOPATH)/bin/embedmd -w `find ./ -path ./vendor -prune -o -name "*.md" -print`

embedmd:
	@go get github.com/campoy/embedmd

.PHONY: all check-license crossbuild build container curl-container test generate embedmd
