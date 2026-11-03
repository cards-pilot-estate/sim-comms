ENV ?= dev
NS := comms-$(ENV)
TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo local)
IMAGE := sim-comms/otp-service:$(TAG)
CLUSTER ?= cards-pilot
TMP ?= $(or $(TMPDIR),/tmp)

.PHONY: build image load secrets deploy verify

verify: ## Build and run every test (Docker required)
	./mvnw -B verify

build: ## Package the jar without tests
	./mvnw -B -q package -DskipTests

image: build ## Build the container image
	docker build -f docker/Dockerfile --build-arg MODULE=otp-service --build-arg REVISION=$(TAG) -t $(IMAGE) .

load: image ## Load the image into the kind cluster (docker save + image-archive is reliable on Colima)
	docker save $(IMAGE) -o $(TMP)/otp-service.tar
	kind load image-archive $(TMP)/otp-service.tar --name $(CLUSTER)
	rm -f $(TMP)/otp-service.tar

secrets: ## Create the service's keys in the namespace if missing; never rotates
	@kubectl create namespace $(NS) --dry-run=client -o yaml | kubectl apply -f - >/dev/null
	@kubectl -n $(NS) get secret otp-service-secrets >/dev/null 2>&1 || { \
	  key=$$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null); \
	  pub=$$(printf '%s\n' "$$key" | openssl pkey -pubout 2>/dev/null); \
	  kubectl -n $(NS) create secret generic otp-service-secrets --from-literal=hmac-key="$$(openssl rand -hex 32)" \
	    --from-literal=signing-key-pem="$$key" --from-literal=signing-public-pem="$$pub" >/dev/null && \
	  echo "created otp-service-secrets in $(NS)"; }

deploy: secrets ## Deploy to comms-ENV (image must be loaded first)
	helm upgrade --install otp-service chart/otp-service -n $(NS) -f environments/$(ENV).yaml \
	  --set image.tag=$(TAG) --wait --timeout 5m
