BINARY := user-management
LDFLAGS := -s -w

.PHONY: dev run test build build-linux build-linux-arm provision deploy backup import-users clean

# Serve templates/static from disk: edit HTML/JS/CSS and just refresh.
# Port 8100, so the tracker (8080) and planner (8090) can run alongside.
dev:
	DEV=1 go run . -addr 127.0.0.1:8100

run: build
	./bin/$(BINARY)

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) .

# Digital Ocean droplets / most home-lab servers
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 .

# Raspberry Pi 4/5 and other ARM boxes
build-linux-arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64 .

# DigitalOcean droplet via Ansible: see "Deploying" in the README.
provision:
	cd deploy/ansible && ansible-playbook provision.yml

deploy:
	cd deploy/ansible && ansible-playbook deploy.yml

# Backs up all three apps' databases, on the droplet and under deploy/ansible/backups/.
backup:
	cd deploy/ansible && ansible-playbook backup.yml

# Dry run by default. For real: make import-users DRY_RUN=false [PREFER=tracker|planner]
DRY_RUN ?= true
PREFER ?=
import-users:
	cd deploy/ansible && ansible-playbook import-users.yml -e dry_run=$(DRY_RUN) -e prefer=$(PREFER)

clean:
	rm -rf bin
