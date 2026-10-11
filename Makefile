BINARY := user-management
LDFLAGS := -s -w

.PHONY: dev run test build build-linux build-linux-arm provision deploy backup import-users register-app clean

# Serve templates/static from disk: edit HTML/JS/CSS and just refresh.
# Port 8100, so the tracker (8080), planner (8090) and event planner (8110) can run alongside.
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

# Backs up every app's database, on the droplet and under deploy/ansible/backups/.
backup:
	cd deploy/ansible && ansible-playbook backup.yml

# Dry run by default. For real: make import-users DRY_RUN=false [PREFER=tracker|planner]
DRY_RUN ?= true
PREFER ?=
import-users:
	cd deploy/ansible && ansible-playbook import-users.yml -e dry_run=$(DRY_RUN) -e prefer=$(PREFER)

# Registers an app (APP=events, planner or tracker; see sso_apps in
# deploy/ansible/defaults.yml) and copies its access list from the app named
# there. Dry run by default. For real: make register-app DRY_RUN=false
# ROTATE=true makes a new secret for an already-registered app (the old one
# stops working at once: redeploy the app straight away). On a Mac the secret
# is saved to the Keychain under the app's name (um-events, um-planner, ...)
# and not shown. KEYCHAIN=name overrides that; KEYCHAIN= (empty) prints it.
# APP is required: events, planner or tracker (the keys of sso_apps in
# deploy/ansible/defaults.yml).
ROTATE ?= false
register-app:
	@test -n "$(APP)" || { echo 'Set APP: make register-app APP=events|planner|tracker'; exit 1; }
	cd deploy/ansible && ansible-playbook register-app.yml -e app=$(APP) -e dry_run=$(DRY_RUN) -e rotate_secret=$(ROTATE)$(if $(filter undefined,$(origin KEYCHAIN)),, -e "keychain_service=$(KEYCHAIN)")

clean:
	rm -rf bin
