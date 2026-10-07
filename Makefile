BINARY := user-management
LDFLAGS := -s -w

.PHONY: dev run test build build-linux build-linux-arm clean

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

clean:
	rm -rf bin
