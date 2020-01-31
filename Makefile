APP=gonbserv

GOOS=linux
GOARCH=amd64

build: CGO_ENABLED:=1
build:
	go build -a -o $(APP)

build-static:
	CGO_ENABLED=0 go build -a -o $(APP)
