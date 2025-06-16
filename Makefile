APP_NAME=mshark

all: build

.PHONY: build
build: 
	CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go

.PHONY: setcap
setcap:
	sudo setcap cap_net_raw+ep ./bin/${APP_NAME}

mshark.test:
	go test -c  -race && sudo setcap cap_net_raw+ep mshark.test

.PHONY: bench
bench: mshark.test
	./mshark.test -test.bench=. -test.benchmem -test.run=^$$ -test.benchtime 1000x \
	-test.cpuprofile='cpu.prof' -test.memprofile='mem.prof'

.PHONY: benchall
benchall:
	for package in $$(go list ./... | tail -n +2); do \
	go test $${package} -bench=. -benchmem -run=^$$ -benchtime 1000x \
	-cpuprofile="$$(basename $${package})/cpu.prof" -memprofile="$$(basename $${package})/mem.prof"; done

.PHONY: test
test:
	go test ./... -v -count=1 

.PHONY: test100
test100:
	go test ./... -count=100 

.PHONY: race
race:
	go test ./... -v -race -count=1 

.PHONY: cover
cover:
	go test ./... -short -count=1 -race -coverprofile=coverage.out
	go tool cover -html=coverage.out
	rm coverage.out

.PHONY: clean
clean:
	find ./bin ! -name '.gitignore' -type f -exec rm -vrf {} +
	rm -v *.txt *.pcap*
