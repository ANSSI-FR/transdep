.PHONY: all

all: transdep webserver

transdep: transdep.go
	go build transdep.go

webserver: webserver.go
	go build webserver.go

