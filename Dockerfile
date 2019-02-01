FROM golang:1.11.5-alpine
RUN mkdir /go/src/BotServer

RUN apk add git

ADD . /go/src/BotServer/
# ADD ../../gorilla/mux /go/src/github.com/
# ADD ../../gorilla/securecookie /go/src/github.com/
# ADD ../../lib/pq /go/src/github.com/
WORKDIR /go/src/BotServer

RUN go get github.com/gorilla/mux
RUN go get github.com/gorilla/securecookie
RUN go get github.com/lib/pq
RUN go install .
ENTRYPOINT [ "/go/bin/BotServer", "root", "toor" ]
# ENTRYPOINT [ "/bin/sh"]
EXPOSE 9990