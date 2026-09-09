# build stage
FROM golang:1.26.8-alpine3.24 AS build-env
RUN apk --no-cache add build-base git bzr mercurial gcc
ADD . /src
RUN cd /src/cmd/microguy && go build -o microman

# final stage
FROM alpine:3.24.1
WORKDIR /app
COPY --from=build-env /src/cmd/microguy/microman /app/
ENTRYPOINT ./microman
