# build stage
FROM golang:alpine AS build-env
RUN apk --no-cache add build-base git bzr mercurial gcc
ADD . /src
RUN cd /src/cmd/microbro && go build -o microman
# final stage
FROM alpine
WORKDIR /app
COPY --from=build-env /src/cmd/microbro/mircroman /app/
ENTRYPOINT ./microman
