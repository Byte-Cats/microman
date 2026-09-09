#!/usr/bin/env bash
set -e

echo "Checking dependencies and formatting..."
cd ../ && go mod tidy

unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "The following files are not gofmt'ed:"
  echo "$unformatted"
  exit 1
fi

if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run
else
  echo "golangci-lint not installed, skipping lint step"
fi

cd deploy

echo "Building Binary Executable..."
go build -o bin/ ./../cmd/microguy/;

echo "Default Config Copying to build directory..."
cp env bin/.env
echo "Build complete!";
