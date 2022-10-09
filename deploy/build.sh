echo "Checking dependencies and formatting..."
cd ../ && go mod tidy && go mod vendor &&  gofmt ./ && golangci-lint run && cd deploy ;

echo "Building Binary Executable..."
go build -o bin/ ./../cmd/microbro/;

echo "Default Config Copying to build directory..."
cp env bin/.env
echo "Build complete!";
