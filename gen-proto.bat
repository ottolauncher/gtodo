protoc \
    --proto_path=${GOPATH}/src
    --proto_path=${GOPATH}/src/github.com/google/protobuf/src \
    --proto_path=. \
    --govalidators_out=. \
    --go_out=. --go-grpc_out=. proto/*.proto
