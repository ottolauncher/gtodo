#export GOPATH=/c/Users/zadiv/go/pkg/mod
protoc \
    --go_out=. --go-grpc_out=. \
    -I=proto/buf/validate \
    -I=proto/buf/validate/priv \
    -I=proto \
     proto/*.proto
#    -I=${GOPATH}/google.golang.org/protobuf/src \


