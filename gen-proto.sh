export GOPATH=/c/Users/zadiv/go
protoc \
    --go_out=. --go-grpc_out="$GOPATH"/src \
    -I=proto/ \
     $(find proto/** -iname "*.proto")



