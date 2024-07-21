package models

import (
        "context"
        "encoding/json"
        "fmt"
        "github.com/pkg/errors"
        "google.golang.org/protobuf/proto"
        "google.golang.org/protobuf/types/known/anypb"
        "google.golang.org/protobuf/types/known/wrapperspb"
)

type Manager[T any] interface {
        Create(ctx context.Context, v interface{}) (*T, error)
        Bulk(ctx context.Context, v interface{}) ([]*T, error)
        Update(ctx context.Context, v interface{}) (*T, error)
        Delete(ctx context.Context, filter *wrapperspb.BytesValue) error
        DeleteByID(ctx context.Context, id string) error
        Get(ctx context.Context, filter *wrapperspb.BytesValue) (*T, error)
        GetByID(ctx context.Context, id string) (*T, error)
        All(ctx context.Context, any *wrapperspb.BytesValue, limit, page int64) ([]*T, error)
        Search(ctx context.Context, q string, limit, page int64) ([]*T, error)
}

func ConvertInterfaceToAny(v interface{}) (*anypb.Any, error) {
        pv, ok := v.(proto.Message)
        if !ok {
                return &anypb.Any{}, fmt.Errorf("%v is not proto.Message", pv)
        }
        anyValue := &anypb.Any{}
        bytes, _ := json.Marshal(v)
        bytesValue := &wrapperspb.BytesValue{Value: bytes}
        err := anypb.MarshalFrom(anyValue, bytesValue, proto.MarshalOptions{})
	return anyValue, err
}

func ConvertAnyToInterface(anyValue *anypb.Any) (interface{}, error) {
        var value interface{}
        if len(anyValue.Value) == 0 {
                return value, nil
        }

        bytesValue := &wrapperspb.BytesValue{}

        if err := anypb.UnmarshalTo(anyValue, bytesValue, proto.UnmarshalOptions{}); err != nil {
                return value, errors.Wrapf(err, "while using UnmarshalTo function")
        }
        if uErr := json.Unmarshal(bytesValue.Value, &value); uErr != nil {
                return value, errors.Wrapf(uErr, "while using the standard marshal function")
        }
        return value, nil
}

