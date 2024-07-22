package handlers

import (
	"gtodo/pb"
)

type Resolver struct {
	tdc pb.TodoServiceClient
	uc  pb.UserServiceClient
}

func NewResolver(tdc pb.TodoServiceClient, uc pb.UserServiceClient) *Resolver {
	return &Resolver{tdc: tdc, uc: uc}
}