package handlers

import (
	"gtodo/pb"
)

type Resolver struct {
	client pb.TodoServiceClient
}

func NewResolver(bck pb.TodoServiceClient) *Resolver {
	return &Resolver{client: bck}
}
