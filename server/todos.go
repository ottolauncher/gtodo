package server

import (
	"context"
	"fmt"
	"github.com/ottolauncher/gtodo/models"
	"github.com/ottolauncher/gtodo/pb"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
)

type TodoServer struct {
	pb.UnimplementedTodoServiceServer
	GrpcSrv *grpc.Server
	tm      *models.TodoManager
}

func NewTodoServer(bm *models.TodoManager) *TodoServer {
	var opts []grpc.ServerOption
	newServer := grpc.NewServer(opts...)
	runner := &TodoServer{
		GrpcSrv: newServer,
		tm:      bm,
	}
	pb.RegisterTodoServiceServer(newServer, runner)
	reflection.Register(newServer)
	return runner
}

func (srv *TodoServer) CreateTodo(ctx context.Context, req *pb.TodoRequest) (*pb.Todo, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := srv.tm.Create(lCtx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}
func (srv *TodoServer) UpdateTodo(ctx context.Context, req *pb.UpdateTodoRequest) (*pb.Todo, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := srv.tm.Update(lCtx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}
func (srv *TodoServer) DeleteTodo(ctx context.Context, req *pb.DeleteTodoRequest) (*emptypb.Empty, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := srv.tm.Delete(lCtx, req.Filter); err != nil {
		return nil, errors.Wrapf(err, "deleting Todo with %v", req.Filter)
	}
	return &emptypb.Empty{}, nil
}

func (srv *TodoServer) BulkTodo(ctx context.Context, in *pb.BulkTodoRequest) (*pb.ListTodoResponse, error) {
	_, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := srv.tm.Bulk(context.TODO(), in)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (srv *TodoServer) ListTodos(ctx context.Context, req *pb.ListTodoRequest) (*pb.ListTodoResponse, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	res, err := srv.tm.All(lCtx, req.Filter, req.Limit, req.Page)
	if err != nil {
		return nil, fmt.Errorf("oooops something went wrong: %v", err)
	}
	return res, nil
}

func (srv *TodoServer) GetTodo(ctx context.Context, req *pb.GetTodoRequest) (*pb.Todo, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := srv.tm.Get(lCtx, req.Filter)
	if err != nil {
		return nil, fmt.Errorf("oooops something went wrong: %v", err)
	}
	return res, nil
}

func (srv *TodoServer) SearchTodo(ctx context.Context, req *pb.SearchTodoRequest) (*pb.ListTodoResponse, error) {
	lCtx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	res, err := srv.tm.Search(lCtx, req.Q, req.Limit, req.Page)
	if err != nil {
		return nil, fmt.Errorf("oooops something went wrong: %v", err)
	}
	return res, nil

}
