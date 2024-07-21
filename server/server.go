package server

import (
	"context"
	"fmt"
	"gtodo/models"
	"gtodo/pb"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
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

func (srv *TodoServer) ListTodos(ctx context.Context, req *pb.ListTodoRequest) (*pb.ListTodoResponse, error) {
	lCtx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
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

func (srv *TodoServer) BulkTodo(stream pb.TodoService_BulkTodoServer) error {
	lCtx, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	// receive first part of stream with required metadata
	_, err := stream.Recv()
	if err != nil {
		return err
	}

	var (
		colChan chan *pb.TodoRequest
		errChan chan error
		Todos   []*pb.TodoRequest
	)
	waitChan := make(chan struct{})
	go func() {
		defer close(colChan)
		defer close(errChan)
		for {
			if done := stream.Context().Err(); done != nil {
				log.Println("deadline exceeded")
				errChan <- status.Errorf(codes.DeadlineExceeded, "client deadline for stream exceeded")
			}
			select {
			case <-lCtx.Done():
				log.Println("server deadline exceeded")
				errChan <- status.Error(codes.DeadlineExceeded, "server deadline for stream exceeded")
			}
			in, err := stream.Recv()
			if err == io.EOF {
				errChan <- status.Errorf(codes.OK, "Stream completed")
				close(waitChan)
				return
			}
			if err != nil {
				errChan <- status.Errorf(codes.Canceled, "Stream cancelled")
			} else {
				colChan <- in
			}
		}
	}()

	for Todo := range colChan {
		Todos = append(Todos, Todo)
	}
	res, err := srv.tm.Bulk(context.TODO(), Todos)
	if err != nil {
		return status.Errorf(codes.Internal, "ooops something went wrong: %v", err)
	}
	var errs []error
	for er := range errChan {
		errs = append(errs, er)
	}
	if len(errs) > 0 {
		return status.Errorf(codes.Unknown, fmt.Sprintf("%v", errs))
	}
	<-waitChan
	return stream.SendAndClose(res)
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
