package server

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
	"gtodo/models"
	"gtodo/pb"
	"time"
)

type UserServer struct {
	pb.UnimplementedUserServiceServer
	GrpcSrv *grpc.Server
	um      *models.UserManager
}

func NewUserServer(um *models.UserManager) *UserServer {
	var opts []grpc.ServerOption
	newServer := grpc.NewServer(opts...)
	runner := &UserServer{
		GrpcSrv: newServer,
		um:      um,
	}
	pb.RegisterUserServiceServer(newServer, runner)
	reflection.Register(newServer)
	return runner
}

func (u *UserServer) CreateUser(ctx context.Context, req *pb.UserRequest) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.Create(lCtx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *UserServer) CreateSuperUser(ctx context.Context, req *pb.SuperUserRequest) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.Update(lCtx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *UserServer) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.Update(lCtx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *UserServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.Login(lCtx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *UserServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (u *UserServer) ListUser(ctx context.Context, req *pb.ListUserRequest) (*pb.ListUserResponse, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	res, err := u.um.All(lCtx, req.Filter, req.Limit, req.Page)
	if err != nil {
		return nil, fmt.Errorf("oooops something went wrong: %v", err)
	}
	return res, nil
}

func (u *UserServer) SearchUser(ctx context.Context, req *pb.SearchUserRequest) (*pb.ListUserResponse, error) {
	lCtx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	res, err := u.um.Search(lCtx, req.Q, req.Limit, req.Page)
	if err != nil {
		return nil, fmt.Errorf("oooops something went wrong: %v", err)
	}
	return res, nil
}

func (u *UserServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*emptypb.Empty, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := u.um.Delete(lCtx, req.Filter); err != nil {
		return nil, errors.Wrapf(err, "deleting Todo with %v", req.Filter)
	}
	return &emptypb.Empty{}, nil
}

func (u *UserServer) BulkUser(ctx context.Context, req *pb.BulkUserRequest) (*pb.ListUserResponse, error) {
	_, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.Bulk(context.TODO(), req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *UserServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.Get(lCtx, req.Filter)
	if err != nil {
		return nil, fmt.Errorf("oooops something went wrong: %v", err)
	}
	return res, nil
}
