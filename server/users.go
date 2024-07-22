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
func (u *UserServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*emptypb.Empty, error) {
	_, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if req.OldPassword == "" && req.NewPassword == "" && req.ConfirmNewPassword == "" {
		return nil, fmt.Errorf("all the passwords fields must be provided")
	}
	if req.OldPassword == req.NewPassword {
		return nil, fmt.Errorf("your old password are too similar to the new one")
	}
	if req.NewPassword != req.ConfirmNewPassword {
		return nil, fmt.Errorf("both new and confirm password must match")
	}
	if err := u.um.ChangePassword(context.TODO(), &pb.ChangePasswordRequest{
		OldPassword:        req.OldPassword,
		NewPassword:        req.NewPassword,
		ConfirmNewPassword: req.ConfirmNewPassword,
		Email:              req.Email,
	}); err != nil {
		return nil, err
	}
	return nil, nil
}

func (u *UserServer) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest) (*emptypb.Empty, error) {
	_, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := u.um.ForgotPassword(context.TODO(),
		&pb.ForgotPasswordRequest{Email: req.GetEmail()}); err != nil {
		return nil, err
	}
	return nil, nil
}
func (u *UserServer) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*emptypb.Empty, error) {
	_, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if req.GetPassword1() != req.GetPassword2() {
		return nil, fmt.Errorf("password miss match")
	}
	if err := u.um.ResetPassword(context.TODO(),
		&pb.ResetPasswordRequest{
			ResetToken: req.ResetToken,
			Password1:  req.GetPassword1(),
			Password2:  req.GetPassword2(),
		}); err != nil {
		return nil, err
	}
	return nil, nil
}

func (u *UserServer) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*emptypb.Empty, error) {
	_, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := u.um.VerifyEmail(context.TODO(), req.GetCode()); err != nil {
		return nil, err
	}
	return nil, nil
}
func (u *UserServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.LoginResponse, error) {
	lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := u.um.RefreshToken(lctx, req.AccessToken)
	if err != nil {
		return nil, err
	}
	return &pb.LoginResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
	}, nil
}

func (u *UserServer) CreateUser(ctx context.Context, req *pb.UserRequest) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.CreateSuperUser(lCtx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *UserServer) CreateSuperUser(ctx context.Context, req *pb.SuperUserRequest) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := u.um.UpdateSuperUser(lCtx, req)
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
