package auth

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gtodo/helpers"
	"gtodo/models"
)

type Interceptor struct {
	um    *models.UserManager
	roles map[string][]string
}

func accessibleRoles() map[string][]string {
	const todoServicePath = "TodoService"
	return map[string][]string{
		todoServicePath + "CreateTodo": {"admin"},
		todoServicePath + "DeleteTodo": {"admin"},
		todoServicePath + "ListTodo":   {"admin", "user"},
		todoServicePath + "SearchTodo": {"admin", "user"},
		todoServicePath + "BulkTodo":   {"admin"},
		todoServicePath + "GetTodo":    {"admin", "user"},
		todoServicePath + "UpdateTodo": {"admin"},
	}
}

type UnaryManager interface {
	Unary() grpc.UnaryServerInterceptor
	Stream() grpc.StreamServerInterceptor
	authorize(ctx context.Context, method string) error
}

func (u *Interceptor) authorize(ctx context.Context, method string) error {
	roles, ok := u.roles[method]
	if !ok {
		// everyone can access
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "metadata are not provided")
	}
	values := md["authorization"]
	if len(values) == 0 {
		return status.Errorf(codes.Unauthenticated, "authorization token is missing")
	}
	accessToken := values[0]
	token, err := helpers.ParseAccessToken(accessToken)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "access token is invalid: %v", err)
	}
	claims, ok := token.Claims.(*helpers.JWTCustomClaims)
	if ok && token.Valid {
		for _, role := range accessibleRoles() {
			if role == claims.Role {
				return nil
			}
		}
	}
	return status.Errorf(codes.PermissionDenied, "you cannot perform that action")
}

func NewUnaryInterceptor(um *models.UserManager, roles map[string][]string) *Interceptor {
	return &Interceptor{
		um:    um,
		roles: roles,
	}
}

func (u *Interceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := u.authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func (u *Interceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := u.authorize(stream.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, stream)
	}
}
