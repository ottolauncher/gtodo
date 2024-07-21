package interceptor

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gtodo/models"
	"time"
)

type AuthInterceptor struct {
	um          *models.UserManager
	authMethods map[string]bool
	td          map[string]string
}

func NewAuthInterceptor(um *models.UserManager, methods map[string]bool, refresh time.Duration) (*AuthInterceptor, error) {
	auth := &AuthInterceptor{
		um:          um,
		authMethods: methods,
	}
	if err := auth.scheduleRefreshToken(refresh); err != nil {
		return nil, err
	}
	return auth, nil
}

type ClientManager interface {
	Unary() grpc.StreamClientInterceptor
	Stream() grpc.StreamClientInterceptor
	scheduleRefreshToken(refreshDuration time.Duration) error
	attachToken(ctx context.Context) context.Context
	refreshToken() error
}

func (u *AuthInterceptor) attachToken(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", u.td["accessToken"])
}

func (u *AuthInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if u.authMethods[method] {
			return invoker(u.attachToken(ctx), method, req, reply, cc, opts...)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (u *AuthInterceptor) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if u.authMethods[method] {
			return streamer(u.attachToken(ctx), desc, cc, method, opts...)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func (u *AuthInterceptor) refreshToken() error {
	td, err := u.um.RefreshToken(context.TODO(), u.td["refreshToken"])
	if err != nil {
		return err
	}
	u.td = map[string]string{"accessToken": td.AccessToken, "refreshToken": td.RefreshToken}
	return nil
}

func (u *AuthInterceptor) scheduleRefreshToken(refresh time.Duration) error {
	if err := u.refreshToken(); err != nil {
		return err
	}
	go func() {
		wait := refresh
		for {
			time.Sleep(wait)
			err := u.refreshToken()
			if err != nil {
				wait = time.Second
			} else {
				wait = refresh
			}
		}
	}()
	return nil
}
