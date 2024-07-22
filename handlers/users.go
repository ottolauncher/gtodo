package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/ottolauncher/gtodo/models"
	"github.com/ottolauncher/gtodo/pb"
	"github.com/quangdangfit/gocommon/errors"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"log"
	"net/http"
	"strings"
	"time"
)

type UserHandler interface {
	Logout(c *gin.Context)
	Login(c *gin.Context)
	RefreshToken(c *gin.Context)
	CreateUser(c *gin.Context)
	UpdateUser(c *gin.Context)
	BulkUser(c *gin.Context)
	DeleteUser(c *gin.Context)
	GetUser(c *gin.Context)
	AllUser(c *gin.Context)
	SearchUser(c *gin.Context)
	ForgotPassword(c *gin.Context)
	ResetPassword(c *gin.Context)
	ChangePassword(c *gin.Context)
}

type LogoutRequest struct {
	AccessToken string `json:"accessToken"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserRequest struct {
	Username  string   `json:"username,omitempty" bson:"username,omitempty"`
	Email     string   `json:"email,omitempty" bson:"email,omitempty"`
	Password1 *string  `json:"password1,omitempty" bson:"password1"`
	Password2 *string  `json:"password2,omitempty" bson:"password2"`
	Phones    []string `json:"phones,omitempty" bson:"phones,omitempty"`
	Gender    string   `json:"gender,omitempty" bson:"gender,omitempty"`
	Roles     []string `json:"roles" bson:"roles"`
	IsStaff   *bool    `json:"isStaff,omitempty" bson:"isStaff,omitempty"`
	IsAdmin   *bool    `json:"isAdmin,omitempty" bson:"isAdmin,omitempty"`
	FullName  *string  `json:"fullName,omitempty" bson:"fullName,omitempty"`
	Address   *string  `json:"address,omitempty" bson:"address,omitempty"`
}

type UpdateUserRequest struct {
	Username    string   `json:"username,omitempty" bson:"username,omitempty"`
	Email       string   `json:"email,omitempty" bson:"email,omitempty"`
	OldPassword *string  `json:"oldPassword,omitempty" bson:"OldPassword"`
	NewPassword *string  `json:"newPassword,omitempty" bson:"newPassword"`
	Phones      []string `json:"phones,omitempty" bson:"phones,omitempty"`
	Gender      string   `json:"gender,omitempty" bson:"gender,omitempty"`
	Roles       []string `json:"roles" bson:"roles"`
	IsStaff     *bool    `json:"isStaff,omitempty" bson:"isStaff,omitempty"`
	IsAdmin     *bool    `json:"isAdmin,omitempty" bson:"isAdmin,omitempty"`
	FullName    *string  `json:"fullName,omitempty" bson:"fullName,omitempty"`
	Address     *string  `json:"address,omitempty" bson:"address,omitempty"`
}

type ListUserRequest struct {
	Filter map[string]interface{} `json:"filter"`
	Limit  int64                  `json:"limit"`
	Page   int64                  `json:"page"`
}

type QueryUserRequest struct {
	Q     string `json:"q"`
	Limit int64  `json:"limit"`
	Page  int64  `json:"page"`
}

type ForgotPasswordInput struct {
	Email string `json:"email"`
}

// ResetPasswordInput struct
type ResetPasswordInput struct {
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}

type ChangePasswordInput struct {
	Email              string `json:"email"`
	OldPassword        string `json:"oldPassword"`
	NewPassword        string `json:"newPassword"`
	ConfirmNewPassword string `json:"confirmNewPassword"`
}

func (r *Resolver) Logout(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 350*time.Millisecond)
	defer cancel()
	var token LogoutRequest
	if err := c.ShouldBindBodyWithJSON(&token); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: err.Error(), Code: ""})
		return
	}
	_, err := r.uc.Logout(context.TODO(), &pb.LogoutRequest{AccessToken: token.AccessToken})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: err.Error(), Code: ""})
		return
	}
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"status": "done"})
}
func (r *Resolver) ChangePassword(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	var payload ChangePasswordInput
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}
	if _, err := r.uc.ChangePassword(context.TODO(), &pb.ChangePasswordRequest{
		OldPassword:        payload.OldPassword,
		NewPassword:        payload.NewPassword,
		ConfirmNewPassword: payload.ConfirmNewPassword,
		Email:              payload.Email,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "fail", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "password data has been updated successfully"})

}
func (r *Resolver) ForgotPassword(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	var payload ForgotPasswordInput
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}
	message := "You will receive a reset email if user with that email exist"
	if _, err := r.uc.ForgotPassword(context.TODO(), &pb.ForgotPasswordRequest{Email: payload.Email}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "invalid credentials"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": message})
}

func (r *Resolver) ResetPassword(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	var payload *ResetPasswordInput
	resetToken := c.Param("resetToken")
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{"status": "fail", "message": err.Error()})
		return
	}
	if payload.Password != payload.PasswordConfirm {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{"status": "fail", "message": "passwords miss match"})
		return
	}
	if _, err := r.uc.ResetPassword(context.TODO(), &pb.ResetPasswordRequest{
		ResetToken: resetToken,
		Password1:  payload.Password,
		Password2:  payload.PasswordConfirm,
	}); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{"status": "fail", "message": "the reset token is invalid or has expired"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "password data updated successfully"})

}

func (r *Resolver) Login(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	var login LoginRequest
	if err := c.ShouldBindBodyWithJSON(&login); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: err.Error(), Code: ""})
		return
	}
	res, err := r.uc.Login(context.TODO(), &pb.LoginRequest{
		Username: login.Username, Password: login.Password,
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: "invalid credentials", Code: fmt.Sprintf("%v", errors.ErrorAuth)})
		return
	}
	c.SetCookie("token", fmt.Sprintf("%v", res), 3600, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"token": res})
}

func (r *Resolver) RefreshToken(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 3500*time.Millisecond)
	defer cancel()
	token := models.TokenFromHeader(c.Request)
	if len(token) == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("authorization token are missing").Error(), Code: fmt.Sprintf("%v", errors.ErrorAuthToken)})
		return
	}

	res, err := r.uc.RefreshToken(context.TODO(), &pb.RefreshTokenRequest{AccessToken: token})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("while renewing access token").Error(), Code: fmt.Sprintf("%v", errors.ErrorAuthToken)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": res})
}

func (r *Resolver) CreateUser(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	var req UserRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("please fill all the required field").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorBadRequest)})
		return
	}
	user := &pb.UserRequest{
		Username:  req.Username,
		Email:     req.Email,
		Password1: *req.Password1,
		Password2: *req.Password2,
		Phones:    req.Phones,
		FullName:  *req.FullName,
		Address:   *req.Address,
		Roles:     req.Roles,
	}

	if strings.EqualFold(strings.ToLower(req.Gender), "male") {
		user.Gender = &pb.UserRequest_Male{Male: req.Gender}
	} else if strings.EqualFold(strings.ToLower(req.Gender), "female") {
		user.Gender = &pb.UserRequest_Female{Female: req.Gender}
	}
	res, err := r.uc.CreateUser(context.TODO(), user)
	if err != nil {
		log.Println("on create user ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("something went wrong").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorDatabaseCreate)})
		return
	}
	message := "We sent an email with a verification code to " + res.Email
	c.JSON(http.StatusCreated, gin.H{"status": "success", "message": message})
}

func (r *Resolver) VerifyEmail(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	code := c.Param("verificationCode")
	if _, err := r.uc.VerifyEmail(context.TODO(), &pb.VerifyEmailRequest{Code: code}); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("invalid verification token").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorTokenMalformed)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Email verified successfully"})
}

func (r *Resolver) UpdateUser(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	var req UpdateUserRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("please fill all the required field").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorBadRequest)})
		return
	}
	user := &pb.UpdateUserRequest{
		Email:       req.Email,
		OldPassword: *req.OldPassword,
		NewPassword: *req.NewPassword,
		Phones:      req.Phones,
		FullName:    *req.FullName,
		Address:     *req.Address,
		Roles:       req.Roles,
	}

	if strings.EqualFold(strings.ToLower(req.Gender), "male") {
		user.Gender = &pb.UpdateUserRequest_Male{Male: req.Gender}
	} else if strings.EqualFold(strings.ToLower(req.Gender), "female") {
		user.Gender = &pb.UpdateUserRequest_Female{Female: req.Gender}
	}
	res, err := r.uc.UpdateUser(context.TODO(), user)
	if err != nil {
		log.Println("on create user ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("something went wrong").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorDatabaseCreate)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": res})
}

func (r *Resolver) BulkUser(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	var req []*UserRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("please fill all the required field").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorBadRequest)})
		return
	}
	var users []*pb.UserRequest
	for _, i := range req {
		user := &pb.UserRequest{
			Username:  i.Username,
			Email:     i.Email,
			Password1: *i.Password1,
			Password2: *i.Password2,
			Phones:    i.Phones,
			FullName:  *i.FullName,
			Address:   *i.Address,
			Roles:     i.Roles,
		}

		if strings.EqualFold(strings.ToLower(i.Gender), "male") {
			user.Gender = &pb.UserRequest_Male{Male: i.Gender}
		} else if strings.EqualFold(strings.ToLower(i.Gender), "female") {
			user.Gender = &pb.UserRequest_Female{Female: i.Gender}
		}
		users = append(users, user)
	}

	res, err := r.uc.BulkUser(context.TODO(), &pb.BulkUserRequest{Input: users})
	if err != nil {
		log.Println("on create user ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("something went wrong").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorDatabaseCreate)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": res})
}

func (r *Resolver) DeleteUser(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	args := c.Query("filter")
	if len(args) == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("filter query are required").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorBadRequest)})
		return
	}
	var filter []byte
	base64.StdEncoding.Encode(filter, []byte(args))

	_, err := r.uc.DeleteUser(context.TODO(), &pb.DeleteUserRequest{Filter: &wrapperspb.BytesValue{Value: filter}})
	if err != nil {
		log.Println("on delete user ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("something went wrong").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorDatabaseCreate)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "done"})
}

func (r *Resolver) GetUser(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	args := c.Query("filter")
	if len(args) == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("filter query are required").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorBadRequest)})
		return
	}
	var filter []byte
	base64.StdEncoding.Encode(filter, []byte(args))

	res, err := r.uc.GetUser(context.TODO(), &pb.GetUserRequest{Filter: &wrapperspb.BytesValue{Value: filter}})
	if err != nil {
		log.Println("on get user ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("something went wrong").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorDatabaseCreate)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": res})
}

func (r *Resolver) AllUser(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	var req ListUserRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("please fill all the required field").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorBadRequest)})
		return
	}
	var filter []byte
	base64.StdEncoding.Encode(filter, []byte(fmt.Sprintf("%v", req.Filter)))

	res, err := r.uc.ListUser(context.TODO(), &pb.ListUserRequest{
		Filter: &wrapperspb.BytesValue{Value: filter}, Page: req.Page, Limit: req.Limit},
	)
	if err != nil {
		log.Println("on get all user ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("something went wrong").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorDatabaseCreate)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": res})
}

func (r *Resolver) SearchUser(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5000*time.Millisecond)
	defer cancel()
	var req QueryUserRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest,
			models.ErrorResponse{Message: fmt.Errorf("please fill all the required field").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorBadRequest)})
		return
	}

	res, err := r.uc.SearchUser(context.TODO(), &pb.SearchUserRequest{
		Q: req.Q, Page: req.Page, Limit: req.Limit},
	)
	if err != nil {
		log.Println("on get all user ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			models.ErrorResponse{Message: fmt.Errorf("something went wrong").Error(),
				Code: fmt.Sprintf("%v", errors.ErrorDatabaseCreate)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": res})
}
