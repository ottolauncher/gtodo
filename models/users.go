package models

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bufbuild/protovalidate-go"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gtodo/helpers"
	"gtodo/pb"
	"log"
	"strings"
	"time"
)

type UserManager struct {
	col    *mongo.Collection
	v      *protovalidate.Validator
	client *redis.Client
}

func NewUserManger(c *mongo.Client, client *redis.Client) *UserManager {
	v, _ := protovalidate.New()
	col := c.Database(cfg.MongodbDatabase).Collection(cfg.DbUserName)

	return &UserManager{col: col, v: v, client: client}
}

type User struct {
	ID         primitive.ObjectID `json:"id,omitempty" bson:"id,omitempty"`
	Username   string             `json:"username,omitempty" bson:"username,omitempty"`
	Email      string             `json:"email,omitempty" bson:"email,omitempty"`
	Password   *string            `json:"password,omitempty" bson:"password"`
	Phones     []string           `json:"phones,omitempty" bson:"phones,omitempty"`
	Gender     string             `json:"gender,omitempty" bson:"gender,omitempty"`
	Role       string             `json:"role" bson:"role"`
	IsStaff    *bool              `json:"isStaff,omitempty" bson:"isStaff,omitempty"`
	IsAdmin    *bool              `json:"isAdmin,omitempty" bson:"isAdmin,omitempty"`
	FullName   *string            `json:"fullName,omitempty" bson:"fullName,omitempty"`
	Address    *string            `json:"address,omitempty" bson:"address,omitempty"`
	DateJoined *time.Time         `json:"dateJoined,omitempty" bson:"dateJoined,omitempty"`
	LastLogin  *time.Time         `json:"lastLogin,omitempty" bson:"lastLogin,omitempty"`
}

type IUser interface {
	SetRole(role string) error
	GetRole() string
	SetGender(gender string) error
	GetGender() string
}

type UserWithRoleAndGender struct {
	*pb.User
}

func (u *UserWithRoleAndGender) SetRole(role string) error {
	switch role {
	case "admin":
		u.Role = &pb.User_Admin{Admin: "admin"}
	case "seller":
		u.Role = &pb.User_Seller{Seller: "seller"}
	case "user":
		u.Role = &pb.User_User{User: "user"}
	default:
		u.Role = &pb.User_User{User: "user"}
	}
	return nil
}

func (u *UserWithRoleAndGender) GetRole() string {
	return u.GetRole()
}

func (u *UserWithRoleAndGender) SetGender(gender string) error {
	switch gender {
	case "male":
		u.Gender = &pb.User_Male{Male: gender}
	case "female":
		u.Gender = &pb.User_Female{Female: gender}
	default:
		u.Gender = &pb.User_Female{Female: "female"}
	}
	return nil
}

func (u *UserWithRoleAndGender) GetGender() string {
	return u.GetGender()
}

func getUpdatedGender(u *pb.UpdateUserRequest) string {
	var gender string
	switch x := u.Gender.(type) {
	case *pb.UpdateUserRequest_Male:
		gender = x.Male
	case *pb.UpdateUserRequest_Female:
		gender = x.Female
	}
	return gender
}
func NewUserFromGrpcRequest(u interface{}) (*User, error) {
	// Type assertion to ensure we're dealing with UserWithRole
	uwr, ok := u.(*UserWithRoleAndGender)
	if !ok {
		return nil, errors.New("unexpected type passed")
	}
	now := time.Now()
	user := &User{
		ID:         primitive.NewObjectID(),
		Username:   uwr.Username,
		Email:      uwr.Email,
		Password:   nil,
		Phones:     uwr.Phones,
		IsStaff:    nil,
		IsAdmin:    nil,
		FullName:   &uwr.FullName,
		Address:    &uwr.Address,
		DateJoined: &now,
		LastLogin:  nil,
	}
	user.Role = uwr.GetGender()
	user.Gender = uwr.GetRole()
	return user, nil
}

func NewUserListResponse(users []*User) *pb.ListUserResponse {
	var returned pb.ListUserResponse
	for _, u := range users {
		returned.Users = append(returned.Users, UserToGrpcUser(u))
	}
	return &returned
}
func UserToGrpcUser(u *User) *pb.User {
	if u != nil {
		user := &pb.User{
			Id:         u.ID.String(),
			Username:   u.Username,
			Email:      u.Email,
			Password:   "-",
			Phones:     u.Phones,
			IsStaff:    *u.IsStaff,
			IsAdmin:    *u.IsAdmin,
			FullName:   *u.FullName,
			Address:    *u.Address,
			DateJoined: timestamppb.New(*u.DateJoined),
			LastLogin:  timestamppb.New(*u.LastLogin),
		}
		if strings.EqualFold(strings.ToLower(u.Gender), "male") {
			user.Gender = &pb.User_Male{Male: u.Gender}
		} else if strings.EqualFold(strings.ToLower(u.Gender), "female") {
			user.Gender = &pb.User_Female{Female: u.Gender}
		}
		return user
	}
	return nil
}
func (u *UserManager) Logout(ctx context.Context, accessToken string) error {
	_, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	token, err := helpers.ParseAccessToken(accessToken)
	if err != nil {
		return errors.Wrapf(err, "invalid token")
	}
	claims, ok := token.Claims.(*helpers.JWTCustomClaims)
	if ok && token.Valid {

		if err := helpers.DeleteTokens(u.client, &helpers.AccessDetails{
			AccessUuid: claims.AccessUUID,
			UserID:     claims.UserID,
		}); err != nil {
			return errors.Wrapf(err, "while deleting tokens")
		}
		if _, err := helpers.DeleteAuth(u.client, *claims.AccessUUID); err != nil {
			return errors.Wrapf(err, "while deleting authorisation")
		}
	}
	return nil
}
func (u *UserManager) Login(ctx context.Context, v interface{}) (*pb.LoginResponse, error) {
	_, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	switch x := v.(type) {
	case *pb.LoginRequest:
		if err := u.v.Validate(x); err != nil {
			return nil, errors.Wrapf(err, "validation failed")
		} else {
			filter := bson.M{"username": x.GetUsername()}
			var user User
			if err := u.col.FindOne(context.TODO(), filter).Decode(&user); err != nil {
				return nil, errors.Wrapf(err, "invalid credentials")
			}
			if helpers.CheckPassword(x.Password, []byte(*user.Password)) {
				update := bson.D{{Key: "$set", Value: bson.D{
					{Key: "lastLogin", Value: time.Now()},
				}}}
				_ = u.col.FindOneAndUpdate(context.TODO(), bson.M{"_id": user.ID}, update, options.FindOneAndUpdate().SetReturnDocument(1))
				// generate token
				td, createErr := helpers.CreateToken(user)
				if createErr != nil {
					return nil, errors.Wrapf(err, "while generating token")
				}
				tokenDetails := &pb.LoginResponse{
					AccessToken:  td.AccessToken,
					RefreshToken: td.RefreshToken,
				}
				if err := helpers.CreateAuth(u.client, user.ID.String(), td); err != nil {
					return nil, errors.Wrapf(err, "while creating auth features")
				}
				return tokenDetails, nil
			} else {
				return nil, fmt.Errorf("invalid credentials")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported type %v", x)
	}
}

func (u *UserManager) Create(ctx context.Context, v interface{}) (*pb.User, error) {
	_, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	opts := options.CreateIndexes().SetMaxTime(10 * time.Second)
	index := mongo.IndexModel{Keys: bson.D{{Key: "username", Value: "text"}}, Options: options.Index().SetUnique(true)}
	_, err := u.col.Indexes().CreateOne(context.TODO(), index, opts)
	if err != nil {
		return nil, err
	}
	switch x := v.(type) {
	case *pb.UserRequest:
		if err := u.v.Validate(x); err != nil {
			return nil, errors.Wrapf(err, "validation failed")
		} else {
			if !strings.EqualFold(x.Password1, x.Password2) {
				return nil, fmt.Errorf("password miss match")
			}
			insert, err := NewUserFromGrpcRequest(x)
			if err != nil {
				return nil, err
			}
			// generate password
			p, err := helpers.HashPassword(x.Password2)
			if err != nil {
				return nil, errors.Wrapf(err, "while hashing password")
			}
			pwd := string(p)
			insert.Password = &pwd
			_, err = u.col.InsertOne(context.TODO(), insert)
			if err != nil {
				if er, ok := err.(mongo.WriteException); ok && er.WriteErrors[0].Code == 1100 {
					return nil, errors.Wrap(err, "username already takeb")
				}
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unsupported type: %v", x)
	}
	return nil, nil
}

func (u *UserManager) Bulk(ctx context.Context, v interface{}) (*pb.ListUserResponse, error) {
	_, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var collector []mongo.WriteModel
	switch x := v.(type) {
	case *pb.BulkUserRequest:
		chanOwner := func() (chan *User, chan error) {
			errs := make(chan error)
			outUser := make(chan *User, len(x.Input))

			go func() {
				defer close(errs)
				defer close(outUser)
				for _, t := range x.Input {
					if !strings.EqualFold(t.Password1, t.Password2) {
						errs <- fmt.Errorf("password miss match")
					} else {
						user, err := NewUserFromGrpcRequest(t)
						if err != nil {
							errs <- err
						}
						p, err := helpers.HashPassword(t.Password2)
						if err != nil {
							errs <- errors.Wrapf(err, "while hashing password")
						}
						pwd := string(p)
						user.Password = &pwd
						outUser <- user
						collector = append(collector,
							mongo.NewInsertOneModel().SetDocument(user))
					}

				}
				opts := options.BulkWrite().SetOrdered(false)
				_, err := u.col.BulkWrite(context.TODO(), collector, opts)
				if err != nil {
					errs <- errors.Wrap(err, "when inserting bulk data")
				}
			}()
			return outUser, errs
		}

		consumer := func(results chan *User, errs chan error) (*pb.ListUserResponse, error) {
			var (
				aggregator []*pb.User
				outErr     []error
			)
			for result := range results {
				aggregator = append(aggregator, UserToGrpcUser(result))
			}
			for e := range errs {
				outErr = append(outErr, e)
			}
			if len(outErr) > 0 {
				return nil, fmt.Errorf("%v", outErr)
			}
			return &pb.ListUserResponse{Users: aggregator}, nil
		}
		results, errs := chanOwner()
		return consumer(results, errs)
	default:
		return nil, fmt.Errorf("unsupported type %v: ", x)
	}

}

func (u *UserManager) Update(ctx context.Context, v interface{}) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	switch x := v.(type) {
	case *pb.UpdateUserRequest:
		if strings.EqualFold(x.OldPassword, x.NewPassword) {
			return nil, fmt.Errorf("your password are too similar with the new one")
		}
		var user User
		oid, err := primitive.ObjectIDFromHex(x.Id)
		if err != nil {
			return nil, fmt.Errorf("please provide a valid user id")
		}
		filter := bson.M{"_id": oid}
		if err := u.col.FindOne(context.TODO(), filter).Decode(&user); err != nil {
			if err == mongo.ErrNoDocuments {
				return nil, fmt.Errorf("user does not exist")
			}
			return nil, err
		}
		if !helpers.CheckPassword(x.OldPassword, []byte(*user.Password)) {
			return nil, fmt.Errorf("invalid credentials")
		}
		p, err := helpers.HashPassword(x.NewPassword)
		if err != nil {
			return nil, err
		}
		pwd := string(p)

		update := bson.D{{Key: "$set", Value: bson.D{
			{Key: "email", Value: x.GetEmail()},
			{Key: "password", Value: pwd},
			{Key: "gender", Value: getUpdatedGender(x)},
			{Key: "fullName", Value: x.GetFullName()},
			{Key: "isStaff", Value: x.GetIsStaff()},
			{Key: "isAdmin", Value: x.GetIsAdmin()},
			{Key: "phones", Value: x.GetPhones()},
			{Key: "address", Value: x.GetAddress()},
		}}}
		res := u.col.FindOneAndUpdate(lCtx, bson.M{"_id": oid}, update, options.FindOneAndUpdate().SetReturnDocument(1))
		var lUser User
		if err := res.Decode(&lUser); err != nil {
			return nil, errors.Wrapf(err, "no user with ID: %s exists", x.GetId())
		}
		return UserToGrpcUser(&lUser), nil
	default:
		return nil, fmt.Errorf("unsupported type %v", x)
	}
}

func (u *UserManager) Delete(ctx context.Context, filter *wrapperspb.BytesValue) error {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := u.v.Validate(filter); err != nil {
		return errors.Wrapf(err, "please enter a criteria first")
	}
	var args interface{}
	if err := json.Unmarshal(filter.Value, &args); err != nil {
		return errors.Wrapf(err, "while converting bytes value to interface")
	}
	res, err := u.col.DeleteOne(lCtx, args)
	if err != nil {
		return errors.Wrapf(err, "while deleting todo with %v", args)
	}
	if res.DeletedCount == 0 {
		return errors.Wrapf(err, "no document with %v exists", args)
	}
	return nil
}

func (u *UserManager) Get(ctx context.Context, filter *wrapperspb.BytesValue) (*pb.User, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user User

	var args interface{}

	if err := json.Unmarshal(filter.Value, args); err != nil {
		return nil, errors.Wrapf(err, "while parsing filter argument")
	}

	if err := u.col.FindOne(lCtx, args).Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			log.Println("empty document response")
			return nil, fmt.Errorf(`user does not exists`)
		} else {
			log.Println("error not nil from findOne: ", err)
			return nil, err
		}
	} else {
		return UserToGrpcUser(&user), nil
	}
}

func (u *UserManager) All(ctx context.Context, any *wrapperspb.BytesValue, limit, page int64) (*pb.ListUserResponse, error) {
	_, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var users []*User

	opts := newMongoPaginate(limit, page).getPaginatedOpts()
	opts.SetSort(bson.M{"createdAt": -1})

	var filter interface{}

	if err := json.Unmarshal(any.Value, &filter); err != nil {
		return nil, errors.Wrapf(err, "while converting to interface")
	}

	if filter == nil {
		filter = bson.D{}
	}

	cursor, err := u.col.Find(context.TODO(), filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrapf(err, "request returned no documents")
		}
		return nil, errors.Wrapf(err, "unexpected error occured")
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		user := User{}
		err := cursor.Decode(&user)
		if err != nil {
			return nil, errors.Wrapf(err, "unexpected results while decoding")
		}
		users = append(users, &user)
	}
	if err := cursor.Err(); err != nil {
		return nil, errors.Wrapf(err, "cursor lead error")
	}
	if len(users) == 0 {
		return &pb.ListUserResponse{}, nil
	}
	return NewUserListResponse(users), nil
}

func (u *UserManager) Search(ctx context.Context, q string, limit, page int64) (*pb.ListUserResponse, error) {
	lCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var users []*User

	filter := bson.M{"$text": bson.M{"$search": q}}

	opts := newMongoPaginate(limit, page).getPaginatedOpts()
	opts.SetSort(bson.M{"createdAt": -1})

	cursor, err := u.col.Find(context.TODO(), filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(lCtx)

	for cursor.Next(context.TODO()) {
		user := &User{}
		err := cursor.Decode(&user)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return &pb.ListUserResponse{}, nil
	}
	return NewUserListResponse(users), nil
}
