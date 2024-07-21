package models

import (
	"context"
	"encoding/json"
	"fmt"
	"gtodo/config"
	"gtodo/pb"
	"log"
	"time"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var cfg *config.Config

func init() {
	lcfg, err := config.Read(".env")
	if err != nil {
		log.Fatalln("unable to load env files: ", err)
	}
	cfg = lcfg
}

func NewTodoManger(c *mongo.Client) *TodoManager {
	col := c.Database(cfg.MongodbDatabase).Collection(cfg.DbTodoName)
	return &TodoManager{col: col}
}

type TodoManager struct {
	col *mongo.Collection
}

// swagger: model TodoRequest
type TodoRequest struct {
	Name        string `json:"name" bson:"name"`
	Description string `json:"description" bson:"description"`
	Done        bool   `json:"done" bson:"done"`
}

// swagger: model UpdateTodoRequest
type UpdateTodoRequest struct {
	ID          string `json:"id,omitempty" bson:"id,omitempty"`
	Name        string `json:"name" bson:"name"`
	Description string `json:"description" bson:"description"`
	Done        bool   `json:"done" bson:"done"`
}

// swagger: model Todo
type Todo struct {
	// swagger:strfmt bsonobjectid
	ID          primitive.ObjectID `json:"id,omitempty" bson:"id,omitempty"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Done        bool               `json:"done" bson:"done"`
	CreatedAt   *time.Time         `json:"createdAt" bson:"createdAt"`
	UpdatedAt   *time.Time         `json:"updatedAt" bson:"updatedAt"`
}

// swagger: model Filter
type Filter map[string]interface{}

// swagger: model ErrorResponse
type ErrorResponse struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

// swagger: model DefaultResponse
type DefaultResponse map[string]interface{}

func NewTodoToGrpcRequest(t *TodoRequest) *pb.TodoRequest {
	return &pb.TodoRequest{
		Name:        t.Name,
		Description: t.Description,
		Done:        t.Done,
	}
}

func UpdateTodoToGrpcRequest(t *UpdateTodoRequest) *pb.UpdateTodoRequest {
	return &pb.UpdateTodoRequest{
		Id:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		Done:        t.Done,
	}
}

func TodoFromGrpcResponse(t *pb.Todo) (*Todo, error) {
	date := t.CreatedAt.AsTime()
	oid, err := primitive.ObjectIDFromHex(t.Id)
	if err != nil {
		return nil, err
	}
	return &Todo{
		ID:          oid,
		Name:        t.GetName(),
		Description: t.GetDescription(),
		Done:        t.GetDone(),
		CreatedAt:   &date,
		UpdatedAt:   &date,
	}, nil
}

func NewTodoFromGrpc(t *pb.TodoRequest) *Todo {
	now := time.Now()
	return &Todo{
		ID:          primitive.NewObjectID(),
		Name:        t.GetName(),
		Description: t.GetDescription(),
		Done:        t.GetDone(),
		CreatedAt:   &now,
		UpdatedAt:   &now,
	}
}

func TodoToGrpc(t *Todo) *pb.Todo {
	return &pb.Todo{
		Id:          t.ID.String(),
		Name:        t.Name,
		Description: t.Description,
		Done:        t.Done,
		CreatedAt:   timestamppb.New(*t.CreatedAt),
		UpdatedAt:   timestamppb.New(*t.UpdatedAt),
	}
}

func (t *TodoManager) Create(ctx context.Context, v interface{}) (*pb.Todo, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	opts := options.CreateIndexes().SetMaxTime(10 * time.Second)
	index := mongo.IndexModel{Keys: bson.D{{Key: "name", Value: "text"}}, Options: options.Index().SetUnique(true)}
	t.col.Indexes().CreateOne(context.TODO(), index, opts)

	switch x := v.(type) {
	case *pb.TodoRequest:
		todo := NewTodoFromGrpc(x)
		_, err := t.col.InsertOne(lCtx, todo)
		if err != nil {
			if er, ok := err.(mongo.WriteException); ok && er.WriteErrors[0].Code == 1100 {
				return nil, errors.Wrap(err, "todo with that name already exists")
			}
			return nil, err
		}
		return TodoToGrpc(todo), nil
	default:
		return nil, fmt.Errorf("unsupported type %v:", x)
	}
}

func (t *TodoManager) Bulk(ctx context.Context, v interface{}) (*pb.ListTodoResponse, error) {
	_, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	switch x := v.(type) {
	case []*pb.TodoRequest:
		chanOwner := func() <-chan *Todo {
			ch := make(chan *Todo, len(x))
			go func() {
				defer close(ch)
				if len(x) > 0 {
					for _, todo := range x {
						ch <- NewTodoFromGrpc(todo)
					}
				} else {
					return
				}
			}()
			return ch
		}
		consumer := func(results <-chan *Todo) (*pb.ListTodoResponse, error) {
			var collector []interface{}

			for result := range results {
				collector = append(collector, result)
			}
			insert, err := t.col.InsertMany(context.TODO(), collector)
			if err != nil {
				return nil, errors.Wrap(err, "when inserting bulk data")
			}
			var localTodos []*Todo
			cursor, err := t.col.Find(context.TODO(), bson.M{"_id": bson.M{"$in": insert.InsertedIDs}})
			if err != nil {
				return nil, err
			}

			defer cursor.Close(context.TODO())
			if err := cursor.Decode(&localTodos); err != nil {
				return nil, err
			}
			return newTodoListResponse(localTodos), nil
		}
		results := chanOwner()
		return consumer(results)

	default:
		return nil, fmt.Errorf("unsupported type %v: ", x)
	}
}

func newTodoListResponse(todos []*Todo) *pb.ListTodoResponse {
	var res *pb.ListTodoResponse
	go func() {
		for _, t := range todos {
			res.Todos = append(res.Todos, TodoToGrpc(t))
		}
	}()
	return res
}

func (t *TodoManager) Update(ctx context.Context, v interface{}) (*pb.Todo, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	switch x := v.(type) {
	case *pb.UpdateTodoRequest:
		now := time.Now()
		update := bson.D{{Key: "$set", Value: bson.D{
			{Key: "name", Value: x.GetName()},
			{Key: "description", Value: x.GetDescription()},
			{Key: "done", Value: x.GetDone()},
			{Key: "updatedAt", Value: now},
		}}}
		oid, err := primitive.ObjectIDFromHex(x.Id)
		if err != nil {
			return nil, err
		}
		res := t.col.FindOneAndUpdate(lCtx, bson.M{"_id": oid}, update, options.FindOneAndUpdate().SetReturnDocument(1))
		var todo Todo
		if err := res.Decode(&todo); err != nil {
			return nil, errors.Wrapf(err, "no todo with ID: %s exists", x.GetId())
		}
		return TodoToGrpc(&todo), nil
	default:
		return nil, fmt.Errorf("unsupported type %v", x)
	}
}

func (t *TodoManager) Delete(ctx context.Context, filter *wrapperspb.BytesValue) error {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var args interface{}
	if err := json.Unmarshal(filter.Value, &args); err != nil {
		return errors.Wrapf(err, "while converting bytes value to interface")
	}
	res, err := t.col.DeleteOne(lCtx, args)
	if err != nil {
		return errors.Wrapf(err, "while deleting todo with %v", args)
	}
	if res.DeletedCount == 0 {
		return errors.Wrapf(err, "no document with %v exists", args)
	}
	return nil
}

func (t *TodoManager) Get(ctx context.Context, filter *wrapperspb.BytesValue) (*pb.Todo, error) {
	lCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var todo Todo

	var args interface{}

	if err := json.Unmarshal(filter.Value, args); err != nil {
		return nil, errors.Wrapf(err, "while parsing filter argument")
	}

	if err := t.col.FindOne(lCtx, args).Decode(&todo); err != nil {
		if err == mongo.ErrNoDocuments {
			log.Println("empty document response")
			return nil, fmt.Errorf(`todo does not exists`)
		} else {
			log.Println("error not nil from findOne: ", err)
			return nil, err
		}
	} else {
		return TodoToGrpc(&todo), nil
	}
}

func (t *TodoManager) All(ctx context.Context, args *wrapperspb.BytesValue, limit, page int64) (*pb.ListTodoResponse, error) {
	_, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var todos []*Todo

	opts := newMongoPaginate(limit, page).getPaginatedOpts()
	opts.SetSort(bson.M{"createdAt": -1})

	var filter interface{}

	if err := json.Unmarshal(args.Value, &filter); err != nil {
		return nil, errors.Wrapf(err, "while converting to interface")
	}

	if filter == nil {
		filter = bson.D{}
	}

	cursor, err := t.col.Find(context.TODO(), filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrapf(err, "request returned no documents")
		}
		return nil, errors.Wrapf(err, "unexpected error occured")
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		todo := Todo{}
		err := cursor.Decode(&todo)
		if err != nil {
			return nil, errors.Wrapf(err, "unexpected results while decoding")
		}
		todos = append(todos, &todo)
	}
	if err := cursor.Err(); err != nil {
		return nil, errors.Wrapf(err, "cursor lead error")
	}
	if len(todos) == 0 {
		return &pb.ListTodoResponse{}, nil
	}
	return newTodoListResponse(todos), nil
}

func (t *TodoManager) Search(ctx context.Context, q string, limit, page int64) (*pb.ListTodoResponse, error) {
	lCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var todos []*Todo

	filter := bson.M{"$text": bson.M{"$search": q}}

	opts := newMongoPaginate(limit, page).getPaginatedOpts()
	opts.SetSort(bson.M{"createdAt": -1})

	cursor, err := t.col.Find(context.TODO(), filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(lCtx)

	for cursor.Next(context.TODO()) {
		todo := &Todo{}
		err := cursor.Decode(&todo)
		if err != nil {
			return nil, err
		}
		todos = append(todos, todo)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}

	if len(todos) == 0 {
		return &pb.ListTodoResponse{}, nil
	}
	return newTodoListResponse(todos), nil
}
