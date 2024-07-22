package handlers

import (
	"context"
	"encoding/base64"
	"github.com/ottolauncher/gtodo/models"
	"github.com/ottolauncher/gtodo/pb"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type TodoHandler interface {
	GetTodo(c *gin.Context)
	AllTodos(c *gin.Context)
	SearchTodo(c *gin.Context)
	CreateTodo(c *gin.Context)
	BulkTodo(c *gin.Context)
	UpdateTodo(c *gin.Context)
	DeleteTodo(c *gin.Context)
}

// GetTodo get todo from database by criteria from query
// @Summary get todo from database by criteria
// @Description get a todo from database with criteria
// @Tags Todo
// @Param filter query models.Filter true "Filter JSON"
// @Success 200 {object} models.Todo
// @Failure 500 {object} models.ErrorResponse
// @Router /todos [get]
func (r *Resolver) GetTodo(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	paramMap := c.Query("filter")
	var filter []byte
	base64.StdEncoding.Encode(filter, []byte(paramMap))

	req := pb.GetTodoRequest{Filter: &wrapperspb.BytesValue{Value: filter}}

	res, err := r.tdc.GetTodo(context.TODO(), &req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error(), Code: ""})
	} else {
		c.JSON(http.StatusOK, gin.H{"data": res})
	}

}

// AllTodos return list of all todos from database
// @Summary get all todos by pagination
// @Description return list of all todos from the database
// @Tags Todos
// @Param filter query models.Filter true "Filter JSON"
// @Param limit  query string true "Limit String"
// @Param page   query string true "Page String"
// @CollectionFormat multi
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Success 200 {object} []*models.Todo
// @Router /todos [get]
func (r *Resolver) AllTodos(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	l := c.Query("limit")
	p := c.Query("page")
	args := c.Query("filter")

	var filter []byte
	base64.StdEncoding.Encode(filter, []byte(args))

	limit, err := strconv.Atoi(l)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, models.ErrorResponse{Message: err.Error(), Code: ""})
	}
	page, err := strconv.Atoi(p)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, models.ErrorResponse{Message: err.Error(), Code: ""})
	}

	req := &pb.ListTodoRequest{
		Filter: &wrapperspb.BytesValue{Value: filter},
		Limit:  int64(limit),
		Page:   int64(page),
	}

	res, err := r.tdc.ListTodo(context.TODO(), req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error(), Code: ""})
	}

	c.JSON(http.StatusOK, gin.H{"data": res.Todos})

}

// SearchTodo return list of all todos from database by a criteria
// @Summary get all todos by pagination from database by a criteria
// @Description return list of all todos from the database by a criteria
// @Tags Todos
// @Param filter query models.Filter true "Filter JSON"
// @Param limit  query string true "Limit String"
// @Param page   query string true "Page String"
// @CollectionFormat multi
// @Success 200 {object} []*models.Todo
// @Router /todos/search [get]
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
func (r *Resolver) SearchTodo(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	q := c.Query("q")
	l := c.Query("limit")
	p := c.Query("page")
	limit, err := strconv.Atoi(l)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}
	page, err := strconv.Atoi(p)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	req := &pb.SearchTodoRequest{
		Q:     q,
		Limit: int64(limit),
		Page:  int64(page),
	}
	res, err := r.tdc.SearchTodo(context.TODO(), req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}
	c.JSON(http.StatusNotFound, gin.H{"data": res.Todos})

}

// CreateTodo create new todo
// @Summary create new todo
// @Description create new todo
// @Tags Todos
// @Param todo body models.TodoRequest true "TodoRequest JSON"
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Success 201 {object} models.Todo
// @Router /todos [post]
func (r *Resolver) CreateTodo(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	var newTodo models.TodoRequest
	if err := c.ShouldBindBodyWithJSON(&newTodo); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, models.ErrorResponse{Message: err.Error(), Code: ""})
	}
	res, err := r.tdc.CreateTodo(context.TODO(), models.NewTodoToGrpcRequest(&newTodo))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error(), Code: ""})
	} else {
		c.JSON(http.StatusCreated, gin.H{"data": res})
	}
}

// BulkTodo create bulk todos
// @Summary create bulk todos
// @Description create bulk todos
// @Tags Todos
// @Param todo body []*models.TodoRequest true "TodoRequest"
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Success 201 {object} models.DefaultResponse
// @Router /todos/bulk [post]
func (r *Resolver) BulkTodo(c *gin.Context) {
	lCtx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	var (
		bulkReq []*models.TodoRequest
	)
	if err := c.ShouldBindBodyWithJSON(&bulkReq); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, models.ErrorResponse{Message: err.Error(), Code: ""})
		return
	}
	res, err := r.tdc.BulkTodo(lCtx, models.ToTodoBulkRequest(bulkReq))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error(), Code: ""})
		return
	} else {
		c.AbortWithStatusJSON(http.StatusCreated, gin.H{"data": res})
		return
	}
}

// UpdateTodo update todo
// @Summary update todo
// @Description update todo
// @Tags Todos
// @Param todo body models.UpdateTodoRequest true "UpdateTodoRequest JSON"
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Success 201 {object} models.Todo
// @Router /todos [post]
func (r *Resolver) UpdateTodo(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	var update models.UpdateTodoRequest
	if err := c.ShouldBindBodyWithJSON(&update); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error(), Code: ""})
	}
	res, err := r.tdc.UpdateTodo(context.TODO(), models.UpdateTodoToGrpcRequest(&update))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error(), Code: ""})
	} else {
		c.JSON(http.StatusOK, gin.H{"data": res})
	}

}

// Delete delete todo
// @Summary delete todo
// @Description delete todo
// @Tags Todos
// @Param filter query models.Filter true "Filter JSON"
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Success 200 {object} models.DefaultResponse
// @Route  /todos [delete]
func (r *Resolver) DeleteTodo(c *gin.Context) {
	_, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	args := c.Param("filter")

	var filter []byte
	base64.StdEncoding.Encode(filter, []byte(args))
	_, err := r.tdc.DeleteTodo(context.TODO(),
		&pb.DeleteTodoRequest{Filter: &wrapperspb.BytesValue{Value: filter}})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error(), Code: ""})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": "done"})
	}

}
