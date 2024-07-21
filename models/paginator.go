package models

import (
        "go.mongodb.org/mongo-driver/mongo/options"
)

type mongoPaginate struct {
        limit int64
        page  int64
}

func newMongoPaginate(limit, page int64) *mongoPaginate {
        if limit < 1 {
                limit = 12
        }
        if page < 1 {
                page = 1
        }
        return &mongoPaginate{
                limit: limit,
                page:  page,
        }
}

func (mp *mongoPaginate) getPaginatedOpts() *options.FindOptions {
        l := mp.limit
        skip := mp.page*mp.limit - mp.limit
        fOpt := options.FindOptions{Limit: &l, Skip: &skip}

        return &fOpt
}

