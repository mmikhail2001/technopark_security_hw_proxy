package domain

import "time"

type HTTPTransaction struct {
	ID       interface{} `bson:"_id,omitempty" json:"_id,omitempty"`
	Request  Request     `bson:"request" json:"request"`
	Response Response    `bson:"response" json:"response"`
	Time     time.Time   `bson:"time" json:"time"`
}

type Request struct {
	Host       string            `bson:"host" json:"host"`
	Method     string            `bson:"method" json:"method"`
	Version    string            `bson:"version" json:"version"`
	Path       string            `bson:"path" json:"path"`
	Protocol   string            `bson:"protocol" json:"protocol"`
	Cookies    map[string]string `bson:"cookies, omitempty" json:"cookies, omitempty"`
	Headers    map[string]string `bson:"headers, omitempty" json:"headers, omitempty"`
	GetParams  map[string]string `bson:"get_params, omitempty" json:"get_params, omitempty"`
	PostParams map[string]string `bson:"post_params, omitempty" json:"post_params, omitempty"`
	RawBody    []byte            `bson:"raw_body, omitempty" json:"raw_body, omitempty"`
}

type Response struct {
	StatusCode    int               `bson:"status_code" json:"status_code"`
	Headers       map[string]string `bson:"headers, omitempty" json:"headers, omitempty"`
	ContentLenght int               `bson:"content_length" json:"content_length"`
	RawBody       []byte            `bson:"raw_body, omitempty" json:"raw_body, omitempty"`
	TextBody      string            `bson:"text_body, omitempty" json:"text_body, omitempty"`
}
