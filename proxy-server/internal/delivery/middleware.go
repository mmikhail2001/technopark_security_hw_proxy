package delivery

import (
	"log"
	"net/http"
	"time"

	"github.com/mmikhail2001/technopark_security_hw_proxy/proxy-server/internal/domain"
)

type Middleware struct {
	repo Repository
}

func NewMiddleware(repo Repository) Middleware {
	return Middleware{repo: repo}
}

func (mw *Middleware) Save(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Test", "test")

		headers := make(map[string]string)
		for name, values := range r.Header {
			for _, value := range values {
				headers[name] = value
			}
		}

		req := domain.Request{
			Host:    r.Host,
			Method:  r.Method,
			Version: r.Proto,
			Path:    r.URL.Path,
			Headers: headers,
			Time:    time.Now(),
		}

		err := mw.repo.Add(req)
		if err != nil {
			log.Println("error to add request to db", err)
		}

		upstream.ServeHTTP(w, r)
	})
}
