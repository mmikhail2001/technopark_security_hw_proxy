package delivery

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"time"
)

// Forward proxy
// - подменяет сертификат для каждого соединения
type Proxy struct {
	// перехват запроса
	Wrap func(upstream http.Handler) http.Handler

	// - корневой сертификат
	// - подписывает сертификаты под каждый сервер назначения
	CA *tls.Certificate

	// - конфиг прокси-сервера как сервера для клиента
	TLSServerConfig *tls.Config

	// - конфиг прокси-сервера как клиента для сервера назначения
	TLSClientConfig *tls.Config

	FlushInterval time.Duration
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		// HTTPS соединение
		p.serveConnect(w, r)
		return
	}
	// HTTP соединение
	// httputil.ReverseProxy реализует http.Handler (имеет метод ServeHTTP)
	reverseProxy := &httputil.ReverseProxy{
		Director:      httpDirector,
		FlushInterval: p.FlushInterval,
	}
	p.Wrap(reverseProxy).ServeHTTP(w, r)
}

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

func httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}
