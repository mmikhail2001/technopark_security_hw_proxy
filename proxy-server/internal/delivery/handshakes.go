package delivery

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/mmikhail2001/technopark_security_hw_proxy/proxy-server/pkg/cert"
)

// каждый раз, когда устанавливается новое TLS-соединение,
// создается новый обратный прокси и вызывается http.Serve для обработки запросов через это соединение.
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		// сервер назначения
		targetConn *tls.Conn
		targetName = dnsName(r.Host)
	)

	if targetName == "" {
		log.Println("cannot determine cert name for " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	// подменный сертификат, который отдадим клиенту
	// dns = targetName, подписан корневым
	tmpCert, err := cert.GenCert(p.CA, []string{targetName})
	if err != nil {
		log.Println("cert targetName", err)
		http.Error(w, "no upstream", 503)
		return
	}

	serverProxyConfig := new(tls.Config)
	if p.TLSServerConfig != nil {
		*serverProxyConfig = *p.TLSServerConfig
	}

	serverProxyConfig.Certificates = []tls.Certificate{*tmpCert}
	// после ClientHello сервер должен отдать сертификат
	// сервер вызывает этот кулбек, чтобы в зависимости от ClientHelloInfo выдать правильный сертификат
	// генерация сертификата на основе имени хоста, указанного в запросе клиента.
	serverProxyConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Метод GetCertificate - у сервера есть несколько сертификатов и нужно выбрать подходящий сертификат в зависимости от параметров соединения или других факторов.
		clientProxyConfig := new(tls.Config)
		if p.TLSClientConfig != nil {
			*clientProxyConfig = *p.TLSClientConfig
		}
		// Это поле определяет ожидаемое имя сервера, которое будет использоваться во время TLS handshake.
		// Полезно, когда сервер использует виртуальные хосты (SNI - Server Name Indication) и требует, чтобы клиент указал ожидаемое имя сервера.

		clientProxyConfig.ServerName = hello.ServerName

		// соединение с сервером назначения
		targetConn, err = tls.Dial("tcp", r.Host, clientProxyConfig)
		if err != nil {
			log.Println("dial", r.Host, err)
			return nil, err
		}
		return cert.GenCert(p.CA, []string{hello.ServerName})
	}

	clientConn, err := connectClient(w, serverProxyConfig)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	defer clientConn.Close()
	if targetConn == nil {
		// TODO: не понятна
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	defer targetConn.Close()

	// TODO: oneShotDialer - устанавливаем соединение с целевым сервером один раз (далее закрываем)
	dialer := &oneShotDialer{targetConn: targetConn}
	reverseProxy := &httputil.ReverseProxy{
		// Director - функция изменения исходного запроса перед перенаправлением
		Director: httpsDirector,
		// настройки для установки соединения
		Transport:     &http.Transport{DialTLS: dialer.Dial},
		FlushInterval: p.FlushInterval,
	}

	ch := make(chan int)
	clientConnFastClose := &onCloseConn{clientConn, func() { ch <- 0 }}
	// слушатель, который принимает только одно соединение и затем считается закрытым.
	// http.Serve(&oneShotListener{clientConnFastClose}, p.Wrap(reverseProxy))
	http.Serve(&oneShotListener{clientConnFastClose}, reverseProxy)
	<-ch
}

func connectClient(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	// низкоуровневые операции с Conn
	rawClientConn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	// Ответ ОК перед установлением TLS соединения
	if _, err = rawClientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		rawClientConn.Close()
		return nil, err
	}
	// net.Conn -> tls.Conn
	// это conn клиента, соединение установлено с подменным сертификатом
	clientConn := tls.Server(rawClientConn, config)

	// обмен сертификатами, установление секретного ключа
	err = clientConn.Handshake()
	if err != nil {
		clientConn.Close()
		rawClientConn.Close()
		return nil, err
	}
	return clientConn, nil
}

func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

type oneShotDialer struct {
	targetConn net.Conn
	mu         sync.Mutex
}

func (d *oneShotDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.targetConn == nil {
		return nil, errors.New("closed")
	}
	targetConn := d.targetConn
	d.targetConn = nil
	return targetConn, nil
}

type oneShotListener struct {
	clientConn net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.clientConn == nil {
		return nil, errors.New("closed >>")
	}
	clientConn := l.clientConn
	l.clientConn = nil
	return clientConn, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.clientConn.LocalAddr()
}

type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}
