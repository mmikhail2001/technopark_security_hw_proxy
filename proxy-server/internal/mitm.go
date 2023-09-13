package mitm

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

// Proxy is a forward proxy that substitutes itsP own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	// Wrap specifies a function for optionally wrapping upstream for
	// inspecting the decrypted HTTP request and response.
	// проверка расшифрованного запроса и ответа
	Wrap func(upstream http.Handler) http.Handler

	// CA specifies the root CA for generating leaf certs for each incoming
	// TLS request.
	CA *tls.Certificate

	// TLSServerConfig specifies the tls.Config to use when generating leaf
	// cert using CA.
	TLSServerConfig *tls.Config

	// TLSClientConfig specifies the tls.Config to use when establishing
	// an upstream connection for proxying.
	// !!! т.е. настройки tls для соединения с сервером назначения
	TLSClientConfig *tls.Config

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("ServeHTTP")
	if r.Method == "CONNECT" {

		// HTTPS
		log.Println("CONNECT")
		p.serveConnect(w, r)
		return
	}
	log.Println("NO CONNECT")

	// HTTP
	rp := &httputil.ReverseProxy{
		// функция для настройки исходящего запроса
		Director: httpDirector,
		// интервал для форсированной отправки данных
		FlushInterval: p.FlushInterval,
	}
	p.Wrap(rp).ServeHTTP(w, r)
}

// обслуживание keep-alive HTTPS соединение
// пока не закроем коннект, не выйдем из функции

// каждый раз, когда устанавливается новое TLS-соединение, создается новый обратный прокси и вызывается http.Serve для обработки запросов через это соединение.
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		// сервер назначения
		sconn *tls.Conn
		name  = dnsName(r.Host)
	)

	log.Printf("name : %s", name)

	if name == "" {
		log.Println("cannot determine cert name for " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	// временный сертификат по хосту назначения
	// подменный сертификат, который отдадим клиенту
	provisionalCert, err := p.cert(name)
	if err != nil {
		log.Println("cert", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if p.TLSServerConfig != nil {
		*sConfig = *p.TLSServerConfig
	}

	sConfig.Certificates = []tls.Certificate{*provisionalCert}
	// после ClientHello сервер должен отдать сертификат
	// сервер вызывает этот кулбек, чтобы в зависимости от ClientHelloInfo выдать правильный сертификат
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		log.Println("GetCertificate")
		// Метод GetCertificate - у сервера есть несколько сертификатов и нужно выбрать подходящий сертификат в зависимости от параметров соединения или других факторов.
		// Например, можно выбрать сертификат на основе имени хоста, указанного в запросе клиента.
		cConfig := new(tls.Config)
		if p.TLSClientConfig != nil {
			*cConfig = *p.TLSClientConfig
		}
		// Это поле определяет ожидаемое имя сервера, которое будет использоваться во время handshake. Это может быть полезно, когда сервер использует виртуальные хосты (SNI - Server Name Indication) и требует, чтобы клиент указал ожидаемое имя сервера.
		cConfig.ServerName = hello.ServerName
		// соединение с сервером назначения!
		log.Printf("Dial with %s from PROXY", r.Host)
		sconn, err = tls.Dial("tcp", r.Host, cConfig)
		if err != nil {
			log.Println("dial", r.Host, err)
			return nil, err
		}
		return p.cert(hello.ServerName)
	}

	cconn, err := handshake(w, sConfig)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	defer cconn.Close()
	if sconn == nil {
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	defer sconn.Close()

	od := &oneShotDialer{c: sconn}
	rp := &httputil.ReverseProxy{
		// Director - функция изменения исходного запроса перед перенаправление
		Director: httpsDirector,
		// как будет установлено соединение с целевым сервером?
		// настройки для установки соединения
		// - oneShotDialer - устанавливаем соединение с целевым сервером один раз. Почему?
		// - после закрытие прокси-conn функция завершится (<-ch)
		Transport:     &http.Transport{DialTLS: od.Dial},
		FlushInterval: p.FlushInterval,
	}

	ch := make(chan int)
	wc := &onCloseConn{cconn, func() { ch <- 0 }}
	// принимает соединения, Accept
	// Это позволяет создать слушатель, который принимает только одно соединение и затем считается закрытым.
	http.Serve(&oneShotListener{wc}, p.Wrap(rp))
	<-ch
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	return genCert(p.CA, names)
}

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake. It returns the net.Conn or and
// error if any.
func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	// Интерфейс Hijacker полезен, когда обработчик HTTP хочет взять контроль над соединением и выполнять низкоуровневые операции с ним
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	// Ответ ОК перед установлением TLS соединения
	log.Printf("resp OK to client")
	if _, err = raw.Write(okHeader); err != nil {
		raw.Close()
		return nil, err
	}
	// config = sConfig с временным сертификатом
	// tls.Conn из net.Conn
	// это conn клиента, соединение установлено с подменным сертификатом
	conn := tls.Server(raw, config)
	// обмен сертификатами, установление секретного ключа
	log.Println("Handshake with CLIENT")
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

func httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}

// dnsName returns the DNS name in addr, if any.
func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// namesOnCert returns the dns names
// in the peer's presented cert.
func namesOnCert(conn *tls.Conn) []string {
	// TODO(kr): handle IP addr SANs.
	c := conn.ConnectionState().PeerCertificates[0]
	if len(c.DNSNames) > 0 {
		// If Subject Alt Name is given,
		// we ignore the common name.
		// This matches behavior of crypto/x509.
		return c.DNSNames
	}
	return []string{c.Subject.CommonName}
}

// A oneShotDialer implements net.Dialer whos Dial only returns a
// net.Conn as specified by c followed by an error for each subsequent Dial.
type oneShotDialer struct {
	c  net.Conn
	mu sync.Mutex
}

func (d *oneShotDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c == nil {
		log.Println(">>> Dial nil")
		return nil, errors.New("closed")
	}
	c := d.c
	d.c = nil
	return c, nil
}

// A oneShotListener implements net.Listener whos Accept only returns a
// net.Conn as specified by c followed by an error for each subsequent Accept.
type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		log.Println(">>> Accept nil")
		return nil, errors.New("closed")
	}
	log.Println(">>> Conn Accept BUSY")
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		log.Println(">>> Close nil")
		c.f = nil
	}
	return c.Conn.Close()
}
