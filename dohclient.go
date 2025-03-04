package rdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"log/slog"

	"github.com/jtacoma/uritemplates"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// DoHClientOptions contains options used by the DNS-over-HTTP resolver.
type DoHClientOptions struct {
	// Query method, either GET or POST. If empty, POST is used.
	Method string

	// Bootstrap address - IP to use for the service instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Transport protocol to run HTTPS over. "quic" or "tcp", defaults to "tcp".
	Transport string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	TLSConfig *tls.Config

	QueryTimeout time.Duration

	// Optional dialer, e.g. proxy
	Dialer Dialer

	Use0RTT bool

	UseECH       bool
	ResolverList map[string]Resolver
	ECHresolver  string
	echAddress   string
}

// Returns an HTTP client based on the DoH options
func (opt DoHClientOptions) client(endpoint string) (*http.Client, error) {
	var (
		tr  http.RoundTripper
		err error
	)
	switch opt.Transport {
	case "tcp", "":
		tr, err = dohTcpTransport(opt)
	case "quic":
		tr, err = dohQuicTransport(endpoint, opt)
	default:
		err = fmt.Errorf("unknown protocol: '%s'", opt.Transport)
	}
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: tr,
	}, nil
}

// DoHClient is a DNS-over-HTTP resolver with support fot HTTP/2.
type DoHClient struct {
	id       string
	endpoint string
	template *uritemplates.UriTemplate
	client   *http.Client
	opt      DoHClientOptions
	metrics  *ListenerMetrics
}

var _ Resolver = &DoHClient{}

func NewDoHClient(id, endpoint string, opt DoHClientOptions) (*DoHClient, error) {
	// Parse the URL template
	template, err := uritemplates.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	client, err := opt.client(endpoint)
	if err != nil {
		return nil, err
	}

	if opt.Method == "" {
		opt.Method = "POST"
	}
	if opt.Use0RTT && opt.Transport == "quic" {
		opt.Method = "GET"
	}
	if opt.Method != "POST" && opt.Method != "GET" {
		return nil, fmt.Errorf("unsupported method '%s'", opt.Method)
	}
	if opt.QueryTimeout == 0 {
		opt.QueryTimeout = defaultQueryTimeout
	}

	return &DoHClient{
		id:       id,
		endpoint: endpoint,
		template: template,
		client:   client,
		opt:      opt,
		metrics:  NewListenerMetrics("client", id),
	}, nil
}

// Resolve a DNS query.
func (d *DoHClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if d.opt.UseECH {
		err := d.ProcessECH()
		if err != nil {
			return nil, err
		}
	}

	// Packing a message is not always a read-only operation, make a copy
	q = q.Copy()
	log := logger(d.id, q, ci)

	log.Debug("querying upstream resolver",
		slog.String("resolver", d.endpoint),
		slog.String("protocol", "doh"),
		slog.String("method", d.opt.Method),
	)

	// Add padding before sending the query over HTTPS
	padQuery(q)

	// Pack the DNS query into wire format
	msg, err := q.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}

	d.metrics.query.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), d.opt.QueryTimeout)
	defer cancel()

	// Build a DoH request and execute it
	req, err := d.buildRequest(ctx, msg)
	if err != nil {
		return nil, err
	}
	resp, err := d.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Extract the DNS response from the HTTP response
	return d.responseFromHTTP(resp)
}

func (d *DoHClient) buildRequest(ctx context.Context, msg []byte) (*http.Request, error) {
	switch d.opt.Method {
	case "POST":
		return d.buildPostRequest(ctx, msg)
	case "GET":
		return d.buildGetRequest(ctx, msg)
	default:
		return nil, errors.New("unsupported method")
	}
}

func (d *DoHClient) do(req *http.Request) (*http.Response, error) {
	resp, err := d.client.Do(req)
	if err != nil {
		d.metrics.err.Add(req.Method, 1)
		return nil, err
	}
	return resp, err
}

func (d *DoHClient) buildPostRequest(ctx context.Context, msg []byte) (*http.Request, error) {
	// The URL could be a template. Process it without values since POST doesn't use variables in the URL.
	u, err := d.template.Expand(map[string]any{})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(msg))
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")
	return req, nil
}

func (d *DoHClient) buildGetRequest(ctx context.Context, msg []byte) (*http.Request, error) {
	// Encode the query as base64url
	b64 := base64.RawURLEncoding.EncodeToString(msg)

	// The URL must be a template. Process it with the "dns" param containing the encoded query.
	u, err := d.template.Expand(map[string]any{"dns": b64})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}

	method := http.MethodGet
	if d.opt.Use0RTT && d.opt.Transport == "quic" {
		method = http3.MethodGet0RTT
	}

	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	return req, nil
}

func (d *DoHClient) String() string {
	return d.id
}

// Check the HTTP response status code and parse out the response DNS message.
func (d *DoHClient) responseFromHTTP(resp *http.Response) (*dns.Msg, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		d.metrics.err.Add(fmt.Sprintf("http%d", resp.StatusCode), 1)
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		d.metrics.err.Add("read", 1)
		return nil, err
	}
	a := new(dns.Msg)
	err = a.Unpack(rb)
	if err != nil {
		d.metrics.err.Add("unpack", 1)
	} else {
		d.metrics.response.Add(rCode(a), 1)
	}
	return a, err
}

func dohTcpTransport(opt DoHClientOptions) (http.RoundTripper, error) {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       opt.TLSConfig,
		DisableCompression:    true,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	// If we're using a custom tls.Config, HTTP2 isn't enabled by default in
	// the HTTP library. Turn it on for this transport.
	if tr.TLSClientConfig != nil {
		if err := http2.ConfigureTransport(tr); err != nil {
			return nil, err
		}
	}

	// Use a custom dialer if a bootstrap address or local address was provided
	if opt.BootstrapAddr != "" || opt.echAddress != "" || opt.LocalAddr != nil || opt.Dialer != nil {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: opt.LocalAddr}}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if opt.BootstrapAddr != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(opt.BootstrapAddr, port)
			} else if opt.echAddress != "" {
				addr = opt.echAddress
			}
			if opt.Dialer != nil {
				return opt.Dialer.Dial(network, addr)
			}
			return d.DialContext(ctx, network, addr)
		}
	}
	return tr, nil
}

func dohQuicTransport(endpoint string, opt DoHClientOptions) (http.RoundTripper, error) {
	var tlsConfig *tls.Config
	if opt.TLSConfig == nil {
		tlsConfig = new(tls.Config)
	} else {
		tlsConfig = opt.TLSConfig.Clone()
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	// enable TLS session caching for session resumption and 0-RTT
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(100)
	tlsConfig.ServerName = u.Hostname()
	lAddr := net.IPv4zero
	if opt.LocalAddr != nil {
		lAddr = opt.LocalAddr
	}

	dialer := func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
		return newQuicConnection(u.Hostname(), addr, lAddr, tlsConfig, config, opt.Use0RTT)
	}
	if opt.BootstrapAddr != "" || opt.echAddress != "" {
		dialer = func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
			if opt.BootstrapAddr != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(opt.BootstrapAddr, port)
			} else if opt.echAddress != "" {
				addr = opt.echAddress
				Log.Debug("replaced ip with ech ip", "url", addr)
			}
			return newQuicConnection(u.Hostname(), addr, lAddr, tlsConfig, config, opt.Use0RTT)
		}
	}

	tr := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			TokenStore: quic.NewLRUTokenStore(10, 10),
		},
		Dial: dialer,
	}
	return tr, nil
}

// QUIC connection that automatically restarts when it's used after having timed out. Needed
// since the quic-go RoundTripper doesn't have any connection management and timed out
// connections aren't restarted. This one uses EarlyConnection so we can use 0-RTT if the
// server supports it (lower latency)
type quicConnection struct {
	quic.EarlyConnection

	hostname  string
	rAddr     string
	lAddr     net.IP
	tlsConfig *tls.Config
	config    *quic.Config
	mu        sync.Mutex
	udpConn   *net.UDPConn
	Use0RTT   bool
}

func newQuicConnection(hostname, rAddr string, lAddr net.IP, tlsConfig *tls.Config, config *quic.Config, use0RTT bool) (quic.EarlyConnection, error) {
	connection, udpConn, err := quicDial(context.TODO(), rAddr, lAddr, tlsConfig, config, use0RTT)
	if err != nil {
		return nil, err
	}

	Log.Debug("new quic connection",
		slog.String("protocol", "quic"),
		slog.String("hostname", hostname),
		slog.String("remote", rAddr),
		slog.String("local", lAddr.String()),
	)

	return &quicConnection{
		hostname:        hostname,
		rAddr:           rAddr,
		lAddr:           lAddr,
		tlsConfig:       tlsConfig,
		config:          config,
		udpConn:         udpConn,
		EarlyConnection: connection,
		Use0RTT:         use0RTT,
	}, nil
}

func (s *quicConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.EarlyConnection.OpenStreamSync(ctx)
	if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
		Log.Debug("temporary fail when trying to open stream, attempting new connection", "error", err)
		if err = quicRestart(s); err != nil {
			return nil, err
		}
		stream, err = s.EarlyConnection.OpenStreamSync(ctx)
	}
	return stream, err
}

func (s *quicConnection) OpenStream() (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.EarlyConnection.OpenStream()
	if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
		Log.Debug("temporary fail when trying to open stream, attempting new connection", "error", err)
		if err = quicRestart(s); err != nil {
			return nil, err
		}
		stream, err = s.EarlyConnection.OpenStream()
	}
	return stream, err
}

func (s *quicConnection) NextConnection(context.Context) (quic.Connection, error) {
	return nil, errors.New("not implemented")
}

func quicRestart(s *quicConnection) error {
	// Try to open a new connection, but clean up our mess before we do so
	// This function should be called with the quicConnection locked, but lock checking isn't provided
	// in golang; the issue was closed with "Won't fix"
	_ = s.EarlyConnection.CloseWithError(DOQNoError, "")

	// We need to close the UDP socket ourselves as we own the socket not the quic-go module
	// c.f. https://github.com/quic-go/quic-go/issues/1457
	if s.udpConn != nil {
		_ = s.udpConn.Close()
		s.udpConn = nil
	}
	Log.Debug("attempt reconnect", slog.String("protocol", "quic"),
		slog.String("hostname", s.hostname),
		slog.String("local", s.lAddr.String()),
		slog.String("remote", s.rAddr),
	)
	var err error
	var earlyConn quic.EarlyConnection
	earlyConn, s.udpConn, err = quicDial(context.TODO(), s.rAddr, s.lAddr, s.tlsConfig, s.config, s.Use0RTT)
	if err != nil || s.udpConn == nil {
		Log.Error("couldn't restart quic connection", slog.Group("details", slog.String("protocol", "quic"), slog.String("address", s.hostname), slog.String("local", s.lAddr.String())), "error", err)
		return err
	}
	Log.Debug("restarted quic connection", slog.Group("details", slog.String("protocol", "quic"), slog.String("address", s.hostname), slog.String("local", s.lAddr.String()), slog.String("rAddr", s.rAddr)))

	s.EarlyConnection = earlyConn
	return nil
}

func quicDial(ctx context.Context, rAddr string, lAddr net.IP, tlsConfig *tls.Config, config *quic.Config, use0RTT bool) (quic.EarlyConnection, *net.UDPConn, error) {
	var earlyConn quic.EarlyConnection
	udpAddr, err := net.ResolveUDPAddr("udp", rAddr)
	if err != nil {
		Log.Error("couldn't resolve remote addr for UDP quic client", "error", err, "rAddr", rAddr)
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr, Port: 0})
	if err != nil {
		Log.Error("couldn't listen on UDP socket on local address", "error", err, "local", lAddr.String())
		return nil, nil, err
	}

	if use0RTT {
		earlyConn, err = quic.DialEarly(ctx, udpConn, udpAddr, tlsConfig, config)
		if err != nil {
			_ = udpConn.Close()
			Log.Error("couldn't dial quic early connection", "error", err)
			return nil, nil, err
		}
	} else {
		conn, err := quic.Dial(ctx, udpConn, udpAddr, tlsConfig, config)
		if err != nil {
			_ = udpConn.Close()
			Log.Error("couldn't dial quic connection", "error", err)
			return nil, nil, err
		}
		earlyConn = &earlyConnWrapper{Connection: conn}
	}
	return earlyConn, udpConn, nil
}

type earlyConnWrapper struct {
	quic.Connection
}

func (e *earlyConnWrapper) HandshakeComplete() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (e *earlyConnWrapper) NextConnection(ctx context.Context) (quic.Connection, error) {
	return nil, fmt.Errorf("NextConnection not supported for non-0RTT connections")
}

type HTTPSrr struct {
	echConfig []byte
	target    string
	ipv4hint  string
	ipv6hint  string
}

func (d *DoHClient) ProcessECH() error {
	u, err := url.Parse(d.endpoint)
	if err != nil {
		return err
	}

	httpsrr, err := GetECHConfigFromDNS(u.Hostname(), d.opt)
	if err != nil {
		return fmt.Errorf("could not fetch ECH config '%s'", err)
	}

	var ip string
	if httpsrr.ipv4hint != "" {
		ip = httpsrr.ipv4hint
	} else if httpsrr.ipv6hint != "" {
		ip = httpsrr.ipv6hint
	}

	if ip != "" && net.ParseIP(ip) != nil {
		d.opt.echAddress = net.JoinHostPort(ip, u.Port())
		Log.Debug("Connecting to advertised IP from HTTPS RR from now on")
	}

	tlsConfig := d.opt.TLSConfig
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.EncryptedClientHelloConfigList = httpsrr.echConfig
	tlsConfig.ServerName = httpsrr.target
	d.opt.UseECH = false

	d.client, err = d.opt.client("https://" + httpsrr.target)
	if err != nil {
		return err
	}
	return nil
}

func GetECHConfigFromDNS(serverName string, opt DoHClientOptions) (*HTTPSrr, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(serverName), dns.TypeHTTPS)

	var resp *dns.Msg
	var resolvErr error
	if opt.ECHresolver != "" {
		resp, resolvErr = opt.ResolverList[opt.ECHresolver].Resolve(msg, ClientInfo{})
	} else {
		ECHresolver, err := NewDoHClient("echTemp", "https://1.1.1.1/dns-query{?dns}", DoHClientOptions{})
		if err != nil {
			return nil, fmt.Errorf("could not instantiate DoH resolvers for ECH config fetch, last error: %v", err)
		}
		resp, resolvErr = ECHresolver.Resolve(msg, ClientInfo{})
	}

	if resolvErr != nil {
		return nil, fmt.Errorf("ech DNS resolvers failed, last error: %v", resolvErr)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query returned error code: %d", resp.Rcode)
	}

	for _, ans := range resp.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			rr, err := parseHTTPSForECH(https)
			if err == nil && rr != nil {
				return rr, nil
			}
		}
	}

	return nil, errors.New("no ECH configuration found in DNS records")
}

func parseHTTPSForECH(https *dns.HTTPS) (*HTTPSrr, error) {
	var rr = new(HTTPSrr)

	for _, kv := range https.Value {
		if kv.Key() == dns.SVCB_ECHCONFIG {
			conf, err := base64.StdEncoding.DecodeString(kv.String())
			if err != nil {
				return nil, fmt.Errorf("failed to decode ECH config: %v", err)
			}
			rr.echConfig = conf
			break
		}
	}

	for _, kv := range https.Value {
		if kv.Key() == dns.SVCB_IPV6HINT {
			rr.ipv6hint = kv.String()
		} else if kv.Key() == dns.SVCB_IPV4HINT {
			rr.ipv4hint = kv.String()
		}
	}
	rr.target = https.Target
	return rr, nil
}
