package rdns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jtacoma/uritemplates"
	"github.com/miekg/dns"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// MASQUEClient is a MASQUED DNS-over-HTTP/3 resolver.
type MASQUEClient struct {
	id     string
	proxy  string
	target string

	template *uritemplate.Template
	client   *http.Client
	opt      MASQUEClientOptions
}

var _ Resolver = &MASQUEClient{}

type MASQUEClientOptions struct {
	QueryTimeout time.Duration
}

func NewMASQUEClient(id, proxy string, endpoint string, opt MASQUEClientOptions) (*MASQUEClient, error) {
	// Parse the URL template
	mproxy, err := ensureHTTPSPort(proxy)
	if err != nil {
		return nil, err
	}
	template := uritemplate.MustNew(mproxy + "?h={target_host}&p={target_port}")

	if opt.QueryTimeout == 0 {
		opt.QueryTimeout = defaultQueryTimeout
	}

	mdoh := &MASQUEClient{
		id:       id,
		proxy:    mproxy,
		target:   endpoint,
		template: template,
		client:   SetupMasque(template, endpoint),
		opt:      opt,
	}

	return mdoh, nil
}

func SetupMasque(proxyURITemplate *uritemplate.Template, url string) *http.Client {
	cl := masque.Client{
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}
	host, err := extractHostPort(url)
	if err != nil {
		Log.Error("failed to parse url:", "error", err)
	}

	return &http.Client{
		Transport: &http3.Transport{
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				raddr, err := net.ResolveUDPAddr("udp", host)
				if err != nil {
					return nil, err
				}
				pconn, _, err := cl.Dial(context.Background(), proxyURITemplate, raddr)
				if err != nil {
					Log.Error("dialing MASQUE failed:", "error", err)
				}
				Log.Error(fmt.Sprintf("dialed connection: %s <-> %s", pconn.LocalAddr(), raddr))
				return quic.DialEarly(ctx, pconn, raddr, tlsConf, &quic.Config{DisablePathMTUDiscovery: true})
			},
		},
	}
}

func extractHostPort(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}

	// Check if port is explicitly set
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	Log.Debug("old: " + target + " new: " + host)
	return host, nil
}

// Resolve a DNS query.
func (d *MASQUEClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	q = q.Copy()
	padQuery(q)

	// Pack the DNS query into wire format
	msg, err := q.Pack()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.opt.QueryTimeout)
	defer cancel()

	// Build a DoH request and execute it
	req, err := d.buildRequest(msg, ctx)
	if err != nil {
		return nil, err
	}

	rsp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	// Extract the DNS response from the HTTP response
	return responseFromHTTP(rsp)
}

func (d *MASQUEClient) String() string {
	return d.id
}

func (d *MASQUEClient) buildRequest(msg []byte, ctx context.Context) (*http.Request, error) {
	// Encode the query as base64url
	b64 := base64.RawURLEncoding.EncodeToString(msg)
	template, err := uritemplates.Parse(d.target)
	if err != nil {
		return nil, err
	}

	// The URL must be a template. Process it with the "dns" param containing the encoded query.
	u, err := template.Expand(map[string]interface{}{"dns": b64})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	return req, nil
}

func ensureHTTPSPort(template string) (string, error) {
	u, err := url.Parse(template)
	if err != nil {
		return "", err
	}

	if u.Scheme != "https" {
		return "", fmt.Errorf("only 'https' URLs are supported")
	}

	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		// Add default HTTPS port if missing
		u.Host = net.JoinHostPort(u.Hostname(), "443")
	}

	return u.String(), nil
}

// Check the HTTP response status code and parse out the response DNS message.
func responseFromHTTP(resp *http.Response) (*dns.Msg, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	a := new(dns.Msg)
	err = a.Unpack(rb)
	return a, err
}
