package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/yosida95/uritemplate/v3"
)

type MDoQClient struct {
	id       string
	proxy    string
	target   string
	template *uritemplate.Template

	client *DoQClient
	quic.EarlyConnection
}

var _ Resolver = &MDoQClient{}

func NewMDoQClient(id, proxy string, endpoint string, opt DoQClientOptions) (*MDoQClient, error) {
	// Parse the URL template
	mproxy, err := ensureHTTPSPort(proxy)
	if err != nil {
		return nil, err
	}
	template := uritemplate.MustNew(mproxy + "?h={target_host}&p={target_port}")

	cl, err := NewDoQClient(id, endpoint, opt)
	if err != nil {
		return nil, err
	}

	return &MDoQClient{
		id:       id,
		proxy:    mproxy,
		target:   endpoint,
		template: template,
		client:   cl,
	}, nil
}

func (d *MDoQClient) masqueDial(url string) (quic.EarlyConnection, error) {
	cl := masque.Client{
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1320,
		},
	}

	pconn, _, err := cl.DialAddr(context.Background(), d.template, url)
	if err != nil {
		Log.Error("failed to dial masque proxy:", "error", err)
		return nil, err
	}

	host, _, err := net.SplitHostPort(d.target)
	if err != nil {
		Log.Error("failed to parse target address:", "error", err)
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", d.target)
	if err != nil {
		Log.Debug("couldn't resolve remote addr (" + d.target + ") for UDP quic client")
		return nil, err
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"doq"},
		ServerName: host,
	}

	earlyConn, err := quic.DialEarly(context.Background(), pconn, udpAddr, tlsConfig, &quic.Config{DisablePathMTUDiscovery: true})
	if err != nil {
		_ = pconn.Close()
		Log.Debug("couldn't dial quic early connection")
		return nil, err
	}

	return earlyConn, err
}

// Resolve a DNS query.
func (d *MDoQClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if d.EarlyConnection == nil {
		conn, err := d.masqueDial(d.target)
		if err != nil {
			Log.Error("failed to dial target via masque proxy:", "error", err)
			return nil, err
		}
		d.EarlyConnection = conn
	}

	qc := q.Copy()
	qc.Id = 0

	deadlineTime := time.Now().Add(2 * time.Second)

	// Encode the query
	p, err := qc.Pack()
	if err != nil {
		return nil, err
	}

	// Add a length prefix
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)

	// Get a new stream in the connection
	var stream quic.Stream
	for range 2 {
		stream, err = d.EarlyConnection.OpenStream()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				conn, err := d.masqueDial(d.target)
				if err != nil {
					Log.Error("failed to dial target via masque proxy:", "error", err)
					return nil, err
				}
				d.EarlyConnection = conn
				continue
			}
			return nil, err
		}
		break
	}

	// Write the query into the stream and close it. Only one stream per query/response
	_ = stream.SetWriteDeadline(deadlineTime)
	if _, err = stream.Write(b); err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}

	_ = stream.SetReadDeadline(deadlineTime)

	// DoQ requires a length prefix, like TCP
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	// Read the response
	b = make([]byte, length)
	if _, err = io.ReadFull(stream, b); err != nil {
		return nil, err
	}

	// Decode the response and restore the ID
	a := new(dns.Msg)
	err = a.Unpack(b)
	a.Id = q.Id

	return a, err
}

func (d *MDoQClient) String() string {
	return d.id
}
