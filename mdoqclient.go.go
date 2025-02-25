package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
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
	net.PacketConn
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

func initMasque(template *uritemplate.Template, url string) (net.PacketConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", url)
	if err != nil {
		Log.Error("failed to resolve udp addr:", "error", err)
		return nil, err
	}

	cl := masque.Client{
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}

	Log.Debug(fmt.Sprintf("parsed url: %s -> %s", url, raddr))
	pconn, _, err := cl.Dial(context.Background(), template, raddr)
	if err != nil {
		Log.Error("failed to dial masque proxy:", "error", err)
		return nil, err
	}
	return pconn, err
}

func (d *MDoQClient) masqueDial(endpoint string) (quic.EarlyConnection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		Log.Debug("couldn't resolve remote addr (" + endpoint + ") for UDP quic client")
		return nil, err
	}

	tlsConfig := new(tls.Config)
	tlsConfig.NextProtos = []string{"doq"}
	// use DialEarly so that we attempt to use 0-RTT DNS queries, it's lower latency (if the server supports it)
	earlyConn, err := quic.DialEarly(context.Background(), d.PacketConn, udpAddr, tlsConfig, &quic.Config{DisablePathMTUDiscovery: true})
	if err != nil {
		// don't leak filehandles / sockets; if we got here udpConn must exist
		_ = d.PacketConn.Close()
		Log.Debug("couldn't dial quic early connection")
		return nil, err
	}

	return earlyConn, err
}

func (d *MDoQClient) getMasqueStream() (quic.Stream, error) {
	stream, err := d.EarlyConnection.OpenStream()
	if err != nil {
		Log.Debug("temporary fail when trying to open stream, attempting new connection")
	}
	Log.Debug("got new stream")
	return stream, err
}

// Resolve a DNS query.
func (d *MDoQClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if d.PacketConn == nil {
		conn, err := initMasque(d.template, d.target)
		if err != nil {
			Log.Error("failed to connect to masque proxy:", "error", err)
			return nil, err
		}
		d.PacketConn = conn
	}
	Log.Debug("have masque packetConn")

	if d.EarlyConnection == nil {
		conn, err := d.masqueDial(d.target)
		if err != nil {
			Log.Error("failed to dial target via masque proxy:", "error", err)
			return nil, err
		}
		Log.Debug("got new Early Conn")
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
	stream, err := d.getMasqueStream()
	if err != nil {
		return nil, err
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
