package rdns

import (
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

type MASQUEListener struct {
	id         string
	addr       string
	template   *uritemplate.Template
	quicServer *http3.Server

	opt MASQUEListenerOptions
}

var _ Listener = &MASQUEListener{}

type MASQUEListenerOptions struct {
	TLSConfig  *tls.Config
	ServerName string
}

func NewMASQUEListener(id, endpoint string, opt MASQUEListenerOptions) (*MASQUEListener, error) {
	template := uritemplate.MustNew(opt.ServerName + "/masque?h={target_host}&p={target_port}")
	s := &MASQUEListener{
		id:       id,
		addr:     endpoint,
		template: template,
		opt:      opt,
	}
	http.HandleFunc("/masque", s.MasqueHandler)
	return s, nil
}

func (s *MASQUEListener) MasqueHandler(w http.ResponseWriter, r *http.Request) {
	var proxy masque.Proxy
	Log.Debug("new request received /masque")
	// parse the UDP proxying request
	mreq, err := masque.ParseRequest(r, s.template)
	if err != nil {
		var perr *masque.RequestParseError
		Log.Debug("parse error")
		if errors.As(err, &perr) {
			w.WriteHeader(perr.HTTPStatus)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// start proxying UDP datagrams back and forth
	err = proxy.Proxy(w, mreq)
	if err != nil {
		Log.Debug("encountered error during proxy operation")
	}
	Log.Debug("handler done")
}

func (s *MASQUEListener) String() string {
	return s.id
}

// Start the DoH server with QUIC transport.
func (s *MASQUEListener) Start() error {
	Log.Debug("starting MASQUE listener")
	s.quicServer = &http3.Server{
		Addr:            s.addr,
		TLSConfig:       s.opt.TLSConfig,
		EnableDatagrams: true,
	}
	return s.quicServer.ListenAndServe()
}

// Stop the server.
func (s *MASQUEListener) Stop() error {
	Log.Debug("stopping listener")
	return s.quicServer.Close()
}
