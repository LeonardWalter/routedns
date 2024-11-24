// The MIT License
//
// Copyright (c) 2019-2020, Cloudflare, Inc. and Apple, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package rdns

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/cisco/go-hpke"
	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	// HPKE constants
	kemID  = hpke.DHKEM_X25519
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AESGCM128

	defaultSeedLength = 32
)

// ODoHListener is an Oblivious DNS over HTTPS listener.
type ODoHListener struct {
	id         string
	addr       string
	dohClientP *DoHClientPool // Client pool for proxy forwarding if acting as ODoH proxy
	dohServer  *DoHListener

	r           Resolver // Forwarding DNS queries if acting as ODoH Target
	opt         ODoHListenerOptions
	odohKeyPair odoh.ObliviousDoHKeyPair
}

type ODoHListenerOptions struct {
	ListenOptions

	OdohMode  string
	AllowDoH  bool
	KeySeed   string
	Transport string
	TLSConfig *tls.Config
}

var _ Listener = &ODoHListener{}

// NewODoHListener returns an instance of an oblivious DNS-over-HTTPS listener.
func NewODoHListener(id, addr string, opt ODoHListenerOptions, resolver Resolver) (*ODoHListener, error) {
	keyPair, err := getKeyPair(opt)
	if err != nil {
		log.Fatalf("Failed to generate HPKE key pair: %v", err)
		return nil, err
	}

	dohOpt := DoHListenerOptions{
		TLSConfig: opt.TLSConfig,
		Transport: opt.Transport,
		isChild:   true,
	}
	dohListen, err := NewDoHListener(id, addr, dohOpt, resolver)
	if err != nil {
		log.Fatalf("Failed to spawn DoH listener: %v", err)
		return nil, err
	}

	l := &ODoHListener{
		id:          id,
		addr:        addr,
		r:           resolver,
		opt:         opt,
		odohKeyPair: keyPair,
		dohServer:   dohListen,
		dohClientP:  NewDoHClientPool(10),
	}

	switch opt.OdohMode {
	case "proxy":
		http.HandleFunc("/proxy", l.ODoHproxyHandler)
	case "target":
		http.HandleFunc("/dns-query", l.ODoHqueryHandler)
		http.HandleFunc("/.well-known/odohconfigs", l.configHandler)
	default:
		http.HandleFunc("/proxy", l.ODoHproxyHandler)
		http.HandleFunc("/dns-query", l.ODoHqueryHandler)
		http.HandleFunc("/.well-known/odohconfigs", l.configHandler)
	}
	return l, nil
}

func (s *ODoHListener) Start() error {
	return s.dohServer.Start()
}

func (s *ODoHListener) Stop() error {
	return s.dohServer.Stop()
}

func (s *ODoHListener) ODoHproxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	contentType := r.Header.Get("Content-Type")
	host := r.URL.Query().Get("targethost")
	if host == "" {
		http.Error(w, "no targethost specified", http.StatusBadRequest)
		return
	}
	path := r.URL.Query().Get("targetpath")
	if path == "" {
		http.Error(w, "no targetpath specified", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	client, err := s.dohClientP.GetClient(host)
	if err != nil {
		var err error
		tlsConfig, err := TLSClientConfig("", "", "", host)
		if err != nil {
			return
		}
		opt := DoHClientOptions{
			Method:    r.Method,
			Transport: s.opt.Transport,
			TLSConfig: tlsConfig,
		}
		client, err = s.dohClientP.AddClient(host, path, opt)
		if err != nil {
			Log.Printf("Adding new client failed")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	Log.WithFields(logrus.Fields{"client": r.RemoteAddr, "target": host}).Debug("forwarding query to ODoH target")
	response, err := forwardProxyRequest(client, host, path, b, contentType)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if response.StatusCode != 200 {
		http.Error(w, http.StatusText(response.StatusCode), response.StatusCode)
		return
	}

	defer response.Body.Close()
	rb, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(rb)
}

func forwardProxyRequest(client *http.Client, targethost string, targetPath string, body []byte, contentType string) (*http.Response, error) {
	targetURL := "https://" + targethost + targetPath
	req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
	if err != nil {
		log.Println("Failed creating target POST request")
		return nil, errors.New("failed creating target POST request")
	}
	req.Header.Set("Content-Type", contentType)
	return client.Do(req)
}

func (s *ODoHListener) ODoHqueryHandler(w http.ResponseWriter, r *http.Request) {
	qHeader := r.Header.Get("Content-Type")
	if r.Method != "POST" || qHeader == "application/dns-message" {
		if s.opt.AllowDoH {
			Log.Debug("Forwarding DoH query")
			s.dohServer.dohHandler(w, r)
			return
		} else {
			Log.Debug("DoH queries disabled, dropping DoH message")
			http.Error(w, "only contentType oblivious-dns-message allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if qHeader != "application/oblivious-dns-message" {
		http.Error(w, "only contentType oblivious-dns-message allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	msg, err := odoh.UnmarshalDNSMessage(b)
	if err != nil {
		http.Error(w, "error while parsing oblivious query", http.StatusBadRequest)
		return
	}

	obliviousQuery, responseContext, err := s.odohKeyPair.DecryptQuery(msg)
	if err != nil {
		http.Error(w, "error while decrypting oblivious query", http.StatusBadRequest)
		return
	}
	q, err := decodeDNSQuestion(obliviousQuery.Message())
	if err != nil {
		http.Error(w, "decodeDNSQuestion failed", http.StatusBadRequest)
		return
	}

	ci := ClientInfo{
		Listener:      s.id,
		TLSServerName: r.TLS.ServerName,
	}
	a, err := s.r.Resolve(q, ci)
	if err != nil {
		Log.WithError(err).Error("failed to resolve")
		a = new(dns.Msg)
		a.SetRcode(q, dns.RcodeServerFailure)
	}

	p, err := a.Pack()
	if err != nil {
		Log.WithError(err).Error("failed to encode response")
		return
	}

	obliviousResponse, err := s.createObliviousResponseForQuery(responseContext, p)
	if err != nil {
		http.Error(w, "createObliviousResponseForQuery failed", http.StatusBadRequest)
		return
	}

	packedResponseMessage := obliviousResponse.Marshal()
	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.Write(packedResponseMessage)
}

func decodeDNSQuestion(encodedMessage []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(encodedMessage)
	return msg, err
}

func (s *ODoHListener) createObliviousResponseForQuery(context odoh.ResponseContext, dnsResponse []byte) (odoh.ObliviousDNSMessage, error) {
	response := odoh.CreateObliviousDNSResponse(dnsResponse, 0)
	odohResponse, err := context.EncryptResponse(response)
	return odohResponse, err
}

func (s *ODoHListener) String() string {
	return s.id
}

func (s *ODoHListener) configHandler(w http.ResponseWriter, r *http.Request) {
	Log.Printf("%s Handling %s\n", r.Method, r.URL.Path)

	configSet := []odoh.ObliviousDoHConfig{s.odohKeyPair.Config}
	configs := odoh.CreateObliviousDoHConfigs(configSet)
	w.Write(configs.Marshal())
}

func getKeyPair(opt ODoHListenerOptions) (odoh.ObliviousDoHKeyPair, error) {
	var seed []byte
	var err error
	if opt.KeySeed != "" {
		seed, err = hex.DecodeString(opt.KeySeed)
		if err != nil {
			log.Fatalf("Failed to read key seed: %v", err)
		}
	} else {
		seed = make([]byte, defaultSeedLength)
		if _, err := rand.Read(seed); err != nil {
			log.Fatalf("Failed to generate random seed: %v", err)
		}
	}
	return odoh.CreateKeyPairFromSeed(kemID, kdfID, aeadID, seed)
}
