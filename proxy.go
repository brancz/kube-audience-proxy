/*
Copyright 2020 Frederic Branczyk All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

const (
	DefaultAudienceParameter = "kubernetes-audience"
)

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

type Proxy struct {
	logger log.Logger

	// transport specifies the roundtripper to use to request the upstream.
	transport http.RoundTripper

	// tokenRetriever specifies the TokenRetriever to use to inject the
	// Authorization token into the request to the upstream.
	tokenRetriever TokenRetriever

	// audienceParameter specifies the
	audienceParameter string

	// tokenCache is used to cache token request responses for certain audiences.
	tokenCache *tokenCache

	// certCache is used to cache certificates generated on the fly for upstream targets.
	certCache *certCache

	// ca specifies the CA to use to generate certs for incoming requests.
	ca *tls.Certificate

	// tlsServerConfig specifies the tls.Config to use when generating leaf
	// cert using CA.
	tlsServerConfig *tls.Config

	// tlsClientConfig specifies the tls.Config to use when requesting the upstream.
	tlsClientConfig *tls.Config
}

func NewProxy(logger log.Logger, transport http.RoundTripper, tokenRetriever TokenRetriever, audienceParameter string, ca *tls.Certificate, tlsServerConfig, tlsClientConfig *tls.Config) *Proxy {
	return &Proxy{
		logger:            logger,
		transport:         transport,
		tokenRetriever:    tokenRetriever,
		audienceParameter: audienceParameter,
		ca:                ca,
		tlsServerConfig:   tlsServerConfig,
		tlsClientConfig:   tlsClientConfig,
		tokenCache:        newTokenCache(),
		certCache:         newCertCache(),
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dump, _ := httputil.DumpRequest(r, true)
	level.Debug(p.logger).Log("msg", "request processing request", "request", string(dump))

	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}

	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = r.Host
			r.URL.Scheme = "http"
		},
		Transport:     NewTokenRoundTripper(p.logger, p.transport, p.tokenRetriever, p.tokenCache, p.audienceParameter),
		FlushInterval: 5 * time.Second,
	}
	rp.ServeHTTP(w, r)
}

type TokenRoundTripper struct {
	retriever         TokenRetriever
	transport         http.RoundTripper
	logger            log.Logger
	audienceParameter string
	tokenCache        *tokenCache
}

func NewTokenRoundTripper(logger log.Logger, transport http.RoundTripper, retriever TokenRetriever, tokenCache *tokenCache, audienceParameter string) TokenRoundTripper {
	return TokenRoundTripper{
		logger:            logger,
		transport:         transport,
		retriever:         retriever,
		audienceParameter: audienceParameter,
		tokenCache:        tokenCache,
	}
}

func (t TokenRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	q := r.URL.Query()
	audience := q.Get(t.audienceParameter)
	level.Debug(t.logger).Log("msg", "extracting audience from proxying request", "url", r.URL, "audience", audience)
	if audience == "" {
		return nil, nil
	}

	token, err := t.tokenFor(audience)
	if err == nil {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	if err != nil {
		level.Error(t.logger).Log("msg", "failed to retrieve token", "err", err)
	}

	return t.transport.RoundTrip(r)
}

func (t TokenRoundTripper) tokenFor(audience string) (string, error) {
	token, exists := t.tokenCache.Get(audience)
	if exists {
		return token, nil
	}

	token, err := t.retriever.TokenFor(audience)
	if err != nil {
		return "", err
	}

	t.tokenCache.Set(audience, token)
	return token, nil
}

// based on github.com/kr/mitm
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		sconn *tls.Conn
		name  = dnsName(r.Host)
	)

	if name == "" {
		level.Error(p.logger).Log("msg", "cannot determine cert name", "host", r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	level.Debug(p.logger).Log("msg", "create provisional cert", "name", name)
	if err != nil {
		level.Error(p.logger).Log("msg", "could not create provisional cert", "err", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if p.tlsServerConfig != nil {
		*sConfig = *p.tlsServerConfig
	}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		level.Debug(p.logger).Log("msg", "get cert")
		cConfig := new(tls.Config)
		if p.tlsClientConfig != nil {
			*cConfig = *p.tlsClientConfig
		}

		serverName := hello.ServerName
		if len(serverName) == 0 {
			serverName = name
		}

		cConfig.ServerName = serverName
		level.Debug(p.logger).Log("msg", "tls dial", "host", r.Host, "servername", serverName)
		sconn, err = tls.Dial("tcp", r.Host, cConfig)
		if err != nil {
			level.Error(p.logger).Log("msg", "failed to dial", "host", r.Host, "err", err)
			return nil, err
		}

		level.Debug(p.logger).Log("msg", "creating provisional cert", "servername", serverName)
		return p.cert(serverName)
	}

	cconn, err := p.handshake(w, sConfig)
	if err != nil {
		level.Error(p.logger).Log("msg", "handshake", "host", r.Host, "err", err)
		return
	}
	defer cconn.Close()
	if sconn == nil {
		level.Error(p.logger).Log("msg", "could not determine cert name", "host", r.Host)
		return
	}
	defer sconn.Close()

	od := &oneShotDialer{c: sconn}
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = r.Host
			r.URL.Scheme = "https"
		},
		Transport:     NewTokenRoundTripper(p.logger, &http.Transport{DialTLS: od.Dial}, p.tokenRetriever, p.tokenCache, p.audienceParameter),
		FlushInterval: 5 * time.Second,
	}

	ch := make(chan int)
	wc := &onCloseConn{cconn, func() { ch <- 0 }}
	http.Serve(&oneShotListener{wc}, rp)
	<-ch
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	cert, exists := p.certCache.Get(names...)
	if exists {
		return cert, nil
	}

	cert, err := genCert(p.ca, names)
	if err != nil {
		return nil, err
	}

	p.certCache.Set(cert, names...)
	return cert, nil
}

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake. It returns the net.Conn or and
// error if any.
func (p *Proxy) handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	level.Debug(p.logger).Log("msg", "hijack connection")
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	level.Debug(p.logger).Log("msg", "respond to connect")
	if _, err = raw.Write(okHeader); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Server(raw, config)
	level.Debug(p.logger).Log("msg", "handshake")
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	level.Debug(p.logger).Log("msg", "handshake done")
	return conn, nil
}

// dnsName returns the DNS name in addr, if any.
func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
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
		return nil, errors.New("closed")
	}
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
		c.f = nil
	}
	return c.Conn.Close()
}
