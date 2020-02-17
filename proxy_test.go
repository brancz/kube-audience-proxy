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
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
)

func testLogger() log.Logger {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowAll())
	return log.With(logger,
		"ts", log.DefaultTimestampUTC,
		"caller", log.DefaultCaller,
	)
}

type tokenRetrieverFunc func(req *http.Request) (string, error)

func (f tokenRetrieverFunc) TokenFor(req *http.Request) (string, error) {
	return f(req)
}

func testTokenRetriever(l log.Logger, token string) TokenRetriever {
	clientset := &fake.Clientset{}
	clientset.Fake.AddReactor("create", "serviceaccounts", func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
		if action.GetSubresource() == "token" {
			return true, &authenticationv1.TokenRequest{
				Status: authenticationv1.TokenRequestStatus{
					Token: token,
				},
			}, nil
		}

		// This branch is unexpected to happen at all.
		return true, nil, fmt.Errorf("no reaction implemented for %s", action)
	})
	clientset.Fake.AddReactor("*", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("no reaction implemented for %s", action)
	})

	return newTokenRetriever(l, clientset.CoreV1().ServiceAccounts("default"), "default")
}

func TestProxy(t *testing.T) {
	var expectation http.Handler
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		expectation.ServeHTTP(w, req)
	}))

	l := testLogger()
	r := testTokenRetriever(l, "test")
	p := NewProxy(l, s.Client().Transport, r, DefaultAudienceParameter, nil, nil, nil)
	ps := httptest.NewServer(p)

	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			level.Debug(l).Log("msg", "proxy url", "url", ps.URL)
			u, err := url.Parse(ps.URL)
			if err != nil {
				return nil, err
			}
			return u, nil
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	expectation = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatal(err)
		}

		expectedHost := u.Host
		gotHost := req.Host
		if expectedHost != gotHost {
			t.Fatalf("Unexpected host. Expected %q Got %q", expectedHost, gotHost)
		}

		expectedPath := "/metrics"
		gotPath := req.URL.Path
		if expectedPath != gotPath {
			t.Fatalf("Unexpected path. Expected %q Got %q", expectedPath, gotPath)
		}

		expectedAuthHeader := "Bearer test"
		gotAuthHeader := req.Header.Get("Authorization")
		if expectedAuthHeader != gotAuthHeader {
			t.Fatalf("Unexpected Authorization header. Expected %q Got %q", expectedAuthHeader, gotAuthHeader)
		}
	})

	c := &http.Client{Transport: transport}
	u, _ := url.Parse(s.URL)
	u.Scheme = "http"
	reqURL := u.String() + "/metrics?kubernetes-audience=test-audience"
	level.Debug(l).Log("msg", "performing get request with proxy configured", "url", reqURL)
	_, err := c.Get(reqURL)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTLSProxy(t *testing.T) {
	var expectation http.Handler
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		expectation.ServeHTTP(w, req)
	}))

	l := testLogger()
	r := testTokenRetriever(l, "test")

	certPEM, _, ca, err := genAndParseCACert()
	if err != nil {
		t.Fatal(err)
	}

	p := NewProxy(l, s.Client().Transport, r, DefaultAudienceParameter, ca, nil, s.Client().Transport.(*http.Transport).TLSClientConfig)
	ps := httptest.NewServer(p)

	level.Debug(l).Log("msg", "proxy url", "url", ps.URL)
	u, err := url.Parse(ps.URL)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	tlsClientConfig := &tls.Config{
		RootCAs: pool,
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(u),
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsClientConfig,
	}
	c := http.Client{Transport: transport}

	expectation = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatal(err)
		}

		expectedHost := u.Host
		gotHost := req.Host
		if expectedHost != gotHost {
			t.Fatalf("Unexpected host. Expected %q Got %q", expectedHost, gotHost)
		}

		expectedPath := "/metrics"
		gotPath := req.URL.Path
		if expectedPath != gotPath {
			t.Fatalf("Unexpected path. Expected %q Got %q", expectedPath, gotPath)
		}

		expectedAuthHeader := "Bearer test"
		gotAuthHeader := req.Header.Get("Authorization")
		if expectedAuthHeader != gotAuthHeader {
			t.Fatalf("Unexpected Authorization header. Expected %q Got %q", expectedAuthHeader, gotAuthHeader)
		}
	})

	reqURL := s.URL + "/metrics?kubernetes-audience=test-audience"
	level.Debug(l).Log("msg", "performing get request with proxy configured", "url", reqURL)
	_, err = c.Get(reqURL)
	if err != nil {
		t.Fatal(err)
	}
}
