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
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	k8sapiflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog"

	"github.com/brancz/kube-audience-proxy/version"
)

const (
	logLevelAll   = "all"
	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
	logLevelNone  = "none"

	logFormatLogfmt = "logfmt"
	logFormatJson   = "json"
)

var (
	availableLogLevels = []string{
		logLevelAll,
		logLevelDebug,
		logLevelInfo,
		logLevelWarn,
		logLevelError,
		logLevelNone,
	}
	availableLogFormats = []string{
		logFormatLogfmt,
		logFormatJson,
	}
)

type options struct {
	LogLevel              string
	LogFormat             string
	InsecureListenAddress string
	SecureListenAddress   string
	Apiserver             string
	Kubeconfig            string
	NamespaceFile         string
	ServiceAccountName    string
	AudienceParameter     string
	TLSCertFile           string
	TLSKeyFile            string
	TLSMinVersion         string
	TLSCipherSuites       []string
	CAFileDestination     string
	InsecureSkipTLSVerify bool
}

var versions = map[string]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
}

func tlsVersion(versionName string) (uint16, error) {
	if version, ok := versions[versionName]; ok {
		return version, nil
	}
	return 0, fmt.Errorf("unknown tls version %q", versionName)
}

func Main() int {
	opts := options{}

	// Add klog flags
	klogFlags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	klog.InitFlags(klogFlags)

	flagset := pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
	flagset.AddGoFlagSet(klogFlags)

	// Logging flags
	flagset.StringVar(&opts.LogLevel, "log-level", logLevelInfo, fmt.Sprintf("Log level to use. Possible values: %s.", strings.Join(availableLogLevels, ", ")))
	flagset.StringVar(&opts.LogFormat, "log-format", logFormatLogfmt, fmt.Sprintf("Log format to use. Possible values: %s.", strings.Join(availableLogFormats, ", ")))

	// Serving flags
	flagset.StringVar(&opts.InsecureListenAddress, "insecure-listen-address", "", "Address to bind HTTP server to.")
	flagset.StringVar(&opts.SecureListenAddress, "secure-listen-address", "", "Address to bind HTTPS server to.")

	// Proxy flags
	flagset.BoolVar(&opts.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, " If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure.")

	// TLS flags
	flagset.StringVar(&opts.TLSCertFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert)")
	flagset.StringVar(&opts.TLSKeyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	flagset.StringVar(&opts.TLSMinVersion, "tls-min-version", "VersionTLS12", "Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flagset.StringSliceVar(&opts.TLSCipherSuites, "tls-cipher-suites", nil, "Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used")

	flagset.StringVar(&opts.CAFileDestination, "ca-file-destination", "ca.crt", "File destination to write generated CA cert to.")

	// Kubernetes related flags
	flagset.StringVar(&opts.Apiserver, "apiserver", "", "Alternative apiserver so use.")
	flagset.StringVar(&opts.Kubeconfig, "kubeconfig", "", "Kubeconfig to use to connect to cluster.")
	flagset.StringVar(&opts.NamespaceFile, "namespace-file", "/var/run/secrets/kubernetes.io/serviceaccount/namespace", "File to read namespace of pod from.")
	flagset.StringVar(&opts.ServiceAccountName, "service-account", os.Getenv("SERVICE_ACCOUNT"), "Name of serviceaccount of Pod the kube-audience-proxy process runs in.")

	flagset.StringVar(&opts.AudienceParameter, "audience-parameter", DefaultAudienceParameter, "Parameter name to read audience from to scope tokens to.")
	flagset.Parse(os.Args[1:])

	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	if opts.LogFormat == logFormatJson {
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	}
	switch opts.LogLevel {
	case logLevelAll:
		logger = level.NewFilter(logger, level.AllowAll())
	case logLevelDebug:
		logger = level.NewFilter(logger, level.AllowDebug())
	case logLevelInfo:
		logger = level.NewFilter(logger, level.AllowInfo())
	case logLevelWarn:
		logger = level.NewFilter(logger, level.AllowWarn())
	case logLevelError:
		logger = level.NewFilter(logger, level.AllowError())
	case logLevelNone:
		logger = level.NewFilter(logger, level.AllowNone())
	default:
		fmt.Fprintf(os.Stderr, "log level %v unknown, %v are possible values", opts.LogLevel, availableLogLevels)
		return 1
	}
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	logger.Log("msg", "Starting kube-audience-proxy.", "version", version.Version, "log-level", opts.LogLevel)

	cfg, err := clientcmd.BuildConfigFromFlags(opts.Apiserver, opts.Kubeconfig)
	if err != nil {
		level.Error(logger).Log("msg", "failed to build Kubernetes client config from flags", "err", err)
		return 1
	}

	kclient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		level.Error(logger).Log("msg", "failed to create Kubernetes client from config", "err", err)
		return 1
	}

	namespaceBytes, err := ioutil.ReadFile(opts.NamespaceFile)
	if err != nil {
		level.Error(logger).Log("msg", "failed to read namespace from file", "file", opts.NamespaceFile, "err", err)
		return 1
	}
	namespace := string(namespaceBytes)
	level.Info(logger).Log("msg", "detected namespace", "namespace", namespace)

	if len(opts.ServiceAccountName) == 0 {
		level.Error(logger).Log("msg", "no serviceaccount name specified but required")
		return 1
	}

	level.Debug(logger).Log("msg", "generating CA cert")
	ca, err := genAndWriteCACert(opts.CAFileDestination)
	if err != nil {
		level.Error(logger).Log("msg", "failed to generate and write CA file", "err", err)
		return 1
	}

	tokenRetriever := newTokenRetriever(log.With(logger, "component", "token-retriever"), kclient.CoreV1().ServiceAccounts(namespace), opts.ServiceAccountName)

	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: opts.InsecureSkipTLSVerify,
	}

	t := &http.Transport{
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

	p := NewProxy(log.With(logger, "component", "proxy"), t, tokenRetriever, opts.AudienceParameter, ca, nil, tlsClientConfig)

	if opts.SecureListenAddress != "" {
		srv := &http.Server{
			Handler: p,
			// Disable HTTP/2.
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}

		if opts.TLSCertFile == "" && opts.TLSKeyFile == "" {
			level.Info(logger).Log("msg", "generating self signed cert as no cert is provided")
			certBytes, keyBytes, err := certutil.GenerateSelfSignedCertKey("", nil, nil)
			if err != nil {
				level.Error(logger).Log("msg", "failed to generate self signed cert and key", "err", err)
				return 1
			}
			cert, err := tls.X509KeyPair(certBytes, keyBytes)
			if err != nil {
				level.Error(logger).Log("msg", "failed to load generated self signed cert and key", "err", err)
				return 1
			}

			version, err := tlsVersion(opts.TLSMinVersion)
			if err != nil {
				level.Error(logger).Log("msg", "TLS version invalid", "err", err)
				return 1
			}

			cipherSuiteIDs, err := k8sapiflag.TLSCipherSuites(opts.TLSCipherSuites)
			if err != nil {
				level.Error(logger).Log("msg", "failed to convert TLS cipher suite name to ID", "err", err)
				return 1
			}
			srv.TLSConfig = &tls.Config{
				CipherSuites: cipherSuiteIDs,
				Certificates: []tls.Certificate{cert},
				MinVersion:   version,
				// To enable http/2
				// See net/http.Server.shouldConfigureHTTP2ForServe for more context
				NextProtos: []string{"h2"},
			}
		}

		l, err := net.Listen("tcp", opts.SecureListenAddress)
		if err != nil {
			level.Error(logger).Log("msg", "failed to listen for HTTPS requests", "address", opts.SecureListenAddress, "err", err)
			return 1
		}
		go srv.ServeTLS(l, opts.TLSCertFile, opts.TLSKeyFile)
		level.Info(logger).Log("msg", "listening for HTTPS requests", "address", opts.SecureListenAddress)
	}

	if opts.InsecureListenAddress != "" {
		l, err := net.Listen("tcp", opts.InsecureListenAddress)
		if err != nil {
			level.Error(logger).Log("err", err)
			return 1
		}
		srv := &http.Server{
			Handler: p,
			// Disable HTTP/2.
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		go srv.Serve(l)
		level.Info(logger).Log("msg", "listening for HTTP requests", "address", opts.InsecureListenAddress)
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		logger.Log("msg", "Received SIGTERM, exiting gracefully...")
	}

	return 0
}

func main() {
	os.Exit(Main())
}
