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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage
)

func genAndWriteCACert(caFileDestination string) (*tls.Certificate, error) {
	certPEM, _, ca, err := genAndParseCACert()
	if err != nil {
		return nil, fmt.Errorf("generate CA cert: %w", err)
	}

	err = ioutil.WriteFile(caFileDestination, certPEM, 0444)
	if err != nil {
		return nil, fmt.Errorf("write CA file: %w", err)
	}

	return ca, nil
}

func genAndParseCACert() ([]byte, []byte, *tls.Certificate, error) {
	certPEM, keyPEM, err := GenCA("kube-audience-proxy")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA cert: %w", err)
	}

	ca, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CA keypair: %w", err)
	}
	// TODO(brancz): not sure why this is necessary
	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing leaf cert: %w", err)
	}

	return certPEM, keyPEM, &ca, nil
}

func genCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()
	if !ca.Leaf.IsCA {
		return nil, errors.New("CA cert is not a CA")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	ips := []net.IP{}
	remainingNames := []string{}
	for _, name := range names {
		splitname, _, err := net.SplitHostPort(name)
		if err != nil && err.(*net.AddrError).Err == "missing port in address" {
			splitname = name
		}
		if err != nil && err.(*net.AddrError).Err != "missing port in address" {
			return nil, fmt.Errorf("split host port: %w", err)
		}

		ip := net.ParseIP(splitname)
		if ip != nil {
			ips = append(ips, ip)
			continue
		}

		remainingNames = append(remainingNames, splitname)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		DNSNames:              remainingNames,
		IPAddresses:           ips,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func genKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

func GenCA(name string) (certPEM, keyPEM []byte, err error) {
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return
}
