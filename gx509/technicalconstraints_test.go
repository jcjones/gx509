/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gx509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// var pemPublicKey = `-----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
// wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
// enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
// FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
// fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
// FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
// +QIDAQAB
// -----END PUBLIC KEY-----
// `

var pemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END RSA PRIVATE KEY-----
`

var testPrivateKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(pemPrivateKey))

	var err error
	if testPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic("Failed to parse private key: " + err.Error())
	}
}

// serialiseAndParse generates a self-signed certificate from template and
// returns a parsed version of it.
func serialiseAndParse(t *testing.T, template *x509.Certificate) *x509.Certificate {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
		return nil
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
		return nil
	}

	return cert
}

func checkConstrained(t *testing.T, expected bool, cert *x509.Certificate) {
	result, details := DetermineIfTechnicallyConstrained(cert)
	if expected != result {
		t.Errorf("Expected %v, got %v. Details: %s", expected, result, details)
	}
}

func TestNoConstraints(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2009, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, false, cert)
}

func TestExtAnyKeyUsage(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2009, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny, x509.ExtKeyUsageNetscapeServerGatedCrypto},
		ExcludedIPAddresses: []net.IPNet{
			{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
			{IP: net.IPv6zero, Mask: net.IPMask(net.IPv6zero)}},
		PermittedDNSDomains: []string{".example.com", "example.com"},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, false, cert)
}

func Test2014StepUpConstrainedCert(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2014, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageNetscapeServerGatedCrypto},
		ExcludedIPAddresses: []net.IPNet{
			{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
			{IP: net.IPv6zero, Mask: net.IPMask(net.IPv6zero)}},
		PermittedDNSDomains: []string{".example.com", "example.com"},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, true, cert)
}

func Test2014StepUpUnconstrainedCert(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2014, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageNetscapeServerGatedCrypto},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, false, cert)
}

func Test2017ConstrainedCertWithoutIPv6(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2017, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExcludedIPAddresses: []net.IPNet{
			{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)}},
		PermittedDNSDomains: []string{".example.com", "example.com"},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, false, cert)
}

func Test2017ConstrainedCertWithoutDNSnames(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2017, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExcludedIPAddresses: []net.IPNet{
			{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
			{IP: net.IPv6zero, Mask: net.IPMask(net.IPv6zero)}},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, false, cert)
}

func Test2017ConstrainedCertWithExcludedIPs(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2017, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExcludedIPAddresses: []net.IPNet{
			{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
			{IP: net.IPv6zero, Mask: net.IPMask(net.IPv6zero)}},
		PermittedDNSDomains: []string{".example.com", "example.com"},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, true, cert)
}

func Test2017ConstrainedCertWithIncludedIPs(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2017, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		PermittedIPAddresses: []net.IPNet{
			{IP: net.ParseIP("128.0.0.1"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
			{IP: net.ParseIP("::1"), Mask: net.IPMask(net.IPv6zero)}},
		PermittedDNSDomains: []string{".example.com", "example.com"},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, true, cert)
}

func Test2017ConstrainedCertWithoutIPs(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2017, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		PermittedDNSDomains: []string{".example.com", "example.com"},
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, false, cert)
}

func TestNotACA(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Date(2009, time.December, 1, 23, 59, 59, 59, time.UTC),
		NotAfter:  time.Date(2019, time.December, 1, 23, 59, 59, 59, time.UTC),

		BasicConstraintsValid: true,
		IsCA: false,
	}

	cert := serialiseAndParse(t, template)
	checkConstrained(t, false, cert)
}
