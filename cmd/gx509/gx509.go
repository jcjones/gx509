/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/jcjones/gx509/gx509"
)

var printHeaders = flag.Bool("headers", false, "Add PEM-headers to each block (not compatible with OpenSSL)")

func processCertData(file *os.File) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	pemObj, _ := pem.Decode(pemBytes)
	if pemObj.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("Unknown PEM type: %s", pemObj.Type)
	}

	certObj, err := x509.ParseCertificate(pemObj.Bytes)
	if err != nil {
		return nil, err
	}

	return certObj, nil
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatalf("You must specify the path to the .pem file as the last argument")
		return
	}

	file, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatalf("Could not open file %s: %s", flag.Arg(0), err)
		return
	}

	cert, err := processCertData(file)
	if err != nil {
		log.Fatalf("Could not process file: %s", flag.Arg(0), err)
		return
	}

	fmt.Printf("\n")
	fmt.Printf("X509v3 Name Constraints (critical): %t\n", cert.PermittedDNSDomainsCritical)
	fmt.Printf("X509v3 PermittedDNSDomains: %s\n", cert.PermittedDNSDomains)
	fmt.Printf("X509v3 PermittedIPAddresses: %s\n", cert.PermittedIPAddresses)
	fmt.Printf("X509v3 ExcludedDNSDomains: %s\n", cert.ExcludedDNSDomains)
	fmt.Printf("X509v3 ExcludedIPAddresses: %s\n", cert.ExcludedIPAddresses)

	result, details := gx509.DetermineIfTechnicallyConstrained(cert)

	log.Printf("%s result: %v details: %s", flag.Arg(0), result, details)
}
