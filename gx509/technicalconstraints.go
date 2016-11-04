/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gx509

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// True if all bytes in the slice are zero.
func isAllZeros(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

// A certificate is technically constrained if it has the extendedKeyUsage
// extension that does not contain anyExtendedKeyUsage and either does not
// contain the serverAuth extended key usage or has the nameConstraints
// extension with both dNSName and iPAddress entries.
// For certificates with a notBefore before 23 August 2016, the
// id-Netscape-stepUp OID (aka Netscape Server Gated Crypto ("nsSGC")) is
// treated as equivalent to id-kp-serverAuth.
func DetermineIfTechnicallyConstrained(cert *x509.Certificate) (bool, string) {
	// There must be Extended Key Usage flags
	if len(cert.ExtKeyUsage) == 0 {
		return false, "ExtKeyUsage is required"
	}

	nsSGCCutoff, err := time.Parse(time.RFC3339, "2016-08-23T00:00:00Z")
	if err != nil {
		return false, err.Error()
	}

	stepUpEquivalentToServerAuth := cert.NotBefore.Before(nsSGCCutoff)
	var hasServerAuth bool
	var hasStepUp bool

	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			// Do not permit ExtKeyUsageAny
			return false, "ExtKeyUsageAny not permitted"
		case x509.ExtKeyUsageServerAuth:
			hasServerAuth = true
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			hasStepUp = true
		}
	}

	// Must be marked for Server Auth, or have StepUp and be from before the cutoff
	if !(hasServerAuth || (stepUpEquivalentToServerAuth && hasStepUp)) {
		return true, "Is not constrained: not for Server Auth"
	}

	// For iPAddresses in excludedSubtrees, both IPv4 and IPv6 must be present
	// and the constraints must cover the entire range (0.0.0.0/0 for IPv4 and
	// ::0/0 for IPv6).
	var excludesIPv4 bool
	var excludesIPv6 bool
	for _, cidr := range cert.ExcludedIPAddresses {
		if cidr.IP.Equal(net.IPv4zero) && isAllZeros(cidr.Mask) {
			excludesIPv4 = true
		}
		if cidr.IP.Equal(net.IPv6zero) && isAllZeros(cidr.Mask) {
			excludesIPv6 = true
		}
	}

	hasIPAddressInPermittedSubtrees := len(cert.PermittedIPAddresses) > 0
	hasIPAddressesInExcludedSubtrees := excludesIPv4 && excludesIPv6

	// There must be at least one DNSname constraint
	hasDNSName := len(cert.PermittedDNSDomains) > 0 || len(cert.ExcludedDNSDomains) > 0

	if hasDNSName && (hasIPAddressInPermittedSubtrees || hasIPAddressesInExcludedSubtrees) {
		return true, "Is constrained"
	}

	return false, fmt.Sprintf("Is not constrained: hasDNSName=%v && (hasIPAddressInPermittedSubtrees=%v || hasIPAddressesInExcludedSubtrees=%v)", hasDNSName, hasIPAddressInPermittedSubtrees, hasIPAddressesInExcludedSubtrees)
}
