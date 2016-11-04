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
func isAllZeros(buf []byte, length int) bool {
	if length > len(buf) {
		return false
	}
	for i:=0; i<length; i++ {
		if buf[i] != 0 {
			return false
		}
	}
	return true
}

// A certificate is technically constrained if it has the extendedKeyUsage
// extension that does not contain anyExtendedKeyUsage and either does not
// contain the serverAuth extended key usage or has the nameConstraints
// extension with both dNSName and iPAddress entries.
func DetermineIfTechnicallyConstrained(cert *x509.Certificate) (bool, string) {
	// There must be Extended Key Usage flags
	if len(cert.ExtKeyUsage) == 0 {
		return false, "ExtKeyUsage is required"
	}

	// For certificates with a notBefore before 23 August 2016, the
	// id-Netscape-stepUp OID (aka Netscape Server Gated Crypto ("nsSGC")) is
	// treated as equivalent to id-kp-serverAuth.
	nsSGCCutoff := time.Date(2016, time.August, 23, 0, 0, 0, 0, time.UTC)

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
		return true, fmt.Sprintf(
			"Is constrained: hasServerAuth=%v || (beforeStepUpCutoff=%v && hasStepUp=%v)",
			hasServerAuth, stepUpEquivalentToServerAuth, hasStepUp)
	}

	// For iPAddresses in excludedSubtrees, both IPv4 and IPv6 must be present
	// and the constraints must cover the entire range (0.0.0.0/0 for IPv4 and
	// ::0/0 for IPv6).
	var excludesIPv4 bool
	var excludesIPv6 bool
	for _, cidr := range cert.ExcludedIPAddresses {
		if cidr.IP.Equal(net.IPv4zero) && isAllZeros(cidr.Mask, net.IPv4len) {
			excludesIPv4 = true
		}
		if cidr.IP.Equal(net.IPv6zero) && isAllZeros(cidr.Mask, net.IPv6len) {
			excludesIPv6 = true
		}
	}

	hasIPAddressInPermittedSubtrees := len(cert.PermittedIPAddresses) > 0
	hasIPAddressesInExcludedSubtrees := excludesIPv4 && excludesIPv6

	// There must be at least one DNSname constraint
	hasDNSName := len(cert.PermittedDNSDomains) > 0 ||
		len(cert.ExcludedDNSDomains) > 0

	constraintsText := fmt.Sprintf(
		"hasDNSName=%v && (hasIPAddressInPermittedSubtrees=%v || hasIPAddressesInExcludedSubtrees=%v)",
		hasDNSName, hasIPAddressInPermittedSubtrees, hasIPAddressesInExcludedSubtrees)

	if hasDNSName && (hasIPAddressInPermittedSubtrees ||
		hasIPAddressesInExcludedSubtrees) {
		return true, fmt.Sprintf("Is constrained: %s", constraintsText)
	}

	return false, fmt.Sprintf("Is not constrained: %s)", constraintsText)
}
