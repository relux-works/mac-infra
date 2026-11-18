package javatruststore

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"
)

func NormalizeFingerprint(value string) (string, error) {
	if len(value) != sha256.Size*2 {
		return "", invalid(CauseInvalidFingerprint, nil)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", invalid(CauseInvalidFingerprint, err)
	}
	return strings.ToLower(value), nil
}

func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	remaining := data
	certs := make([]*x509.Certificate, 0)
	for len(bytes.TrimSpace(remaining)) != 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, refusal(CauseMalformedSource, nil)
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, refusal(CauseMalformedSource, nil)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, refusal(CauseMalformedSource, err)
		}
		certs = append(certs, cert)
		remaining = rest
	}
	if len(certs) == 0 {
		return nil, refusal(CauseMalformedSource, nil)
	}
	return certs, nil
}

func selectRoot(certs []*x509.Certificate, fingerprint string, now time.Time) (*x509.Certificate, error) {
	want, _ := hex.DecodeString(fingerprint)
	var selected *x509.Certificate
	matches := 0
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		got := sha256.Sum256(cert.Raw)
		if !bytes.Equal(got[:], want) {
			continue
		}
		matches++
		selected = cert
	}
	switch {
	case matches == 0:
		return nil, refusal(CauseNoMatch, nil)
	case matches != 1:
		return nil, refusal(CauseMultipleMatches, nil)
	}
	if !selected.BasicConstraintsValid || !selected.IsCA {
		return nil, refusal(CauseNotCA, nil)
	}
	if !bytes.Equal(selected.RawSubject, selected.RawIssuer) || selected.CheckSignature(selected.SignatureAlgorithm, selected.RawTBSCertificate, selected.Signature) != nil {
		return nil, refusal(CauseNotSelfSigned, nil)
	}
	now = now.UTC()
	if now.Before(selected.NotBefore) {
		return nil, refusal(CauseNotYetValid, nil)
	}
	if now.After(selected.NotAfter) {
		return nil, refusal(CauseExpired, nil)
	}
	return selected, nil
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
