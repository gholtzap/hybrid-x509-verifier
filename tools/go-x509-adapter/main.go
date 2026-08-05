package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

const maxInputBytes = 16 * 1024 * 1024

type result struct {
	Verdict        string      `json:"verdict"`
	Error          string      `json:"error,omitempty"`
	SignatureError string      `json:"signature_error,omitempty"`
	Trace          []event     `json:"trace"`
	Extensions     []extension `json:"extensions"`
}

type event struct {
	Operation string `json:"operation"`
	Target    string `json:"target"`
	Algorithm string `json:"algorithm,omitempty"`
	Outcome   string `json:"outcome"`
}

type extension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
}

func main() {
	rootPath := flag.String("root", "", "root certificate")
	intermediatePath := flag.String("intermediate", "", "intermediate certificate")
	leafPath := flag.String("leaf", "", "leaf certificate")
	dnsName := flag.String("dns", "", "expected DNS name")
	validationTime := flag.String("time", "", "RFC 3339 validation time")
	version := flag.Bool("version", false, "print the Go runtime version")
	flag.Parse()

	if *version {
		fmt.Println(runtime.Version())
		return
	}
	if *rootPath == "" || *intermediatePath == "" || *leafPath == "" || *validationTime == "" {
		fail("root, intermediate, leaf, and time are required")
	}

	now, err := time.Parse(time.RFC3339, *validationTime)
	if err != nil {
		fail("invalid validation time: " + err.Error())
	}
	root := readCertificate(*rootPath)
	intermediate := readCertificate(*intermediatePath)
	leaf := readCertificate(*leafPath)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	signatureErr := leaf.CheckSignatureFrom(intermediate)
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       *dnsName,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})

	trace := []event{
		{
			Operation: "check-signature-from",
			Target:    "leaf",
			Algorithm: leaf.SignatureAlgorithm.String(),
			Outcome:   outcome(signatureErr),
		},
		{
			Operation: "verify-web-pki-server-path",
			Target:    "leaf-through-intermediate",
			Outcome:   outcome(err),
		},
	}
	extensions := make([]extension, 0, len(leaf.Extensions))
	for _, item := range leaf.Extensions {
		extensions = append(extensions, extension{OID: item.Id.String(), Critical: item.Critical})
	}
	verdict := classify(err, signatureErr, trace, extensions)
	if err := json.NewEncoder(os.Stdout).Encode(verdict); err != nil {
		fail(err.Error())
	}
}

func classify(verifyErr, signatureErr error, trace []event, extensions []extension) result {
	if errors.Is(signatureErr, x509.ErrUnsupportedAlgorithm) {
		return result{Verdict: "unsupported", Error: errorText(verifyErr), SignatureError: signatureErr.Error(), Trace: trace, Extensions: extensions}
	}
	if verifyErr != nil {
		return result{Verdict: "reject", Error: verifyErr.Error(), Trace: trace, Extensions: extensions}
	}
	return result{Verdict: "accept", Trace: trace, Extensions: extensions}
}

func outcome(err error) string {
	if err == nil {
		return "pass"
	}
	if errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return "unsupported"
	}
	return "fail"
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func readCertificate(path string) *x509.Certificate {
	info, err := os.Stat(path)
	if err != nil {
		fail(err.Error())
	}
	if !info.Mode().IsRegular() || info.Size() > maxInputBytes {
		fail("certificate input is not a regular bounded file: " + path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		fail("invalid single-certificate PEM: " + path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fail(err.Error())
	}
	return certificate
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
