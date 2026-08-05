package main

import (
	"crypto/x509"
	"errors"
	"testing"
)

func TestClassifyPreservesDirectUnsupportedSignatureCause(t *testing.T) {
	got := classify(errors.New("x509: certificate signed by unknown authority"), x509.ErrUnsupportedAlgorithm, nil, nil)
	if got.Verdict != "unsupported" || got.SignatureError == "" {
		t.Fatalf("got %#v", got)
	}
}

func TestClassifyDoesNotPromoteOrdinaryRejection(t *testing.T) {
	got := classify(errors.New("invalid signature"), errors.New("invalid signature"), nil, nil)
	if got.Verdict != "reject" {
		t.Fatalf("got %#v", got)
	}
}

func TestOutcomeKeepsUnsupportedSeparateFromFailure(t *testing.T) {
	if outcome(nil) != "pass" || outcome(x509.ErrUnsupportedAlgorithm) != "unsupported" || outcome(errors.New("bad")) != "fail" {
		t.Fatal("unexpected source trace outcome")
	}
}
