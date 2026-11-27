package eudore

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestTraceTLSStateEmpty(t *testing.T) {
	tr := &ClientTrace{}
	// an empty but non-nil slice is what a resumed handshake produces
	traceTLSState(tr, tls.ConnectionState{PeerCertificates: []*x509.Certificate{}})
	if tr.TLSHandshakeSubject != "" || tr.TLSHandshakeDigest != "" {
		t.Fatalf("empty peer certificates wrote into the trace: %q %q",
			tr.TLSHandshakeSubject, tr.TLSHandshakeDigest)
	}
}

func TestTraceTLSStateLeaf(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "eudore.test"},
		Issuer:       pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1700086400, 0),
		RawSubject:   []byte{1},
		RawIssuer:    []byte{2},
	}
	tr := &ClientTrace{}
	traceTLSState(tr, tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
	if tr.TLSHandshakeSubject != "CN=eudore.test" {
		t.Fatalf("subject = %q", tr.TLSHandshakeSubject)
	}
	if tr.TLSHandshakeDigest == "" {
		t.Fatal("digest not recorded")
	}
}
