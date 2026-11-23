package tls

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestServerPaddingUnsolicitedResponseAbortsHandshake(t *testing.T) {
	// QUIC exposes the actual plaintext TLS handshake messages. Replace only
	// EncryptedExtensions, retaining its length and a valid advertised ALPN, so
	// the client must reject the unsolicited extension before verifying Finished.
	longALPN := strings.Repeat("x", 64)
	clientConfig := testConfigClient.Clone()
	clientConfig.NextProtos = []string{longALPN, "h3"}
	serverConfig := testConfigServer.Clone()
	serverConfig.NextProtos = []string{longALPN}
	client := newTestQUICClient(t, &QUICConfig{TLSConfig: clientConfig})
	server := newTestQUICServer(t, &QUICConfig{TLSConfig: serverConfig})
	client.conn.SetTransportParameters(nil)
	server.conn.SetTransportParameters(nil)

	injected := false
	err := runTestQUICConnection(t.Context(), client, server, func(e QUICEvent, src, dst *testQUICConn) bool {
		if injected || src != server || e.Kind != QUICWriteData || e.Level != QUICEncryptionLevelHandshake {
			return false
		}

		if len(e.Data) < 6 || e.Data[0] != typeEncryptedExtensions {
			t.Fatal("server did not begin Handshake data with EncryptedExtensions")
		}

		length := 4 + int(e.Data[1])<<16 + int(e.Data[2])<<8 + int(e.Data[3])
		if length > len(e.Data) {
			t.Fatal("truncated test EncryptedExtensions")
		}

		// Message header + extensions length + ALPN extension + empty QUIC
		// parameters + server-padding extension leave this many opaque bytes.
		paddingLength := length - (4 + 2 + 4 + 2 + 1 + len("h3") + 4 + 4)
		if paddingLength < 0 {
			t.Fatal("test ALPN did not reserve enough room")
		}

		builder := cryptobyte.NewBuilder(nil)
		builder.AddUint8(typeEncryptedExtensions)
		builder.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(extensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(uint16(1 + len("h3")))
					b.AddUint8(uint8(len("h3")))
					b.AddBytes([]byte("h3"))
				})
				b.AddUint16(extensionQUICTransportParameters)
				b.AddUint16(0)
				b.AddUint16(extensionServerPadding)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, paddingLength)) })
			})
		})
		raw, err := builder.Bytes()
		if err != nil || len(raw) != length || binary.BigEndian.Uint16(raw[4:]) != uint16(length-6) {
			t.Fatalf("invalid replacement message: len=%d want=%d err=%v", len(raw), length, err)
		}

		copy(e.Data, raw)
		injected = true
		return false
	})
	var alertError AlertError
	if !injected || err == nil || !strings.Contains(err.Error(), "unrequested server padding") ||
		!errors.As(err, &alertError) || alertError != AlertError(alertUnsupportedExtension) {
		t.Fatalf("unsolicited padding did not produce unsupported_extension: injected=%t err=%v", injected, err)
	}

	if client.complete || client.conn.ConnectionState().HandshakeComplete {
		t.Fatal("handshake completed with an unsolicited extension")
	}
}
