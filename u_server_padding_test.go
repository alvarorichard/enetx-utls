package tls

import (
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func TestServerPaddingValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		offer     []byte
		response  []byte
		wantError bool
	}{
		{"zero", []byte{0, 0}, []byte{}, false},
		{"opaque-bytes", []byte{0, 3}, []byte{1, 2, 3}, false},
		{"maximum", []byte{0x40, 0}, make([]byte, 16384), false},
		{"wrong-length", []byte{0, 0}, []byte{0}, true},
		{"missing-request", nil, []byte{}, true},
		{"malformed-request", []byte{0}, []byte{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extensions := []TLSExtension{&GenericExtension{Id: 0x1234, Data: []byte{1}}}
			if tc.offer != nil {
				extensions = append(extensions, &GenericExtension{Id: extensionServerPadding, Data: tc.offer})
			}
			raw, err := marshalClientHelloMsg(VersionTLS12, make([]byte, 32), nil, []uint16{TLS_AES_128_GCM_SHA256}, []byte{0}, extensions)
			if err != nil {
				t.Fatal(err)
			}
			hello := new(clientHelloMsg)
			if !hello.unmarshal(raw) {
				t.Fatal("invalid hello")
			}
			builder := cryptobyte.NewBuilder(nil)
			builder.AddUint8(typeEncryptedExtensions)
			builder.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(extensionServerPadding)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tc.response) })
				})
			})
			message := new(encryptedExtensionsMsg)
			if !message.unmarshal(builder.BytesOrPanic()) || !message.utls.serverPaddingPresent || message.utls.serverPaddingLength != len(tc.response) {
				t.Fatal("lost server padding presence or length")
			}
			a, b := localPipe(t)
			b.Close()
			defer a.Close()
			hs := &clientHandshakeStateTLS13{c: Client(a, &Config{}), hello: hello}
			if err := hs.readServerPadding(message); (err != nil) != tc.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, tc.wantError)
			}
			if err := hs.readServerPadding(new(encryptedExtensionsMsg)); err != nil {
				t.Fatal("server may omit padding", err)
			}
		})
	}
}

func TestServerPaddingMalformedHelloSendsInternalAlert(t *testing.T) {
	for name, hello := range map[string]*clientHelloMsg{
		"malformed-wire": {original: []byte{1, 0, 0, 0}},
		"native-serialization": {vers: VersionTLS12, random: make([]byte, 32),
			cipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, compressionMethods: []uint8{0},
			alpnProtocols: []string{strings.Repeat("x", 256)}},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := localPipe(t)
			defer a.Close()
			defer b.Close()
			if err := a.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}

			if err := b.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}

			type alertRecord struct {
				data []byte
				err  error
			}
			received := make(chan alertRecord, 1)
			go func() {
				var header [5]byte
				if _, err := io.ReadFull(b, header[:]); err != nil {
					received <- alertRecord{err: err}
					return
				}

				data := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
				_, err := io.ReadFull(b, data)
				if header[0] != byte(recordTypeAlert) && err == nil {
					err = io.ErrUnexpectedEOF
				}

				received <- alertRecord{data: data, err: err}
			}()
			hs := &clientHandshakeStateTLS13{c: Client(a, &Config{}), hello: hello}
			message := new(encryptedExtensionsMsg)
			message.utls.serverPaddingPresent = true
			err := hs.readServerPadding(message)
			if err == nil {
				t.Fatal("malformed negotiated hello was accepted")
			}

			if name == "malformed-wire" && !strings.Contains(err.Error(), "malformed") {
				t.Fatal("wrong malformed-wire failure", err)
			}

			if name == "native-serialization" && !strings.Contains(err.Error(), "cryptobyte:") {
				t.Fatal("wrong serializer failure", err)
			}

			record := <-received
			if record.err != nil || len(record.data) != 2 || record.data[1] != byte(alertInternalError) {
				t.Fatalf("wrong malformed-template alert: %x %v", record.data, record.err)
			}
		})
	}
}
