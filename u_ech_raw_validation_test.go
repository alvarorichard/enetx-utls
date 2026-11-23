package tls

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type echFailingExtension struct {
	GenericExtension
	err error
}

func (e *echFailingExtension) Read([]byte) (int, error) { return 0, e.err }

func TestECHRawMarshallerRejectsExtensionFailureAndOversizedVectors(t *testing.T) {
	sentinel := errors.New("extension serialization failed")
	for name, extensions := range map[string][]TLSExtension{
		"reader-error":    {&echFailingExtension{GenericExtension: GenericExtension{Id: 0x1234}, err: sentinel}},
		"vector-overflow": {&GenericExtension{Id: 0x1234, Data: make([]byte, 1<<16)}},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := marshalClientHelloMsg(VersionTLS12, make([]byte, 32), nil,
				[]uint16{TLS_AES_128_GCM_SHA256}, []byte{0}, extensions)
			if err == nil || raw != nil {
				t.Fatalf("failed serialization returned a usable ClientHello: len=%d err=%v", len(raw), err)
			}

			if name == "reader-error" && !errors.Is(err, sentinel) {
				t.Fatalf("extension failure lost its cause: %v", err)
			}
		})
	}
}

func TestCustomECHLiteralPolicyValidatesVersionsAndGeneratedShares(t *testing.T) {
	for _, name := range []string{"valid", "mixed-versions", "invalid-versions", "missing-share", "changed-share", "oversized-literal"} {
		t.Run(name, func(t *testing.T) {
			cfg := innerTestConfig(t)
			cfg.ECHClientHelloInner = func(info ECHClientHelloInfo) (*ECHClientHelloSpec, error) {
				outer := new(clientHelloMsg)
				if !outer.unmarshal(info.ClientHello) {
					return nil, errors.New("test received a malformed outer")
				}

				raw, err := extractRawExtensions(outer)
				if err != nil {
					return nil, err
				}

				values := make(map[uint16][]byte)
				for _, extension := range raw {
					values[extension.extType] = extension.data
				}

				spec, err := innerTestPolicy(info)
				if err != nil {
					return nil, err
				}

				for i := range spec.Extensions {
					extension := &spec.Extensions[i]
					if extension.Outer {
						extension.Outer = false
						extension.Data = bytes.Clone(values[extension.ID])
					}

					if extension.ID == extensionSupportedVersions {
						switch name {
						case "mixed-versions":
							extension.Data = []byte{4, 3, 4, 3, 3}
						case "invalid-versions":
							extension.Data = []byte{3, 3}
						}
					}

					if extension.ID == extensionKeyShare {
						switch name {
						case "missing-share":
							extension.Data = []byte{0, 0}
						case "changed-share":
							extension.Data[len(extension.Data)-1] ^= 1
						}
					}
				}

				if name == "oversized-literal" {
					spec.Extensions = append(spec.Extensions, ECHClientHelloExtension{ID: 0x4321, Data: make([]byte, 1<<16)})
				}

				return spec, nil
			}
			client := innerTestClient(t, cfg)
			err := client.BuildHandshakeState()
			if name == "valid" {
				if err != nil {
					t.Fatal("unchanged literal extensions must remain supported", err)
				}

				return
			}

			if err == nil {
				t.Fatal("invalid literal policy was accepted")
			}

			message := map[string]string{
				"mixed-versions": "legacy version", "invalid-versions": "invalid ECH inner",
				"missing-share": "changed key shares", "changed-share": "changed key shares",
				"oversized-literal": "cryptobyte:",
			}[name]
			if !strings.Contains(err.Error(), message) {
				t.Fatalf("wrong validation failure: %v; want %q", err, message)
			}
		})
	}
}

func TestECHRawEncoderRejectsMalformedAndIncompleteReferenceRuns(t *testing.T) {
	extensions := []TLSExtension{
		&GenericExtension{Id: 0x1231, Data: []byte{1}},
		&GenericExtension{Id: 0x1232, Data: []byte{2}},
		&GenericExtension{Id: 0x1233, Data: []byte{3}},
	}
	raw, err := marshalClientHelloMsg(VersionTLS12, make([]byte, 32), nil,
		[]uint16{TLS_AES_128_GCM_SHA256}, []byte{0}, extensions)
	if err != nil {
		t.Fatal(err)
	}

	for name, refs := range map[string][]uint16{
		"noncontiguous": {0x1231, 0x1233},
		"missing":       {0x4321},
	} {
		t.Run(name, func(t *testing.T) {
			if encoded, err := encodeInnerClientHelloFromRaw(&clientHelloMsg{original: raw}, refs, 32); err == nil || encoded != nil {
				t.Fatal("invalid reference run produced an encoded inner")
			}
		})
	}

	malformed := bytes.Clone(raw)
	extensionsLength := 0
	for _, extension := range extensions {
		extensionsLength += extension.Len()
	}

	first := len(malformed) - extensionsLength
	malformed[first+2], malformed[first+3] = 0xff, 0xff
	if encoded, err := encodeInnerClientHelloFromRaw(&clientHelloMsg{original: malformed}, nil, 32); err == nil || encoded != nil {
		t.Fatal("malformed extension framing produced an encoded inner")
	}
}

func TestECHPSKBinderReturnsSerializationFailure(t *testing.T) {
	common := echPSKTestCommon()
	inner := &clientHelloMsg{
		vers: VersionTLS12, random: make([]byte, 32),
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, compressionMethods: []uint8{0},
		alpnProtocols: []string{strings.Repeat("x", 256)},
		pskIdentities: []pskIdentity{{label: []byte("ticket")}},
		pskBinders:    [][]byte{make([]byte, 32)},
	}
	if err := patchECHPSKBinder(inner, &common, nil); err == nil {
		t.Fatal("an unserializable transcript received a PSK binder")
	}

	if !bytes.Equal(inner.pskBinders[0], make([]byte, 32)) {
		t.Fatal("failed serialization modified the binder")
	}
}

var _ TLSExtension = (*echFailingExtension)(nil)

func TestECHInnerParserValidatesBinderBeforePublishingHello(t *testing.T) {
	common := echPSKTestCommon()
	for _, size := range []int{31, 32, 33} {
		identities := []PskIdentity{{Label: []byte("private-ticket")}}
		binders := [][]byte{make([]byte, size)}
		psk := make([]byte, pskExtLen(identities, binders))
		readPskIntoBytes(psk, identities, binders)
		raw, err := marshalClientHelloMsg(VersionTLS12, make([]byte, 32), nil,
			[]uint16{TLS_AES_128_GCM_SHA256}, []byte{0},
			[]TLSExtension{&GenericExtension{Id: extensionPreSharedKey, Data: psk[4:]}})
		if err != nil {
			t.Fatal(err)
		}

		before := bytes.Clone(raw)
		inner, err := parseECHInnerClientHello(raw, &common, nil)
		if size != 32 {
			if err == nil || inner != nil || !strings.Contains(err.Error(), "binder placeholder") || !bytes.Equal(before, raw) {
				t.Fatalf("wrong-sized binder published a partial inner: size=%d err=%v", size, err)
			}

			continue
		}

		if err != nil || inner == nil || len(inner.pskBinders) != 1 || bytes.Equal(before, raw) {
			t.Fatalf("valid inner was not bound to its raw transcript: %v", err)
		}

		if !bytes.Equal(raw[len(raw)-32:], inner.pskBinders[0]) {
			t.Fatal("raw and parsed binders disagree")
		}
	}

	if inner, err := parseECHInnerClientHello([]byte{typeClientHello}, &common, nil); err == nil || inner != nil {
		t.Fatal("malformed raw ClientHello was published")
	}
}
