package tls

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCustomECHBuildRejectsInvalidOuterTemplates(t *testing.T) {
	sentinel := errors.New("outer extension failed")
	for _, name := range []string{"serialization", "duplicate", "no-extensions", "nil-policy", "invalid-psk"} {
		t.Run(name, func(t *testing.T) {
			cfg := innerTestConfig(t)
			cfg.ECHClientHelloInner = innerTestPolicy
			client := innerTestClient(t, cfg)
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}

			want := ""
			switch name {
			case "serialization":
				client.Extensions = append(client.Extensions, &echFailingExtension{GenericExtension: GenericExtension{Id: 0x4321}, err: sentinel})
			case "duplicate":
				client.Extensions = append(client.Extensions, &GenericExtension{Id: 0x1234})
				want = "malformed outer"
			case "no-extensions":
				client.Extensions = nil
				want = "malformed outer"
			case "nil-policy":
				cfg.ECHClientHelloInner = nil
				want = "callback is nil"
			case "invalid-psk":
				common := echPSKTestCommon()
				common.BinderKey = nil
				client.sessionController.pskExtension = &UtlsPreSharedKeyExtension{PreSharedKeyCommon: common}
				want = "key material"
			}

			inner, err := client.buildECHInner(new(echClientContext), make([]byte, 32))
			if err == nil || inner != nil {
				t.Fatal("invalid outer produced a usable inner")
			}

			if name == "serialization" {
				if !errors.Is(err, sentinel) {
					t.Fatalf("serialization failure lost its cause: %v", err)
				}
			} else if !strings.Contains(err.Error(), want) {
				t.Fatalf("wrong validation failure: %v; want %q", err, want)
			}
		})
	}
}

func TestECHOuterPSKErrorsPreserveTemplate(t *testing.T) {
	common := echPSKTestCommon()
	extension := &UtlsPreSharedKeyExtension{PreSharedKeyCommon: common}
	for _, name := range []string{"malformed-inner", "entropy-failure"} {
		t.Run(name, func(t *testing.T) {
			client := UClient(nil, &Config{Rand: bytes.NewReader(nil)}, HelloCustom)
			client.Extensions = []TLSExtension{&GenericExtension{Id: 0x1234}, extension}
			original := append([]TLSExtension(nil), client.Extensions...)
			inner := &clientHelloMsg{pskIdentities: []pskIdentity{{label: []byte("private")}}}
			if name == "entropy-failure" {
				data := make([]byte, extension.Len())
				if _, err := extension.Read(data); err != nil && !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}

				raw, err := marshalClientHelloMsg(VersionTLS12, make([]byte, 32), nil,
					[]uint16{TLS_AES_128_GCM_SHA256}, []byte{0},
					[]TLSExtension{&GenericExtension{Id: extensionPreSharedKey, Data: data[4:]}})
				if err != nil || !inner.unmarshal(raw) {
					t.Fatalf("invalid test inner: %v", err)
				}
			}

			restore, err := client.setECHOuterExtensions(inner, &echClientContext{outerPSK: ECHOuterPSKRandomized})
			if err == nil || restore != nil {
				t.Fatal("unusable PSK placeholder replaced the template")
			}

			if len(client.Extensions) != len(original) || client.Extensions[0] != original[0] || client.Extensions[1] != original[1] {
				t.Fatal("failed placeholder generation mutated the template")
			}

			if name == "entropy-failure" && !errors.Is(err, io.EOF) {
				t.Fatalf("lost entropy failure: %v", err)
			}
		})
	}
}

func TestCustomECHOuterValidationAndRestoration(t *testing.T) {
	for _, name := range []string{"invalid-inner", "invalid-outer"} {
		t.Run(name, func(t *testing.T) {
			cfg := innerTestConfig(t)
			cfg.ECHClientHelloInner = innerTestPolicy
			client := innerTestClient(t, cfg)
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}

			inner := client.echCtx.innerHello
			if name == "invalid-inner" {
				inner = &clientHelloMsg{pskIdentities: []pskIdentity{{label: []byte("private")}}}
				client.echCtx.outerPSK = ECHOuterPSKRandomized
			} else {
				client.Extensions = append(client.Extensions, &GenericExtension{Id: 0x1234})
			}

			original := append([]TLSExtension(nil), client.Extensions...)
			err := client.computeAndUpdateOuterECHExtension(inner, client.echCtx, false)
			if err == nil || !strings.Contains(err.Error(), "outer") {
				t.Fatalf("invalid ECH construction was accepted: %v", err)
			}

			for i, extension := range original {
				if client.Extensions[i] != extension {
					t.Fatal("failed construction changed the configured template")
				}
			}
		})
	}
}
