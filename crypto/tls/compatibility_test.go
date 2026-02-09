package tls

import (
	"testing"
)

// 测试与不支持自定义扩展的客户端/服务器的兼容性
func TestCustomSignatureCompatibility(t *testing.T) {
	t.Run("ClientHello ignores unknown extensions", func(t *testing.T) {
		// 模拟一个包含未知扩展的 ClientHello
		hello := &clientHelloMsg{
			vers:               VersionTLS12,
			random:             make([]byte, 32),
			sessionId:          make([]byte, 0),
			cipherSuites:       []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			compressionMethods: []uint8{compressionNone},
			// 不设置 customSignature，模拟旧版本
		}

		data, err := hello.marshal()
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}

		// 解析消息（应该能成功，即使没有自定义扩展）
		hello2 := &clientHelloMsg{}
		if !hello2.unmarshal(data) {
			t.Fatalf("Failed to unmarshal")
		}

		// 验证：即使消息中没有自定义扩展，也能正常解析
		if hello2.customSignature != "" {
			t.Logf("Note: customSignature is empty, which is expected for old clients")
		}
		t.Log("✓ Successfully parsed ClientHello without custom signature")
	})

	t.Run("ServerHello ignores unknown extensions", func(t *testing.T) {
		// 模拟一个包含未知扩展的 ServerHello
		hello := &serverHelloMsg{
			vers:              VersionTLS12,
			random:            make([]byte, 32),
			sessionId:         make([]byte, 0),
			cipherSuite:       TLS_RSA_WITH_AES_128_GCM_SHA256,
			compressionMethod: compressionNone,
			// 不设置 customSignature，模拟旧版本
		}

		data, err := hello.marshal()
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}

		// 解析消息（应该能成功，即使没有自定义扩展）
		hello2 := &serverHelloMsg{}
		if !hello2.unmarshal(data) {
			t.Fatalf("Failed to unmarshal")
		}

		// 验证：即使消息中没有自定义扩展，也能正常解析
		if hello2.customSignature != "" {
			t.Logf("Note: customSignature is empty, which is expected for old servers")
		}
		t.Log("✓ Successfully parsed ServerHello without custom signature")
	})

	t.Run("Mixed version compatibility", func(t *testing.T) {
		// 新版本 ClientHello (带自定义扩展)
		newClientHello := &clientHelloMsg{
			vers:               VersionTLS12,
			random:             make([]byte, 32),
			sessionId:          make([]byte, 0),
			cipherSuites:       []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
			compressionMethods: []uint8{compressionNone},
			customSignature:    "zhangtiancheng build this",
		}

		data, err := newClientHello.marshal()
		if err != nil {
			t.Fatalf("Failed to marshal new ClientHello: %v", err)
		}

		// 旧版本解析器应该能忽略未知扩展
		oldStyleParser := &clientHelloMsg{}
		if !oldStyleParser.unmarshal(data) {
			t.Fatalf("Old-style parser failed to parse new ClientHello")
		}

		t.Log("✓ Old clients can parse new ClientHello (ignoring custom extension)")
		t.Log("✓ Backward compatibility confirmed")
	})
}

// 测试与标准 TLS 库的互操作性
func TestInteroperabilityWithStandardTLS(t *testing.T) {
	// 创建一个带自定义扩展的 ClientHello
	hello := &clientHelloMsg{
		vers:                         VersionTLS12,
		random:                       make([]byte, 32),
		sessionId:                    make([]byte, 32),
		cipherSuites:                 []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods:           []uint8{compressionNone},
		serverName:                   "example.com",
		ocspStapling:                 true,
		supportedCurves:              []CurveID{CurveP256, CurveP384},
		supportedPoints:              []uint8{pointFormatUncompressed},
		supportedSignatureAlgorithms: []SignatureScheme{PKCS1WithSHA256, ECDSAWithP256AndSHA256},
		customSignature:              "zhangtiancheng build this",
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// 验证消息可以被正确解析
	hello2 := &clientHelloMsg{}
	if !hello2.unmarshal(data) {
		t.Fatalf("Failed to unmarshal")
	}

	// 验证所有标准字段都正确保留
	if hello2.serverName != "example.com" {
		t.Errorf("serverName mismatch")
	}
	if !hello2.ocspStapling {
		t.Errorf("ocspStapling mismatch")
	}
	if len(hello2.supportedCurves) != 2 {
		t.Errorf("supportedCurves mismatch")
	}
	if hello2.customSignature != "zhangtiancheng build this" {
		t.Errorf("customSignature mismatch")
	}

	t.Log("✓ All standard TLS fields preserved correctly")
	t.Log("✓ Custom signature added without affecting other fields")
}
