package tls

import (
	"bytes"
	"testing"
)

func TestCustomSignatureInClientHello(t *testing.T) {
	// 创建一个 ClientHello 消息并设置自定义签名
	hello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		sessionId:          make([]byte, 0),
		cipherSuites:       []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		customSignature:    "zhangtiancheng build this",
	}

	// 序列化消息
	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("Failed to marshal ClientHello: %v", err)
	}

	// 检查序列化的数据是否包含自定义签名
	signature := []byte("zhangtiancheng build this")
	if !bytes.Contains(data, signature) {
		t.Errorf("ClientHello does not contain custom signature")
	}

	// 反序列化消息
	hello2 := &clientHelloMsg{}
	if !hello2.unmarshal(data) {
		t.Fatalf("Failed to unmarshal ClientHello")
	}

	// 验证自定义签名
	if hello2.customSignature != "zhangtiancheng build this" {
		t.Errorf("Custom signature mismatch: got %q, want %q", 
			hello2.customSignature, "zhangtiancheng build this")
	}

	t.Logf("ClientHello custom signature test passed: %q", hello2.customSignature)
}

func TestCustomSignatureInServerHello(t *testing.T) {
	// 创建一个 ServerHello 消息并设置自定义签名
	hello := &serverHelloMsg{
		vers:              VersionTLS12,
		random:            make([]byte, 32),
		sessionId:         make([]byte, 0),
		cipherSuite:       TLS_RSA_WITH_AES_128_GCM_SHA256,
		compressionMethod: compressionNone,
		customSignature:   "zhangtiancheng build this",
	}

	// 序列化消息
	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("Failed to marshal ServerHello: %v", err)
	}

	// 检查序列化的数据是否包含自定义签名
	signature := []byte("zhangtiancheng build this")
	if !bytes.Contains(data, signature) {
		t.Errorf("ServerHello does not contain custom signature")
	}

	// 反序列化消息
	hello2 := &serverHelloMsg{}
	if !hello2.unmarshal(data) {
		t.Fatalf("Failed to unmarshal ServerHello")
	}

	// 验证自定义签名
	if hello2.customSignature != "zhangtiancheng build this" {
		t.Errorf("Custom signature mismatch: got %q, want %q", 
			hello2.customSignature, "zhangtiancheng build this")
	}

	t.Logf("ServerHello custom signature test passed: %q", hello2.customSignature)
}
