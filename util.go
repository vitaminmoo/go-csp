package csp

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
)

func isKeyword(kw string) string {
	var keywords = []string{
		"none",
		"self",
		"unsafe-inline",
		"unsafe-eval",
		"strict-dynamic",
		"unsafe-hashes",
		"report-sample",
		"unsafe-allow-redirects",
	}
	for _, keyword := range keywords {
		if kw == keyword {
			return fmt.Sprintf("'%v'", kw)
		}
		if kw == fmt.Sprintf("'%v'", keyword) {
			return kw
		}
	}
	return ""
}

func formatSource(source string) string {
	kw := isKeyword(source)
	if kw != "" {
		// Keyword
		return kw
	} else if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		// Serialized URL
		return source
	} else if strings.HasSuffix(source, ":") {
		// Scheme
		return source
	} else if strings.Contains(source, ".") {
		// Host
		return source
	} else if strings.HasPrefix(source, "nonce-") {
		// Nonce, incorrectly not quoted
		return fmt.Sprintf("'%v'", source)
	} else if strings.HasPrefix(source, "'nonce-") {
		// Nonce
		return source
	} else if strings.HasPrefix(source, "sha256-") || strings.HasPrefix(source, "sha384-") || strings.HasPrefix(source, "sha512-") {
		// Digest, incorrectly not quoted
		return fmt.Sprintf("'%v'", source)
	} else if strings.HasPrefix(source, "'sha256-") || strings.HasPrefix(source, "'sha384-") || strings.HasPrefix(source, "'sha512-") {
		// Digest
		return source
	}
	log.Printf("Invalid looking source: %v", source)
	return source
}

func mkNonce() string {
	bytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bytes[i] = byte(65 + rand.Intn(25))
	}
	return string(bytes)
}
