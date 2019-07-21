package csp

import (
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"strings"
	"unicode"
)

// CSP3 is a golang native representation of a Content Security Policy 3 policy
type CSP3 struct {
	// Fetch Directives
	ChildSrc      map[string]bool `source:"child-src"`
	ConnectSrc    map[string]bool `source:"connect-src"`
	DefaultSrc    map[string]bool `source:"default-src"`
	FontSrc       map[string]bool `source:"font-src"`
	FrameSrc      map[string]bool `source:"frame-src"`
	ImgSrc        map[string]bool `source:"img-src"`
	ManifestSrc   map[string]bool `source:"manifest-src"`
	MediaSrc      map[string]bool `source:"media-src"`
	PrefetchSrc   map[string]bool `source:"prefetch-src"`
	ObjectSrc     map[string]bool `source:"object-src"`
	ScriptSrc     map[string]bool `source:"script-src"`
	ScriptSrcElem map[string]bool `source:"scriptSrcElem"`
	ScriptSrcAttr map[string]bool `source:"ScriptSrcAttr"`
	WorkerSrc     map[string]bool `source:"WorkerSrc"`
	// Document Directives
	BaseURI     map[string]bool `source:"base-uri"`
	PluginTypes map[string]bool `source:"plugin-types"`
	Sandbox     map[string]bool `source:"sandbox"`
	// Reporting Directives
	ReportURI map[string]bool `source:"report-uri"`
	ReportTo  map[string]bool `source:"report-to"`
}

// NewCSP3 returns a new csp with all maps initialized
func NewCSP3() *CSP3 {
	c := new(CSP3)
	c.ChildSrc = make(map[string]bool)
	c.ConnectSrc = make(map[string]bool)
	c.DefaultSrc = make(map[string]bool)
	c.FontSrc = make(map[string]bool)
	c.FrameSrc = make(map[string]bool)
	c.ImgSrc = make(map[string]bool)
	c.ManifestSrc = make(map[string]bool)
	c.MediaSrc = make(map[string]bool)
	c.PrefetchSrc = make(map[string]bool)
	c.ObjectSrc = make(map[string]bool)
	c.ScriptSrc = make(map[string]bool)
	c.ScriptSrcElem = make(map[string]bool)
	c.ScriptSrcAttr = make(map[string]bool)
	c.WorkerSrc = make(map[string]bool)
	c.BaseURI = make(map[string]bool)
	c.PluginTypes = make(map[string]bool)
	c.Sandbox = make(map[string]bool)
	c.ReportURI = make(map[string]bool)
	c.ReportTo = make(map[string]bool)
	return c
}

// FromString takes a string from a header and makes a CSP3 object from it
// we use unicode whitespace here even though the spec says ascii because *meh*
func FromString(header string) (*CSP3, error) {
	c := NewCSP3()

	tagMap := make(map[string]string)
	v := reflect.ValueOf(*c)
	//t := reflect.TypeOf(c)
	for i := 0; i < v.NumField(); i++ {
		fieldName := v.Type().Field(i).Name
		fieldTag := v.Type().Field(i).Tag
		source, ok := fieldTag.Lookup("source")
		if ok {
			tagMap[source] = fieldName
		}
	}

	tokens := strings.Split(header, ";")
	for _, tokenRaw := range tokens {
		token := strings.TrimSpace(tokenRaw)
		if token == "" {
			continue
		}
		var directiveName string
		gotDirective := false
		var rest string
		for _, c := range token {
			if gotDirective {
				rest += string(c)
				continue
			}
			if unicode.IsSpace(c) {
				gotDirective = true
				continue
			}
			directiveName += string(c)
		}

		directiveName = strings.ToLower(directiveName)
		directiveValue := strings.Fields(rest)
		r := reflect.ValueOf(c)
		f := reflect.Indirect(r).FieldByName(tagMap[directiveName])
		if f.CanSet() {
			m := make(map[string]bool)
			for _, source := range directiveValue {
				m[source] = true
			}
			f.Set(reflect.ValueOf(m))
		} else {
			log.Printf("Can't set value of %v (from %v)", tagMap[directiveName], directiveName)
		}
	}
	return c, nil
}

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

// String returns a string representation of the CSP, ready for inclusion as a Content-Security-Policy header
func (c *CSP3) String() string {
	v := reflect.ValueOf(*c)
	t := reflect.TypeOf(*c)
	values := make([]interface{}, v.NumField())
	var str string
	for i := 0; i < v.NumField(); i++ {
		values[i] = v.Field(i).Interface()
		sourcesMap := v.Field(i).Interface().(map[string]bool)
		var sources []string
		if len(sourcesMap) > 0 {
			field := v.Type().Field(i).Name
			name, _ := t.FieldByName(field)
			str += name.Tag.Get("source")
			for k, v := range sourcesMap {
				if v {
					sources = append(sources, formatSource(k))
				}
			}
			str += " " + strings.Join(sources, " ") + "; "
		}
	}
	return str
}

func mkNonce() string {
	bytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bytes[i] = byte(65 + rand.Intn(25))
	}
	return string(bytes)
}

// SetModerateDefaults sets reasonable defaults, and returns a nonce value for usage in scripts
func (c *CSP3) SetModerateDefaults() string {
	nonce := mkNonce()
	c.DefaultSrc["'none'"] = true
	c.ConnectSrc["'self'"] = true
	c.ImgSrc["'self'"] = true
	c.ScriptSrc[fmt.Sprintf("'nonce-%v'", nonce)] = true
	c.ScriptSrc["'strict-dynamic'"] = true
	c.ObjectSrc["'none'"] = true
	c.BaseURI["'none'"] = true
	return nonce
}

// SetSecureDefaults sets locked down defaults, and returns a nonce value for usage in scripts
func (c *CSP3) SetSecureDefaults() string {
	nonce := mkNonce()
	c.DefaultSrc["'none'"] = true
	c.ConnectSrc["'self'"] = true
	c.ImgSrc["'self'"] = true
	c.ScriptSrc[fmt.Sprintf("'nonce-%v'", nonce)] = true
	c.ObjectSrc["'none'"] = true
	c.BaseURI["'none'"] = true
	return nonce
}

// SetAllowOldBrowsers sets backwards-compatible options
func (c *CSP3) SetAllowOldBrowsers() {
	c.ScriptSrc["'unsafe-inline'"] = true // ignored by browsers that support nonce/digest
	/* not sure if these should be in here. Appears to make CSP2 less safe
	c.ScriptSrc["http:"] = true
	c.ScriptSrc["https:"] = true
	*/
}
