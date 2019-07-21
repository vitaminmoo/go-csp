package csp

import (
	"fmt"
	"log"
	"strings"
	"unicode"

	"github.com/vitaminmoo/orderedset"
)

// Policy is a representation of a CSP Policy
// The version is kind of a moot point, as we need to represent a superset of all available versions
type Policy struct {
	Directives orderedset.OrderedSet
	Sources    map[string]*orderedset.OrderedSet
	Nonce      string
}

// NewPolicy creates a new policy
func NewPolicy() *Policy {
	return &Policy{
		Sources: make(map[string]*orderedset.OrderedSet),
	}
}

// FromString creates a policy by parsing a Serialized CSP
func FromString(header string) *Policy {
	policy := NewPolicy()
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
		if _, ok := policy.Sources[directiveName]; !ok {
			// it doesn't exist, jam it in
			policy.Directives.Append(directiveName)
			policy.Sources[directiveName] = &orderedset.OrderedSet{}
			for _, v := range strings.Fields(rest) {
				policy.Sources[directiveName].Append(v)
			}
		} else {
			// it exists, warn and get out
			log.Printf("Ignoring duplicate directive: \"%v %v\"", directiveName, rest)
		}
	}
	return policy
}

// Set replaces a directive's sources with the specified sources
func (p *Policy) Set(directive string, sources []string) {
	p.Directives.Append(directive)
	p.Sources[directive] = &orderedset.OrderedSet{}
	for _, v := range sources {
		p.Sources[directive].Append(v)
	}
}

// String returns a string representation of the Policy, ready for inclusion as a Content-Security-Policy header
func (p *Policy) String() string {
	var str []string
	for _, i := range p.Directives.AsSlice() {
		str = append(str, fmt.Sprintf("%v %v;", i, strings.Join(p.Sources[i].AsSlice(), " ")))
	}
	return strings.Join(str, " ")
}

// SetModerateDefaults sets reasonable defaults, and returns a nonce value for usage in scripts
func (p *Policy) SetModerateDefaults() {
	p.Nonce = mkNonce()
	p.Set("default-src", []string{"'none'"})
	p.Set("connect-src", []string{"'self'"})
	p.Set("img-src", []string{"'self'"})
	p.Set("script-src", []string{fmt.Sprintf("'nonce-%v'", p.Nonce), "'strict-dynamic'"})
	p.Set("object-src", []string{"'none'"})
	p.Set("base-uri", []string{"'none'"})
}

// SetSecureDefaults sets locked down defaults, and returns a nonce value for usage in scripts
func (p *Policy) SetSecureDefaults() {
	p.Nonce = mkNonce()
	p.Set("default-src", []string{"'none'"})
	p.Set("connect-src", []string{"'self'"})
	p.Set("img-src", []string{"'self'"})
	p.Set("script-src", []string{fmt.Sprintf("'nonce-%v'", p.Nonce)})
	p.Set("object-src", []string{"'none'"})
	p.Set("base-uri", []string{"'none'"})
}

// AddAllowOldBrowsers adds backwards-compatible options
func (p *Policy) AddAllowOldBrowsers() {
	p.Directives.Append("script-src")
	p.Sources["script-src"].Append("'unsafe-inline'")
	/* not sure if these should be in here. Appears to make CSP2 less safe
	p.Sources["script-src"].Append("http:")
	p.Sources["script-src"].Append("https:")
	*/
}
