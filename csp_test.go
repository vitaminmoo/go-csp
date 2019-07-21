package csp

import (
	"reflect"
	"testing"

	"github.com/vitaminmoo/orderedset"
)

func TestNewPolicy(t *testing.T) {
	tests := []struct {
		name string
		want *Policy
	}{
		struct {
			name string
			want *Policy
		}{
			"blank",
			&Policy{
				Sources: make(map[string]*orderedset.OrderedSet),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPolicy(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromString(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name string
		args args
		want *Policy
	}{
		struct {
			name string
			args args
			want *Policy
		}{
			"simple",
			args{header: "img-src 'none';"},
			&Policy{
				Directives: *orderedset.NewOrderedSet([]string{"img-src"}),
				Sources: map[string]*orderedset.OrderedSet{
					"img-src": orderedset.NewOrderedSet([]string{"'none'"}),
				},
			},
		},
		{
			"medium",
			args{header: "img-src https: 'self'; object-src 'none'; default-src 'none'"},
			&Policy{
				Directives: *orderedset.NewOrderedSet([]string{"img-src", "object-src", "default-src"}),
				Sources: map[string]*orderedset.OrderedSet{
					"img-src":     orderedset.NewOrderedSet([]string{"https:", "'self'"}),
					"object-src":  orderedset.NewOrderedSet([]string{"'none'"}),
					"default-src": orderedset.NewOrderedSet([]string{"'none'"}),
				},
			},
		},
		{
			"dupe",
			args{header: "img-src https: 'self'; img-src 'none'"},
			&Policy{
				Directives: *orderedset.NewOrderedSet([]string{"img-src"}),
				Sources: map[string]*orderedset.OrderedSet{
					"img-src": orderedset.NewOrderedSet([]string{"https:", "'self'"}),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromString(tt.args.header); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromString() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestRoundTripFromString(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		struct {
			name string
			args args
			want string
		}{
			"simple",
			args{header: "img-src 'none';"},
			"img-src 'none';",
		},
		{
			"medium",
			args{header: "img-src https: 'self'; object-src 'none'; default-src 'none';"},
			"img-src https: 'self'; object-src 'none'; default-src 'none';",
		},
		{
			"dupe",
			args{header: "img-src https: 'self'; img-src 'none';"},
			"img-src https: 'self';",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromString(tt.args.header).String(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicy_Set(t *testing.T) {
	type args struct {
		directive string
		sources   []string
	}
	tests := []struct {
		name string
		p    *Policy
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.Set(tt.args.directive, tt.args.sources)
		})
	}
}

func TestPolicy_String(t *testing.T) {
	tests := []struct {
		name string
		p    *Policy
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("Policy.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicy_SetModerateDefaults(t *testing.T) {
	tests := []struct {
		name string
		p    *Policy
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.SetModerateDefaults()
		})
	}
}

func TestPolicy_SetSecureDefaults(t *testing.T) {
	tests := []struct {
		name string
		p    *Policy
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.SetSecureDefaults()
		})
	}
}

func TestPolicy_AddAllowOldBrowsers(t *testing.T) {
	tests := []struct {
		name string
		p    *Policy
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.AddAllowOldBrowsers()
		})
	}
}
