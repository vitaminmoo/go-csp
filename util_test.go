package csp

import "testing"

func Test_isKeyword(t *testing.T) {
	type args struct {
		kw string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isKeyword(tt.args.kw); got != tt.want {
				t.Errorf("isKeyword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_formatSource(t *testing.T) {
	type args struct {
		source string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSource(tt.args.source); got != tt.want {
				t.Errorf("formatSource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mkNonce(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mkNonce(); got != tt.want {
				t.Errorf("mkNonce() = %v, want %v", got, tt.want)
			}
		})
	}
}
