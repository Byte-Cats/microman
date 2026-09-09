package data_test

import (
	"testing"

	"github.com/byte-cats/microman/data"
)

type sample struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func TestJsonConvert(t *testing.T) {
	cases := []struct {
		name    string
		in      interface{}
		want    string
		wantErr bool
	}{
		{
			name: "struct",
			in:   sample{Name: "Rex", Age: 3},
			want: `{"name":"Rex","age":3}`,
		},
		{
			name: "map",
			in:   map[string]int{"a": 1},
			want: `{"a":1}`,
		},
		{
			name: "string",
			in:   "hello",
			want: `"hello"`,
		},
		{
			name: "nil",
			in:   nil,
			want: `null`,
		},
		{
			name: "unmarshalable value",
			// channels cannot be marshaled to JSON; JsonConvert currently
			// swallows the marshal error and always returns a nil error.
			in:   make(chan int),
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := data.JsonConvert(tc.in)
			if err != nil {
				t.Errorf("JsonConvert(%v) returned error %v, want nil (current implementation always returns nil)", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("JsonConvert(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
