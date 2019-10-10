package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMakeSafeFileNameUNIX(t *testing.T) {
	if strings.Contains(runtime.GOOS, "windows") {
		t.Skipf("This test doesn't work on Windows")
	}

	tests := []struct {
		Input          string
		ExpectedOutput string
	}{
		{`/example/.file`, `/example/file`},
		{`/example$`, `/example-`},
		{`/home/daphne/cert*example`, `/home/daphne/cert-example`},
		{`/home/fred/cert?example`, `/home/fred/cert-example`},
		{`/home/velma/cert example`, `/home/velma/cert_example`},
	}

	for number, test := range tests {
		output := makeSafeFileName(test.Input)

		require.Equal(t, test.ExpectedOutput, output, "Test %v failed: unexpected output", number)
	}
}
