package cli

import (
	"strings"
	"testing"
)

func TestReportStdinMatchesExactBytes(t *testing.T) {
	c := newTestCLI(t)
	c.ok("", "put", "without-newline", "same-value")
	// Replace the second record with a value ending in LF through the positional
	// argument so the two records differ by one byte.
	c.ok("", "put", "with-newline", "same-value\n", "--allow-get=false", "--allow-exec=false")
	output, _ := c.ok("same-value\n", "report", "--secret-stdin", "--json")
	if !strings.Contains(output, "with-newline") || strings.Contains(output, "without-newline") {
		t.Fatalf("report --secret-stdin did not preserve exact bytes: %q", output)
	}
}
