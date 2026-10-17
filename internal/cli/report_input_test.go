package cli

import (
	"strings"
	"testing"
)

func TestReportStdinMatchesExactBytes(t *testing.T) {
	c := newTestCLI(t)
	c.put("without-newline", "same-value")
	// put removes one final newline, so these records differ by one byte.
	c.put("with-newline", "same-value\n\n", "--allow-get=false", "--allow-exec=false")
	output, _ := c.ok("same-value\n", "report", "--secret-stdin", "--json")
	if !strings.Contains(output, "with-newline") || strings.Contains(output, "without-newline") {
		t.Fatalf("report --secret-stdin did not preserve exact bytes: %q", output)
	}
}
