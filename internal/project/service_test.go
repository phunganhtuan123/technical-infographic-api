package project

import "testing"

func TestDescribeCountsScenesAndNodes(t *testing.T) {
	cases := []struct {
		name          string
		document      string
		scenes, nodes int
	}{
		{"flat document", `{"nodes":[{"id":"a"},{"id":"b"}],"edges":[]}`, 1, 2},
		{"scened document", `{"scenes":[{"nodes":[{"id":"a"}]},{"nodes":[{"id":"a"},{"id":"b"},{"id":"c"}]}]}`, 2, 3},
		{"empty", `{}`, 1, 0},
		// A malformed document must not take the save down with it — the counts
		// are only used for the project list.
		{"not json", `nonsense`, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scenes, nodes := describe([]byte(tc.document))
			if scenes != tc.scenes || nodes != tc.nodes {
				t.Errorf("describe() = (%d scenes, %d nodes), want (%d, %d)", scenes, nodes, tc.scenes, tc.nodes)
			}
		})
	}
}

func TestCheckSizeRefusesOversizedDocuments(t *testing.T) {
	service := &Service{maxDocumentBytes: 16}
	if err := service.checkSize([]byte(`{"ok":1}`)); err != nil {
		t.Fatalf("small document should pass: %v", err)
	}
	if err := service.checkSize(make([]byte, 17)); err == nil {
		t.Fatal("oversized document should be refused")
	}
}

func TestEtagFormat(t *testing.T) {
	if got := etag(42); got != `"42"` {
		t.Errorf("etag(42) = %s, want \"42\"", got)
	}
}
