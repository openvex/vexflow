// SPDX-FileCopyrightText: Copyright 2025 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"
)

func TestIngestScanResults(t *testing.T) {
	results := &models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{Name: "golang.org/x/net", Version: "0.32.0", Ecosystem: "Go"},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GO-2024-3333", Aliases: []string{"CVE-2024-45338", "GHSA-w32m-9786-jp63"}},
						// No CVE alias: the vulnerability keeps its own ID.
						{Id: "GO-2025-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}},
					},
				},
				{
					// The second package's only vulnerability has no CVE alias.
					// Looking its ID up by the package index read past the end
					// of the list and panicked.
					Package: models.PackageInfo{Name: "golang.org/x/crypto", Version: "0.31.0", Ecosystem: "Go"},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-dddd-eeee-ffff"},
					},
				},
			},
		}},
	}

	vulns, err := New().ingestScanResults(results)
	require.NoError(t, err)
	require.Len(t, vulns, 3)

	require.Equal(t, "CVE-2024-45338", vulns[0].ID)
	require.Equal(t, []string{"GHSA-w32m-9786-jp63", "GO-2024-3333"}, vulns[0].Aliases)

	require.Equal(t, "GO-2025-0001", vulns[1].ID)
	require.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, vulns[1].Aliases)
	require.Equal(t, "pkg:golang/golang.org/x/net@v0.32.0", vulns[1].Component.Purl)

	require.Equal(t, "GHSA-dddd-eeee-ffff", vulns[2].ID)
	require.Equal(t, "pkg:golang/golang.org/x/crypto@v0.31.0", vulns[2].Component.Purl)
}
