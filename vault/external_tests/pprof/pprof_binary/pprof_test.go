// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pprof_binary

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/vault/external_tests/pprof"
)

// TestSysPprof_Exec is the same as TestSysPprof, but using a Vault binary
// running as -dev instead of a fake single node TestCluster.  There's no
// particular reason why TestSysPprof was chosen to validate that mechanism,
// other than that it was fast and simple.
func TestSysPprof_Exec(t *testing.T) {
	t.Parallel()
	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("only running exec test when $VAULT_BINARY present")
	}
	cluster := testcluster.NewTestExecDevCluster(t, &testcluster.ExecDevClusterOptions{
		ClusterOptions: testcluster.ClusterOptions{
			NumCores: 1,
		},
		BinaryPath:        binary,
		BaseListenAddress: "127.0.0.1:8208",
	})
	defer cluster.Cleanup()

	pprof.SysPprof_Test(t, cluster)
}

// TestSysPprof_Standby_Exec is the same as TestSysPprof_Standby, but using a Vault binary
// running as -dev-three-node instead of a fake single node TestCluster.  There's
// no particular reason why TestSysPprof was chosen to validate that mechanism,
// other than that it was fast and simple.
func TestSysPprof_Standby_Exec(t *testing.T) {
	t.Parallel()
	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("only running exec test when $VAULT_BINARY present")
	}
	cluster := testcluster.NewTestExecDevCluster(t, &testcluster.ExecDevClusterOptions{
		ClusterOptions: testcluster.ClusterOptions{
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				DisablePerformanceStandby: true,
			},
		},
		BinaryPath:        binary,
		BaseListenAddress: "127.0.0.1:8210",
	})
	defer cluster.Cleanup()

	pprof.SysPprof_Standby_Test(t, cluster)
}
