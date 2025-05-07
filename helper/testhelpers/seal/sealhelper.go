// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sealhelper

import (
	"path"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/go-testing-interface"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/logical/transit"
	"github.com/openbao/openbao/helper/testhelpers/teststorage"
	"github.com/openbao/openbao/http"
	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/openbao/openbao/vault/seal"
)

type TransitSealServer struct {
	*vault.TestCluster
}

func NewTransitSealServer(t testing.T, idx int) *TransitSealServer {
	conf := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
		},
	}
	opts := &vault.TestClusterOptions{
		NumCores:    1,
		HandlerFunc: http.Handler,
		Logger:      logging.NewVaultLogger(hclog.Trace).Named(t.Name()).Named("transit-seal" + strconv.Itoa(idx)),
	}
	teststorage.InmemBackendSetup(conf, opts)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()

	if err := cluster.Cores[0].Client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	}); err != nil {
		t.Fatal(err)
	}

	return &TransitSealServer{cluster}
}

func (tss *TransitSealServer) MakeKey(t testing.T, key string) {
	client := tss.Cores[0].Client
	if _, err := client.Logical().Write(path.Join("transit", "keys", key), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Logical().Write(path.Join("transit", "keys", key, "config"), map[string]interface{}{
		"deletion_allowed": true,
	}); err != nil {
		t.Fatal(err)
	}
}

func (tss *TransitSealServer) MakeSeal(t testing.T, key string) (vault.Seal, error) {
	client := tss.Cores[0].Client
	wrapperConfig := map[string]string{
		"address":     client.Address(),
		"token":       client.Token(),
		"mount_path":  "transit",
		"key_name":    key,
		"tls_ca_cert": tss.CACertPEMFile,
	}
	transitSeal, _, err := configutil.GetTransitKMSFunc(&configutil.KMS{Config: wrapperConfig})
	if err != nil {
		t.Fatalf("error setting wrapper config: %v", err)
	}

	return vault.NewAutoSeal(seal.NewAccess(transitSeal))
}
