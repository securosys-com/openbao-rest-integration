// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*KVCommand)(nil)

type KVCommand struct {
	*BaseCommand
}

func (c *KVCommand) Synopsis() string {
	return "Interact with OpenBao's Key-Value storage"
}

func (c *KVCommand) Help() string {
	helpText := `
Usage: bao kv <subcommand> [options] [args]

  This command has subcommands for interacting with OpenBao's key-value
  store. Here are some simple examples, and more detailed examples are
  available in the subcommands or the documentation.

  Create or update the key named "foo" in the "secret" mount with the value
  "bar=baz":

      $ bao kv put -mount=secret foo bar=baz

  Read this value back:

      $ bao kv get -mount=secret foo

  Get metadata for the key:

      $ bao kv metadata get -mount=secret foo
	  
  Get a specific version of the key:

      $ bao kv get -mount=secret -version=1 foo

  The deprecated path-like syntax can also be used, but this should be avoided 
  for KV v2, as the fact that it is not actually the full API path to 
  the secret (secret/data/foo) can cause confusion:   
  
      $ bao kv get secret/foo

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *KVCommand) Run(args []string) int {
	return cli.RunResultHelp
}
