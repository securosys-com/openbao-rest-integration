// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*SecretsCommand)(nil)

type SecretsCommand struct {
	*BaseCommand
}

func (c *SecretsCommand) Synopsis() string {
	return "Interact with secrets engines"
}

func (c *SecretsCommand) Help() string {
	helpText := `
Usage: bao secrets <subcommand> [options] [args]

  This command groups subcommands for interacting with OpenBao's secrets engines.
  Each secret engine behaves differently. Please see the documentation for
  more information.

  List all enabled secrets engines:

      $ bao secrets list

  Enable a new secrets engine:

      $ bao secrets enable database

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *SecretsCommand) Run(args []string) int {
	return cli.RunResultHelp
}
