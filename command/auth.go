// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*AuthCommand)(nil)

type AuthCommand struct {
	*BaseCommand
}

func (c *AuthCommand) Synopsis() string {
	return "Interact with auth methods"
}

func (c *AuthCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao auth <subcommand> [options] [args]

  This command groups subcommands for interacting with OpenBao's auth methods.
  Users can list, enable, disable, and get help for different auth methods.

  To authenticate to OpenBao as a user or machine, use the "bao login" command
  instead. This command is for interacting with the auth methods themselves, not
  authenticating to OpenBao.

  List all enabled auth methods:

      $ bao auth list

  Enable a new auth method "userpass";

      $ bao auth enable userpass

  Get detailed help information about how to authenticate to a particular auth
  method:

      $ bao auth help github

  Please see the individual subcommand help for detailed usage information.
`)
}

func (c *AuthCommand) Run(args []string) int {
	return cli.RunResultHelp
}
