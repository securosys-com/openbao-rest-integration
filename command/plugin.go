// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
)

var _ cli.Command = (*PluginCommand)(nil)

type PluginCommand struct {
	*BaseCommand
}

func (c *PluginCommand) Synopsis() string {
	return "Interact with OpenBao plugins and catalog"
}

func (c *PluginCommand) Help() string {
	helpText := `
Usage: bao plugin <subcommand> [options] [args]

  This command groups subcommands for interacting with OpenBao's plugins and the
  plugin catalog. The plugin catalog is divided into three types: "auth", 
  "database", and "secret" plugins. A type must be specified on each call. Here 
  are a few examples of the plugin commands.

  List all available plugins in the catalog of a particular type:

      $ bao plugin list database

  Register a new plugin to the catalog as a particular type:

      $ bao plugin register -sha256=d3f0a8b... auth my-custom-plugin

  Get information about a plugin in the catalog listed under a particular type:

      $ bao plugin info auth my-custom-plugin

  Please see the individual subcommand help for detailed usage information.
`

	return strings.TrimSpace(helpText)
}

func (c *PluginCommand) Run(args []string) int {
	return cli.RunResultHelp
}
