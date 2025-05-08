// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*PrintCommand)(nil)
	_ cli.CommandAutocomplete = (*PrintCommand)(nil)
)

type PrintCommand struct {
	*BaseCommand
}

func (c *PrintCommand) Synopsis() string {
	return "Prints runtime configurations"
}

func (c *PrintCommand) Help() string {
	helpText := `
Usage: bao print <subcommand>

	This command groups subcommands for interacting with OpenBao's runtime values.

Subcommands:
	token    Token currently in use
`
	return strings.TrimSpace(helpText)
}

func (c *PrintCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *PrintCommand) AutocompleteFlags() complete.Flags {
	return nil
}

func (c *PrintCommand) Run(args []string) int {
	return cli.RunResultHelp
}
