package main

import "embed"

// templateFiles embeds the `templates` directory so templates can be accessed
// via the embedded filesystem when bundling the binary.
//
//go:embed templates/*
var templateFiles embed.FS
