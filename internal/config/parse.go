package config

import (
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/zclconf/go-cty/cty"
)

// ParseFile parses the given file for a configuration. The syntax of the
// file is determined based on the filename extension: "hcl" for HCL,
// "json" for JSON, other is an error.
func ParseFile(filename string) (*Config, error) {
	var config Config
	return &config, hclsimple.DecodeFile(filename, hclEnvVarsContext(), &config)
}

// Parse parses the configuration from the given reader. The reader will be
// read to completion (EOF) before returning so ensure that the reader
// does not block forever.
//
// format is either "hcl" or "json"
func Parse(r io.Reader, filename, format string) (*Config, error) {
	src, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var config Config
	return &config, hclsimple.Decode("config.hcl", src, hclEnvVarsContext(), &config)
}

func hclEnvVarsContext() *hcl.EvalContext {
	ctx := hcl.EvalContext{
		Variables: make(map[string]cty.Value),
	}
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		ctx.Variables[pair[0]] = cty.StringVal(pair[1])
	}
	return &ctx
}
