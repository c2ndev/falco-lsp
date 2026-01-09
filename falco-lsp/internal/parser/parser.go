// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Alessandro Cannarella
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser

import (
	"fmt"
	"strings"

	"github.com/c2ndev/falco-lsp/internal/schema"
	"gopkg.in/yaml.v3"
)

// safeColumnConvert converts 1-based YAML column to 0-based, clamping to 0 if negative.
func safeColumnConvert(col int) int {
	if col <= 0 {
		return 0
	}
	return col - 1
}

// Document represents a parsed Falco rules file.
type Document struct {
	Items []Item
}

// Item represents a top-level item in a Falco rules file.
type Item interface {
	isItem()
}

// Rule represents a Falco rule definition.
type Rule struct {
	Name       string
	Desc       string
	Condition  string
	Output     string
	Priority   string
	Source     string
	Tags       []string
	Enabled    *bool
	Append     bool
	Exceptions []Exception
	Line       int // Line number where the rule starts (1-based)
	Column     int // Column number where the rule starts (1-based)
}

func (Rule) isItem() {}

// Macro represents a Falco macro definition.
type Macro struct {
	Name      string
	Condition string
	Append    bool
	Line      int // Line number where the macro starts (1-based)
	Column    int // Column number where the macro starts (1-based)
}

func (Macro) isItem() {}

// List represents a Falco list definition.
type List struct {
	Name   string
	Items  []string
	Append bool
	Line   int // Line number where the list starts (1-based)
	Column int // Column number where the list starts (1-based)
}

func (List) isItem() {}

// RequiredEngineVersion represents the required_engine_version directive.
type RequiredEngineVersion struct {
	Version string
}

func (RequiredEngineVersion) isItem() {}

// RequiredPluginVersions represents the required_plugin_versions directive.
type RequiredPluginVersions struct {
	Plugins []PluginVersion
}

func (RequiredPluginVersions) isItem() {}

// PluginVersion represents a plugin version requirement.
type PluginVersion struct {
	Name    string
	Version string
}

// Exception represents a rule exception.
type Exception struct {
	Name   string
	Fields []string
	Comps  []string
	Values [][]string
}

// Diagnostic represents a parsing or semantic error/warning.
type Diagnostic struct {
	Severity string // "error", "warning", "hint"
	Message  string
	Line     int
	Column   int
}

// ParseResult contains the result of parsing a Falco rules file.
type ParseResult struct {
	Document    *Document
	Diagnostics []Diagnostic
}

// Parse parses a Falco rules file from YAML content.
func Parse(content, _ string) (*ParseResult, error) {
	// Handle empty content
	if strings.TrimSpace(content) == "" {
		return &ParseResult{
			Document:    &Document{Items: []Item{}},
			Diagnostics: []Diagnostic{},
		}, nil
	}

	// Use yaml.Node to preserve line/column information
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	doc := &Document{
		Items: make([]Item, 0),
	}
	var diagnostics []Diagnostic

	// Root should be a document node containing a sequence
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return &ParseResult{
			Document:    doc,
			Diagnostics: diagnostics,
		}, nil
	}

	seqNode := root.Content[0]
	if seqNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("expected sequence of items at root level")
	}

	for _, itemNode := range seqNode.Content {
		if itemNode.Kind != yaml.MappingNode {
			continue
		}

		item := parseItemFromNode(itemNode)
		if item != nil {
			doc.Items = append(doc.Items, item)
		}
	}

	return &ParseResult{
		Document:    doc,
		Diagnostics: diagnostics,
	}, nil
}

// getStringValue extracts a string value from a YAML node.
func getStringValue(node *yaml.Node) string {
	if node == nil {
		return ""
	}
	return node.Value
}

// getNodeValue finds the value node for a given key in a mapping node.
func getNodeValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		keyNode := mapping.Content[i]
		valueNode := mapping.Content[i+1]
		if keyNode.Value == key {
			return valueNode
		}
	}
	return nil
}

// getBoolValue gets a boolean value from a node.
func getBoolValue(node *yaml.Node) *bool {
	if node == nil {
		return nil
	}
	if node.Tag == "!!bool" {
		val := node.Value == "true"
		return &val
	}
	return nil
}

// getStringSlice extracts a string slice from a sequence node.
func getStringSlice(node *yaml.Node) []string {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	result := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		result = append(result, item.Value)
	}
	return result
}

func parseItemFromNode(node *yaml.Node) Item {
	// Check for rule
	if ruleNode := getNodeValue(node, schema.PropRule.String()); ruleNode != nil {
		rule := Rule{
			Name:   getStringValue(ruleNode),
			Line:   node.Line,                      // YAML node.Line is 1-based, keep as-is
			Column: safeColumnConvert(node.Column), // YAML node.Column is 1-based, convert to 0-based
		}
		if v := getNodeValue(node, schema.PropDesc.String()); v != nil {
			rule.Desc = getStringValue(v)
		}
		if v := getNodeValue(node, schema.PropCondition.String()); v != nil {
			rule.Condition = getStringValue(v)
		}
		if v := getNodeValue(node, schema.PropOutput.String()); v != nil {
			rule.Output = getStringValue(v)
		}
		if v := getNodeValue(node, schema.PropPriority.String()); v != nil {
			rule.Priority = getStringValue(v)
		}
		if v := getNodeValue(node, schema.PropSource.String()); v != nil {
			rule.Source = getStringValue(v)
		}
		if v := getNodeValue(node, schema.PropTags.String()); v != nil {
			rule.Tags = getStringSlice(v)
		}
		if v := getNodeValue(node, schema.PropEnabled.String()); v != nil {
			rule.Enabled = getBoolValue(v)
		}
		if v := getNodeValue(node, schema.PropAppend.String()); v != nil {
			if b := getBoolValue(v); b != nil {
				rule.Append = *b
			}
		}
		return rule
	}

	// Check for macro
	if macroNode := getNodeValue(node, schema.PropMacro.String()); macroNode != nil {
		macro := Macro{
			Name:   getStringValue(macroNode),
			Line:   node.Line,                      // YAML node.Line is 1-based, keep as-is
			Column: safeColumnConvert(node.Column), // YAML node.Column is 1-based, convert to 0-based
		}
		if v := getNodeValue(node, schema.PropCondition.String()); v != nil {
			macro.Condition = getStringValue(v)
		}
		if v := getNodeValue(node, schema.PropAppend.String()); v != nil {
			if b := getBoolValue(v); b != nil {
				macro.Append = *b
			}
		}
		return macro
	}

	// Check for list
	if listNode := getNodeValue(node, schema.PropList.String()); listNode != nil {
		list := List{
			Name:   getStringValue(listNode),
			Line:   node.Line,                      // YAML node.Line is 1-based, keep as-is
			Column: safeColumnConvert(node.Column), // YAML node.Column is 1-based, convert to 0-based
		}
		if v := getNodeValue(node, schema.PropItems.String()); v != nil {
			list.Items = getStringSlice(v)
		}
		if v := getNodeValue(node, schema.PropAppend.String()); v != nil {
			if b := getBoolValue(v); b != nil {
				list.Append = *b
			}
		}
		return list
	}

	// Check for required_engine_version
	if versionNode := getNodeValue(node, schema.PropRequiredEngineVersion.String()); versionNode != nil {
		return RequiredEngineVersion{
			Version: getStringValue(versionNode),
		}
	}

	// Check for required_plugin_versions
	if pluginsNode := getNodeValue(node, schema.PropRequiredPluginVersions.String()); pluginsNode != nil {
		rpv := RequiredPluginVersions{}
		if pluginsNode.Kind == yaml.SequenceNode {
			for _, p := range pluginsNode.Content {
				if p.Kind == yaml.MappingNode {
					pv := PluginVersion{}
					if nameNode := getNodeValue(p, "name"); nameNode != nil {
						pv.Name = getStringValue(nameNode)
					}
					if versionNode := getNodeValue(p, "version"); versionNode != nil {
						pv.Version = getStringValue(versionNode)
					}
					rpv.Plugins = append(rpv.Plugins, pv)
				}
			}
		}
		return rpv
	}

	return nil
}
