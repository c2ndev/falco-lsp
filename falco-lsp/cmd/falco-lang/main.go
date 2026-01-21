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

// Package main implements the falco-lang CLI tool.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/formatter"
	"github.com/c2ndev/falco-lsp/internal/lsp"
	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/c2ndev/falco-lsp/internal/version"
)

const (
	// File extensions.
	extYAML = ".yaml"
	extYML  = ".yml"

	// Severity levels.
	severityError   = "error"
	severityWarning = "warning"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "falco-lang",
		Short:   "Falco Language Tools",
		Long:    `A CLI tool for working with Falco security rules files.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version.Version, version.Commit, version.BuildTime),
	}

	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(formatCmd())
	rootCmd.AddCommand(lspCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func validateCmd() *cobra.Command {
	var (
		outputFormat string
		strict       bool
	)

	cmd := &cobra.Command{
		Use:   "validate <files...>",
		Short: "Validate Falco rules files",
		Long:  `Validate one or more Falco rules files for syntax and semantic errors.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runValidate(args, outputFormat, strict)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json")
	cmd.Flags().BoolVarP(&strict, "strict", "s", false, "Treat warnings as errors")

	return cmd
}

// ValidationResult represents the result of validating a file.
type ValidationResult struct {
	File        string             `json:"file"`
	Valid       bool               `json:"valid"`
	Errors      int                `json:"errors"`
	Warnings    int                `json:"warnings"`
	Diagnostics []DiagnosticOutput `json:"diagnostics,omitempty"`
}

// DiagnosticOutput is the JSON-serializable diagnostic format.
type DiagnosticOutput struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Code     string `json:"code,omitempty"`
}

func runValidate(files []string, format string, strict bool) error {
	expandedFiles, err := expandPatterns(files)
	if err != nil {
		return fmt.Errorf("error expanding patterns: %w", err)
	}

	if len(expandedFiles) == 0 {
		return fmt.Errorf("no files to validate")
	}

	// Parse all files
	docs := make(map[string]*parser.Document)
	parseResults := make(map[string]*parser.ParseResult)

	for _, file := range expandedFiles {
		// #nosec G304 - file paths are validated by expandPatterns
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", file, err)
		}

		result, err := parser.Parse(string(content), file)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", file, err)
		}

		docs[file] = result.Document
		parseResults[file] = result
	}

	// Analyze all files together
	a := analyzer.NewAnalyzer()
	analysisResult := a.AnalyzeMultiple(docs)

	// Collect results
	results := []ValidationResult{}
	totalErrors := 0
	totalWarnings := 0

	for _, file := range expandedFiles {
		parseResult := parseResults[file]
		diagnostics := []DiagnosticOutput{}
		errors := 0
		warnings := 0

		// Add parse diagnostics
		for _, d := range parseResult.Diagnostics {
			sev := severityError
			if d.Severity == severityWarning {
				sev = severityWarning
				warnings++
			} else {
				errors++
			}
			diagnostics = append(diagnostics, DiagnosticOutput{
				Severity: sev,
				Message:  d.Message,
				Line:     d.Line,
				Column:   d.Column,
			})
		}

		// Add analysis diagnostics for this file only
		for _, d := range analysisResult.Diagnostics {
			// Only include diagnostics for the current file
			if d.Filename != file {
				continue
			}

			sev := d.Severity.String()
			switch d.Severity {
			case analyzer.SeverityError:
				errors++
			case analyzer.SeverityWarning:
				warnings++
			case analyzer.SeverityHint, analyzer.SeverityInfo:
				// Hints and info don't count as errors or warnings
			}

			// ast.Position.Line is already 1-based, Column is 0-based
			// Convert Column to 1-based for display
			line := d.Range.Start.Line
			column := d.Range.Start.Column + 1

			diagnostics = append(diagnostics, DiagnosticOutput{
				Severity: sev,
				Message:  d.Message,
				Line:     line,
				Column:   column,
				Code:     d.Code,
			})
		}

		valid := errors == 0
		if strict {
			valid = errors == 0 && warnings == 0
		}

		results = append(results, ValidationResult{
			File:        file,
			Valid:       valid,
			Errors:      errors,
			Warnings:    warnings,
			Diagnostics: diagnostics,
		})

		totalErrors += errors
		totalWarnings += warnings
	}

	// Output results
	if format == "json" {
		return outputJSON(results)
	}
	return outputText(results, totalErrors, totalWarnings, strict)
}

func outputJSON(results []ValidationResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func outputText(results []ValidationResult, totalErrors, totalWarnings int, strict bool) error {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	for _, result := range results {
		if result.Valid && len(result.Diagnostics) == 0 {
			fmt.Printf("%s %s\n", green("✓"), result.File)
			continue
		}

		if result.Valid {
			fmt.Printf("%s %s\n", yellow("⚠"), result.File)
		} else {
			fmt.Printf("%s %s\n", red("✗"), result.File)
		}

		for _, d := range result.Diagnostics {
			// VSCode terminal auto-detects filepath:line:column pattern and makes it clickable
			// Show location in a compact format on its own line for better readability
			var locLink string
			if d.Line > 0 {
				locLink = fmt.Sprintf("%s:%d:%d", result.File, d.Line, d.Column)
			} else {
				locLink = result.File
			}

			switch d.Severity {
			case "error":
				fmt.Printf("    %s\n", cyan(locLink))
				fmt.Printf("    %s %s\n\n", red("error:"), d.Message)
			case "warning":
				fmt.Printf("    %s\n", cyan(locLink))
				fmt.Printf("    %s %s\n\n", yellow("warning:"), d.Message)
			default:
				fmt.Printf("    %s\n", cyan(locLink))
				fmt.Printf("    %s %s\n\n", dim(d.Severity+":"), d.Message)
			}
		}
	}

	fmt.Println()
	if totalErrors == 0 && totalWarnings == 0 {
		fmt.Printf("%s All files valid\n", green("✓"))
	} else {
		summary := fmt.Sprintf("%d errors, %d warnings", totalErrors, totalWarnings)
		if totalErrors > 0 {
			fmt.Printf("%s %s\n", red("✗"), summary)
		} else {
			fmt.Printf("%s %s\n", yellow("⚠"), summary)
		}
	}

	if totalErrors > 0 || (strict && totalWarnings > 0) {
		os.Exit(1)
	}
	return nil
}

func formatCmd() *cobra.Command {
	var (
		write   bool
		check   bool
		diff    bool
		tabSize int
	)

	cmd := &cobra.Command{
		Use:   "format <files...>",
		Short: "Format Falco rules files",
		Long: `Format one or more Falco rules files.

By default, prints the formatted output to stdout.
Use -w to write changes back to the source file.
Use -c to check if files are already formatted (exits with 1 if not).

Examples:
  falco-lang format rules.yaml
  falco-lang format -w *.falco.yaml
  falco-lang format -c --diff rules/`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runFormat(args, write, check, diff, tabSize)
		},
	}

	cmd.Flags().BoolVarP(&write, "write", "w", false, "Write result to source file instead of stdout")
	cmd.Flags().BoolVarP(&check, "check", "c", false, "Check if files are formatted (exit 1 if not)")
	cmd.Flags().BoolVarP(&diff, "diff", "d", false, "Display diff of formatting changes")
	cmd.Flags().IntVar(&tabSize, "tab-size", 2, "Number of spaces for indentation")

	return cmd
}

// runFormat executes the format command.
func runFormat(patterns []string, write, check, showDiff bool, tabSize int) error {
	opts := formatter.DefaultOptions()
	opts.TabSize = tabSize

	files, err := expandPatterns(patterns)
	if err != nil {
		return fmt.Errorf("error expanding patterns: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no files matched the given patterns")
	}

	hasUnformatted := false
	errorCount := 0

	for _, file := range files {
		// Get file info to preserve permissions
		fileInfo, err := os.Stat(file)
		if err != nil {
			color.Red("Error stat %s: %v", file, err)
			errorCount++
			continue
		}

		// #nosec G304 - file paths are validated by expandPatterns
		content, err := os.ReadFile(file)
		if err != nil {
			color.Red("Error reading %s: %v", file, err)
			errorCount++
			continue
		}

		formatted := formatter.Format(string(content), opts)
		isFormatted := string(content) == formatted

		if check {
			if !isFormatted {
				hasUnformatted = true
				color.Yellow("%s needs formatting", file)
				if showDiff {
					printDiff(string(content), formatted, file)
				}
			} else {
				color.Green("%s is formatted", file)
			}
			continue
		}

		if write {
			if !isFormatted {
				// Preserve original file permissions
				perm := fileInfo.Mode().Perm()
				if err := os.WriteFile(file, []byte(formatted), perm); err != nil {
					color.Red("Error writing %s: %v", file, err)
					errorCount++
					continue
				}
				color.Green("Formatted %s", file)
			}
		} else {
			// Print to stdout
			fmt.Print(formatted)
		}
	}

	if errorCount > 0 {
		return fmt.Errorf("%d error(s) occurred", errorCount)
	}

	if check && hasUnformatted {
		return fmt.Errorf("some files need formatting")
	}

	return nil
}

// printDiff prints a simple diff between two strings.
func printDiff(original, formatted, filename string) {
	fmt.Printf("\n--- %s (original)\n+++ %s (formatted)\n", filename, filename)

	origLines := strings.Split(original, "\n")
	fmtLines := strings.Split(formatted, "\n")

	maxLen := max(len(origLines), len(fmtLines))

	for i := range maxLen {
		origLine := ""
		fmtLine := ""
		if i < len(origLines) {
			origLine = origLines[i]
		}
		if i < len(fmtLines) {
			fmtLine = fmtLines[i]
		}

		if origLine != fmtLine {
			if origLine != "" {
				color.Red("- %s", origLine)
			}
			if fmtLine != "" {
				color.Green("+ %s", fmtLine)
			}
		}
	}
	fmt.Println()
}

// expandPatterns expands file patterns (globs, directories) to a list of files.
func expandPatterns(patterns []string) ([]string, error) {
	var files []string

	for _, pattern := range patterns {
		info, err := os.Stat(pattern)
		if err == nil && info.IsDir() {
			// Walk directory recursively
			err := filepath.Walk(pattern, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && isFalcoFile(path) {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("failed to walk directory %s: %w", pattern, err)
			}
			continue
		}

		// Try as glob pattern
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %s: %w", pattern, err)
		}
		if len(matches) == 0 {
			// Treat as literal file
			if _, err := os.Stat(pattern); err == nil {
				files = append(files, pattern)
			} else {
				return nil, fmt.Errorf("file not found: %s", pattern)
			}
		} else {
			// Filter only Falco files from glob matches
			for _, match := range matches {
				info, err := os.Stat(match)
				if err != nil {
					continue
				}
				if info.IsDir() {
					// Recursively walk directories from glob
					_ = filepath.Walk(match, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						if !info.IsDir() && isFalcoFile(path) {
							files = append(files, path)
						}
						return nil
					})
				} else if isFalcoFile(match) {
					files = append(files, match)
				}
			}
		}
	}

	return files, nil
}

// isFalcoFile returns true if the file is a Falco rules file.
// Falco file extension constants for isFalcoFile.
const (
	extFalcoYAML = ".falco.yaml"
	extFalcoYML  = ".falco.yml"
)

func isFalcoFile(path string) bool {
	ext := filepath.Ext(path)
	base := filepath.Base(path)

	// Check common Falco extensions
	if ext == extYAML || ext == extYML {
		// Check if it's a .falco.yaml or .falco.yml
		if len(base) > len(extFalcoYAML) && base[len(base)-len(extFalcoYAML):] == extFalcoYAML {
			return true
		}
		if len(base) > len(extFalcoYML) && base[len(base)-len(extFalcoYML):] == extFalcoYML {
			return true
		}
		// Also accept any .yaml/.yml file (user might have different naming)
		return true
	}
	return false
}

func lspCmd() *cobra.Command {
	var (
		stdio bool
	)

	cmd := &cobra.Command{
		Use:   "lsp",
		Short: "Start the Language Server Protocol server",
		Long:  `Start the LSP server for IDE integration.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !stdio {
				return fmt.Errorf("only stdio mode is currently supported")
			}
			server := lsp.NewServer()
			return server.Run()
		},
	}

	cmd.Flags().BoolVar(&stdio, "stdio", true, "Use stdio for communication")

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("falco-lang version %s\n", version.Version)
			fmt.Printf("  commit:  %s\n", version.Commit)
			fmt.Printf("  built:   %s\n", version.BuildTime)
		},
	}
}
