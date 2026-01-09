#!/usr/bin/env node
/**
 * Falco Schema Sync Script
 *
 * Downloads the official Falco rules JSON schema from the falcosecurity/falco
 * repository and converts it to a usable JSON schema file.
 *
 * Usage:
 *   pnpm sync-schema
 *   node scripts/sync-falco-schema.mjs
 *
 * This ensures our language tooling stays aligned with the official Falco schema.
 */

import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Official Falco schema source
const FALCO_SCHEMA_URL =
  'https://raw.githubusercontent.com/falcosecurity/falco/master/userspace/engine/rule_json_schema.h';

// Output paths
const SCHEMA_OUTPUT_DIR = path.join(__dirname, '..', 'packages', 'vscode-extension', 'schemas');
const SCHEMA_OUTPUT_FILE = path.join(SCHEMA_OUTPUT_DIR, 'falco-rules.schema.json');
const SCHEMA_METADATA_FILE = path.join(SCHEMA_OUTPUT_DIR, 'schema-metadata.json');

/**
 * Fetch content from a URL
 */
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, res => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}: Failed to fetch ${url}`));
          return;
        }

        let data = '';
        res.on('data', chunk => (data += chunk));
        res.on('end', () => resolve(data));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

/**
 * Extract JSON schema from C++ header file
 */
function extractSchemaFromHeader(headerContent) {
  // The schema is wrapped in LONG_STRING_CONST(...) macro
  // Find the JSON content between the macro
  const startMarker = 'LONG_STRING_CONST(';
  const endMarker = ');';

  const startIndex = headerContent.indexOf(startMarker);
  if (startIndex === -1) {
    throw new Error('Could not find LONG_STRING_CONST macro in header file');
  }

  // Find the opening brace of JSON
  const jsonStart = headerContent.indexOf('{', startIndex);
  if (jsonStart === -1) {
    throw new Error('Could not find JSON start in header file');
  }

  // Find matching closing brace by counting braces
  let braceCount = 0;
  let jsonEnd = -1;
  for (let i = jsonStart; i < headerContent.length; i++) {
    if (headerContent[i] === '{') braceCount++;
    if (headerContent[i] === '}') braceCount--;
    if (braceCount === 0) {
      jsonEnd = i + 1;
      break;
    }
  }

  if (jsonEnd === -1) {
    throw new Error('Could not find matching closing brace in JSON');
  }

  const jsonString = headerContent.substring(jsonStart, jsonEnd);

  // Parse to validate and then re-stringify for proper formatting
  try {
    const schema = JSON.parse(jsonString);
    return schema;
  } catch (e) {
    throw new Error(`Failed to parse JSON schema: ${e.message}`);
  }
}

/**
 * Enhance schema with additional metadata for VS Code
 */
function enhanceSchema(schema) {
  // Add VS Code specific enhancements
  const enhanced = {
    ...schema,
    $id: 'https://falco.org/schemas/falco-rules.schema.json',
    title: 'Falco Rules',
    description:
      'Official JSON Schema for Falco security rules. Auto-synced from falcosecurity/falco repository.',
  };

  // Add description to definitions if not present
  if (enhanced.definitions) {
    if (enhanced.definitions.FalcoRule) {
      enhanced.definitions.FalcoRule.description =
        'A Falco rule, macro, list, or version requirement';
    }
    if (enhanced.definitions.Priority) {
      enhanced.definitions.Priority.description = 'Rule priority/severity level';
    }
    if (enhanced.definitions.Exception) {
      enhanced.definitions.Exception.description =
        'Exception to exclude specific cases from rule detection';
    }
    if (enhanced.definitions.Override) {
      enhanced.definitions.Override.description =
        'Override specific properties of an existing rule';
    }
  }

  return enhanced;
}

/**
 * Main sync function
 */
async function syncSchema() {
  console.log('🦅 Falco Schema Sync');
  console.log('====================\n');

  console.log(`📥 Fetching schema from: ${FALCO_SCHEMA_URL}`);

  try {
    // Fetch the header file
    const headerContent = await fetchUrl(FALCO_SCHEMA_URL);
    console.log(`   ✓ Downloaded ${headerContent.length} bytes\n`);

    // Extract JSON schema
    console.log('🔧 Extracting JSON schema from C++ header...');
    const schema = extractSchemaFromHeader(headerContent);
    console.log('   ✓ Schema extracted successfully\n');

    // Enhance schema
    console.log('✨ Enhancing schema with VS Code metadata...');
    const enhancedSchema = enhanceSchema(schema);
    console.log('   ✓ Schema enhanced\n');

    // Ensure output directory exists
    if (!fs.existsSync(SCHEMA_OUTPUT_DIR)) {
      fs.mkdirSync(SCHEMA_OUTPUT_DIR, { recursive: true });
    }

    // Write schema file
    console.log(`💾 Writing schema to: ${SCHEMA_OUTPUT_FILE}`);
    fs.writeFileSync(SCHEMA_OUTPUT_FILE, JSON.stringify(enhancedSchema, null, 2) + '\n', 'utf-8');
    console.log('   ✓ Schema file written\n');

    // Write metadata file
    const metadata = {
      source: FALCO_SCHEMA_URL,
      syncedAt: new Date().toISOString(),
      schemaVersion: schema.$schema || 'unknown',
      definitionCount: Object.keys(schema.definitions || {}).length,
    };

    fs.writeFileSync(SCHEMA_METADATA_FILE, JSON.stringify(metadata, null, 2) + '\n', 'utf-8');
    console.log(`📋 Metadata saved to: ${SCHEMA_METADATA_FILE}`);
    console.log(`   Source: ${metadata.source}`);
    console.log(`   Synced: ${metadata.syncedAt}`);
    console.log(`   Definitions: ${metadata.definitionCount}\n`);

    console.log('✅ Schema sync complete!\n');

    // Validate schema can be loaded
    console.log('🧪 Validating schema...');
    const loadedSchema = JSON.parse(fs.readFileSync(SCHEMA_OUTPUT_FILE, 'utf-8'));
    if (loadedSchema.definitions && loadedSchema.definitions.FalcoRule) {
      console.log('   ✓ Schema is valid and loadable\n');
    }

    return true;
  } catch (error) {
    console.error(`\n❌ Error: ${error.message}\n`);
    process.exit(1);
  }
}

// Run if called directly
syncSchema();
