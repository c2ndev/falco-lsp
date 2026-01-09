#!/usr/bin/env node
/**
 * @fileoverview Sync Falco fields for Go implementation
 *
 * This script downloads field definitions from falcosecurity repos
 * and generates the Go fields package.
 *
 * Usage: node scripts/sync-fields-go.mjs
 */

import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// GitHub raw content URLs
// NOTE: Using Go source files instead of READMEs because READMEs are often outdated
// as confirmed by Falco maintainers. Go source files are the source of truth.
const SOURCES = {
  k8saudit: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/k8saudit/pkg/k8saudit/fields.go',
    parser: parseGoFields,
    category: 'k8s_audit',
  },
  json: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/json/pkg/json/json.go',
    parser: parseGoFieldsMethod,
    category: 'k8s_audit',
  },
  cloudtrail: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/cloudtrail/pkg/cloudtrail/extract.go',
    parser: parseGoSupportedFields,
    category: 'cloudtrail',
  },
  okta: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/okta/pkg/okta/okta.go',
    parser: parseGoFieldsMethod,
    category: 'okta',
  },
  github: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/github/pkg/github/extract.go',
    parser: parseGoFieldsMethod,
    category: 'github',
  },
  gcpaudit: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/gcpaudit/pkg/gcpaudit/extract.go',
    parser: parseGoFieldsMethod,
    category: 'gcp_audit',
  },
  k8smeta: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/k8smeta/src/plugin.cpp',
    parser: parseCppFields,
    category: 'syscall', // k8smeta enriches syscall events
  },
  container: {
    url: 'https://raw.githubusercontent.com/falcosecurity/plugins/main/plugins/container/src/caps/extract/extract.cpp',
    parser: parseCppFields,
    category: 'syscall', // container enriches syscall events
  },
};

// Syscall fields - these come from falcosecurity/libs headers and Falco docs
// We'll embed the commonly used ones and fetch additional from docs
const SYSCALL_FIELDS_URL =
  'https://raw.githubusercontent.com/falcosecurity/libs/master/userspace/libsinsp/sinsp_filtercheck_fld_info.json';

function fetch(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'falco-language-sync' } }, res => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          return fetch(res.headers.location).then(resolve).catch(reject);
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
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

function parseGoFields(content, source) {
  const fields = [];
  const fieldRegex = /\{\s*Type:\s*"(\w+)",\s*Name:\s*"([^"]+)",\s*Desc:\s*"([^"]+)"/g;

  let match;
  while ((match = fieldRegex.exec(content)) !== null) {
    const [, type, name, desc] = match;
    const category = name.split('.')[0];
    fields.push({
      name,
      type: mapType(type),
      category,
      description: desc,
      isDynamic: name.includes('['),
    });
  }
  return fields;
}

/**
 * Parse Go source file with Fields() method that returns []sdk.FieldEntry
 * Used by: json, okta, github, gcpaudit
 */
function parseGoFieldsMethod(content, source) {
  const fields = [];

  // Match Fields() method that returns []sdk.FieldEntry{...}
  // This regex handles both single-line and multi-line field definitions
  // Pattern 1: {Type: "string", Name: "field.name", Desc: "description"}
  // Pattern 2: {
  //              Type: "string",
  //              Name: "field.name",
  //              Arg: ...,
  //              Desc: "description",
  //            }

  // First, try to extract the Fields() method body
  const methodMatch = content.match(
    /func\s+\([^)]+\)\s+Fields\(\)[^{]*\{[\s\S]*?return\s+\[\]sdk\.FieldEntry\{([\s\S]*?)\n\s*\}\s*\n\s*\}/
  );
  if (!methodMatch) {
    return fields;
  }

  const fieldsBody = methodMatch[1];

  // Split by field entries - each entry starts with { and we need to find matching }
  // Handle nested braces (like in Arg: sdk.FieldEntryArg{...})
  let depth = 0;
  let currentField = '';
  let inString = false;
  let escapeNext = false;

  for (let i = 0; i < fieldsBody.length; i++) {
    const char = fieldsBody[i];

    if (escapeNext) {
      currentField += char;
      escapeNext = false;
      continue;
    }

    if (char === '\\') {
      escapeNext = true;
      currentField += char;
      continue;
    }

    if (char === '"') {
      inString = !inString;
      currentField += char;
      continue;
    }

    if (inString) {
      currentField += char;
      continue;
    }

    if (char === '{') {
      depth++;
      currentField += char;
    } else if (char === '}') {
      depth--;
      currentField += char;

      if (depth === 0 && currentField.trim()) {
        // Parse this field entry
        const typeMatch = currentField.match(/Type:\s*"(\w+)"/);
        const nameMatch = currentField.match(/Name:\s*"([^"]+)"/);
        const descMatch = currentField.match(/Desc:\s*"([^"]*)"/);

        if (typeMatch && nameMatch) {
          const type = typeMatch[1];
          const name = nameMatch[1];
          const desc = descMatch ? descMatch[1] : '';
          const category = name.split('.')[0];

          fields.push({
            name,
            type: mapType(type),
            category,
            description: desc,
            isDynamic: name.includes('['),
          });
        }

        currentField = '';
      }
    } else {
      currentField += char;
    }
  }

  return fields;
}

/**
 * Parse Go source file with var supportedFields = []sdk.FieldEntry{...}
 * Used by: cloudtrail
 */
function parseGoSupportedFields(content, source) {
  const fields = [];

  // Match: var supportedFields = []sdk.FieldEntry{
  //          {Type: "string", Name: "field.name", Desc: "description"},
  //          ...
  //        }

  const fieldRegex =
    /\{Type:\s*"(\w+)",\s*Name:\s*"([^"]+)"(?:,\s*Display:\s*"[^"]*")?(?:,\s*Desc:\s*"([^"]+)")?/g;

  let match;
  while ((match = fieldRegex.exec(content)) !== null) {
    const [, type, name, desc] = match;
    const category = name.split('.')[0];
    fields.push({
      name,
      type: mapType(type),
      category,
      description: desc || '',
      isDynamic: name.includes('['),
    });
  }
  return fields;
}

/**
 * Parse C++ source file with get_fields() method that returns vector<field_info>
 * Used by: k8smeta
 *
 * Example C++ format:
 * const falcosecurity::field_info fields[] = {
 *   {ft::FTYPE_STRING, "k8smeta.pod.name", "Pod Name", "Kubernetes pod name.", {}, false, {}, true},
 *   {ft::FTYPE_STRING, "k8smeta.pod.uid", "Pod UID", "Kubernetes pod UID."},
 *   ...
 * };
 */
function parseCppFields(content, source) {
  const fields = [];

  // C++ type mapping
  const cppTypeMap = {
    FTYPE_STRING: 'string',
    FTYPE_UINT64: 'uint64',
    FTYPE_UINT32: 'uint32',
    FTYPE_INT64: 'int64',
    FTYPE_INT32: 'int32',
    FTYPE_BOOL: 'bool',
    FTYPE_IPADDR: 'ipaddr',
    FTYPE_IPNET: 'ipnet',
    FTYPE_RELTIME: 'reltime',
    FTYPE_ABSTIME: 'abstime',
  };

  // Match field entries in the fields array
  // Pattern: {ft::FTYPE_XXX, "field.name", "Display Name", "Description", ...}
  const fieldRegex = /\{ft::(\w+),\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)"/g;

  let match;
  while ((match = fieldRegex.exec(content)) !== null) {
    const [, cppType, name, displayName, desc] = match;
    const type = cppTypeMap[cppType] || 'string';
    const category = name.split('.')[0];

    fields.push({
      name,
      type,
      category,
      description: desc || displayName || '',
      isDynamic: name.includes('['),
    });
  }

  return fields;
}

function parsePluginReadme(content, source) {
  const fields = [];
  const tableRegex = /\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|[^|]*\|\s*([^|]+)\|/g;

  let match;
  while ((match = tableRegex.exec(content)) !== null) {
    const [, name, type, desc] = match;
    if (name.includes('.')) {
      const category = name.split('.')[0];
      fields.push({
        name: name.trim(),
        type: mapType(type.trim()),
        category,
        description: desc.trim(),
        isDynamic: false,
      });
    }
  }
  return fields;
}

function parseJsonReadme(content, source) {
  const fields = [];
  const tableRegex = /\|\s*`(jevt\.[^`]+)`\s*\|\s*`([^`]+)`\s*\|[^|]*\|\s*([^|]+)\|/g;

  let match;
  while ((match = tableRegex.exec(content)) !== null) {
    const [, name, type, desc] = match;
    fields.push({
      name: name.trim(),
      type: mapType(type.trim()),
      category: 'jevt',
      description: desc.trim(),
      isDynamic: false,
    });
  }
  return fields;
}

function parseSyscallFieldsJson(content) {
  const fields = [];
  try {
    const data = JSON.parse(content);
    for (const category of data) {
      if (category.fields) {
        for (const field of category.fields) {
          fields.push({
            name: field.name,
            type: mapType(field.type || 'string'),
            category: field.name.split('.')[0],
            description: field.desc || '',
            isDynamic:
              field.name.includes('[') ||
              (field.desc && field.desc.toLowerCase().includes('index')),
          });
        }
      }
    }
  } catch (e) {
    console.error('Failed to parse syscall fields JSON:', e.message);
  }
  return fields;
}

function mapType(t) {
  const typeMap = {
    string: 'string',
    uint64: 'uint64',
    uint32: 'uint32',
    int64: 'int64',
    int32: 'int32',
    bool: 'bool',
    ipaddr: 'ipaddr',
    ipnet: 'ipnet',
    reltime: 'reltime',
    abstime: 'abstime',
    port: 'port',
  };
  const base = String(t)
    .replace(/\s*\(.*\)/, '')
    .toLowerCase();
  return typeMap[base] || 'string';
}

function generateFieldsJSON(fields) {
  const uniqueFields = new Map();
  for (const f of fields) {
    if (!uniqueFields.has(f.name)) {
      uniqueFields.set(f.name, {
        name: f.name,
        type: f.type,
        category: f.category,
        description: f.description,
        isDynamic: f.isDynamic,
      });
    }
  }

  const sorted = Array.from(uniqueFields.values()).sort((a, b) => a.name.localeCompare(b.name));

  return JSON.stringify(sorted, null, 2);
}

function generatePluginsJSON(pluginFields) {
  const plugins = {};

  for (const f of pluginFields) {
    if (f.source !== 'k8s_audit' && f.source !== 'k8saudit' && f.source !== 'json') {
      if (!plugins[f.source]) {
        plugins[f.source] = [];
      }
      plugins[f.source].push({
        name: f.name,
        type: f.type,
        category: f.category,
        description: f.description,
        isDynamic: f.isDynamic,
      });
    }
  }

  // Sort fields within each plugin
  for (const source in plugins) {
    const unique = new Map();
    for (const f of plugins[source]) {
      if (!unique.has(f.name)) unique.set(f.name, f);
    }
    plugins[source] = Array.from(unique.values()).sort((a, b) => a.name.localeCompare(b.name));
  }

  return JSON.stringify(plugins, null, 2);
}

async function main() {
  console.log('🔄 Syncing Falco fields for Go implementation...\n');

  let syscallFields = [];
  let pluginFields = [];

  // Try to fetch syscall fields from libs
  try {
    console.log('📥 Fetching syscall fields from falcosecurity/libs...');
    const content = await fetch(SYSCALL_FIELDS_URL);
    syscallFields = parseSyscallFieldsJson(content);
    console.log(`   ✓ Found ${syscallFields.length} syscall fields\n`);
  } catch (error) {
    console.log(`   ⚠ Could not fetch syscall fields: ${error.message}`);
    console.log('   Using fallback syscall fields...\n');
    syscallFields = getFallbackSyscallFields();
  }

  // Fetch plugin fields
  for (const [source, config] of Object.entries(SOURCES)) {
    try {
      console.log(`📥 Fetching ${source} fields...`);
      const content = await fetch(config.url);
      const fields = config.parser(content, config.category);
      for (const f of fields) {
        f.source = config.category;
      }
      pluginFields = pluginFields.concat(fields);
      console.log(`   ✓ Found ${fields.length} fields\n`);
    } catch (error) {
      console.log(`   ⚠ Error fetching ${source}: ${error.message}\n`);
    }
  }

  // Generate JSON files
  const dataDir = path.join(__dirname, '..', '..', 'falco-lsp', 'internal', 'fields', 'data');

  // Generate syscall.json
  const syscallJSON = generateFieldsJSON(syscallFields);
  const syscallPath = path.join(dataDir, 'syscall.json');
  fs.writeFileSync(syscallPath, syscallJSON);
  console.log(`\n✅ Generated ${syscallPath}`);
  console.log(`   Syscall fields: ${syscallFields.length}`);

  // Generate k8saudit.json
  const k8sFields = pluginFields.filter(f => f.source === 'k8s_audit' || f.source === 'k8saudit');
  const k8sJSON = generateFieldsJSON(k8sFields);
  const k8sPath = path.join(dataDir, 'k8saudit.json');
  fs.writeFileSync(k8sPath, k8sJSON);
  console.log(`✅ Generated ${k8sPath}`);
  console.log(`   K8s Audit fields: ${k8sFields.length}`);

  // Generate plugins.json
  const pluginsJSON = generatePluginsJSON(pluginFields);
  const pluginsPath = path.join(dataDir, 'plugins.json');
  fs.writeFileSync(pluginsPath, pluginsJSON);
  const pluginCount = pluginFields.filter(
    f => f.source !== 'k8s_audit' && f.source !== 'k8saudit' && f.source !== 'json'
  ).length;
  console.log(`✅ Generated ${pluginsPath}`);
  console.log(`   Plugin fields: ${pluginCount}`);
}

function getFallbackSyscallFields() {
  // Complete syscall fields from Falco documentation
  return [
    // evt.* fields
    {
      name: 'evt.num',
      type: 'uint64',
      category: 'evt',
      description: 'Event number',
      isDynamic: false,
    },
    {
      name: 'evt.time',
      type: 'abstime',
      category: 'evt',
      description: 'Event timestamp',
      isDynamic: false,
    },
    {
      name: 'evt.type',
      type: 'string',
      category: 'evt',
      description: 'Event type',
      isDynamic: false,
    },
    {
      name: 'evt.dir',
      type: 'string',
      category: 'evt',
      description: 'Event direction',
      isDynamic: false,
    },
    {
      name: 'evt.args',
      type: 'string',
      category: 'evt',
      description: 'All event arguments',
      isDynamic: false,
    },
    {
      name: 'evt.arg',
      type: 'string',
      category: 'evt',
      description: 'Event argument by name',
      isDynamic: true,
    },
    {
      name: 'evt.res',
      type: 'string',
      category: 'evt',
      description: 'Event return value',
      isDynamic: false,
    },
    {
      name: 'evt.rawres',
      type: 'int64',
      category: 'evt',
      description: 'Event return value (raw)',
      isDynamic: false,
    },
    {
      name: 'evt.is_open_exec',
      type: 'bool',
      category: 'evt',
      description: 'Open for exec',
      isDynamic: false,
    },
    {
      name: 'evt.is_open_read',
      type: 'bool',
      category: 'evt',
      description: 'Open for read',
      isDynamic: false,
    },
    {
      name: 'evt.is_open_write',
      type: 'bool',
      category: 'evt',
      description: 'Open for write',
      isDynamic: false,
    },
    {
      name: 'evt.buffer',
      type: 'string',
      category: 'evt',
      description: 'Event buffer',
      isDynamic: false,
    },
    {
      name: 'evt.buflen',
      type: 'uint64',
      category: 'evt',
      description: 'Event buffer length',
      isDynamic: false,
    },
    {
      name: 'evt.hostname',
      type: 'string',
      category: 'evt',
      description: 'Hostname',
      isDynamic: false,
    },
    {
      name: 'evt.cpu',
      type: 'uint32',
      category: 'evt',
      description: 'CPU number',
      isDynamic: false,
    },
    // proc.* fields
    {
      name: 'proc.pid',
      type: 'int64',
      category: 'proc',
      description: 'Process ID',
      isDynamic: false,
    },
    {
      name: 'proc.name',
      type: 'string',
      category: 'proc',
      description: 'Process name',
      isDynamic: false,
    },
    {
      name: 'proc.exe',
      type: 'string',
      category: 'proc',
      description: 'Process executable path',
      isDynamic: false,
    },
    {
      name: 'proc.exepath',
      type: 'string',
      category: 'proc',
      description: 'Process executable path (resolved)',
      isDynamic: false,
    },
    {
      name: 'proc.cmdline',
      type: 'string',
      category: 'proc',
      description: 'Process command line',
      isDynamic: false,
    },
    {
      name: 'proc.args',
      type: 'string',
      category: 'proc',
      description: 'Process arguments',
      isDynamic: false,
    },
    {
      name: 'proc.cwd',
      type: 'string',
      category: 'proc',
      description: 'Process current working directory',
      isDynamic: false,
    },
    {
      name: 'proc.ppid',
      type: 'int64',
      category: 'proc',
      description: 'Parent process ID',
      isDynamic: false,
    },
    {
      name: 'proc.pname',
      type: 'string',
      category: 'proc',
      description: 'Parent process name',
      isDynamic: false,
    },
    {
      name: 'proc.pexe',
      type: 'string',
      category: 'proc',
      description: 'Parent process executable',
      isDynamic: false,
    },
    {
      name: 'proc.pcmdline',
      type: 'string',
      category: 'proc',
      description: 'Parent process command line',
      isDynamic: false,
    },
    {
      name: 'proc.aname',
      type: 'string',
      category: 'proc',
      description: 'Ancestor process name',
      isDynamic: true,
    },
    {
      name: 'proc.aexe',
      type: 'string',
      category: 'proc',
      description: 'Ancestor process executable',
      isDynamic: true,
    },
    {
      name: 'proc.apid',
      type: 'int64',
      category: 'proc',
      description: 'Ancestor process ID',
      isDynamic: true,
    },
    {
      name: 'proc.env',
      type: 'string',
      category: 'proc',
      description: 'Process environment',
      isDynamic: true,
    },
    {
      name: 'proc.duration',
      type: 'reltime',
      category: 'proc',
      description: 'Process duration',
      isDynamic: false,
    },
    {
      name: 'proc.sid',
      type: 'int64',
      category: 'proc',
      description: 'Session ID',
      isDynamic: false,
    },
    {
      name: 'proc.sname',
      type: 'string',
      category: 'proc',
      description: 'Session leader name',
      isDynamic: false,
    },
    {
      name: 'proc.tty',
      type: 'uint32',
      category: 'proc',
      description: 'Process TTY',
      isDynamic: false,
    },
    {
      name: 'proc.is_exe_upper_layer',
      type: 'bool',
      category: 'proc',
      description: 'Executable from upper layer',
      isDynamic: false,
    },
    {
      name: 'proc.is_exe_from_memfd',
      type: 'bool',
      category: 'proc',
      description: 'Executable from memfd',
      isDynamic: false,
    },
    {
      name: 'proc.is_vpgid_leader',
      type: 'bool',
      category: 'proc',
      description: 'Virtual process group leader',
      isDynamic: false,
    },
    {
      name: 'proc.vpid',
      type: 'int64',
      category: 'proc',
      description: 'Virtual PID',
      isDynamic: false,
    },
    {
      name: 'proc.pvpid',
      type: 'int64',
      category: 'proc',
      description: 'Parent virtual PID',
      isDynamic: false,
    },
    // fd.* fields
    {
      name: 'fd.num',
      type: 'int64',
      category: 'fd',
      description: 'File descriptor number',
      isDynamic: false,
    },
    {
      name: 'fd.name',
      type: 'string',
      category: 'fd',
      description: 'File descriptor name/path',
      isDynamic: false,
    },
    {
      name: 'fd.nameraw',
      type: 'string',
      category: 'fd',
      description: 'File descriptor name (raw)',
      isDynamic: false,
    },
    {
      name: 'fd.type',
      type: 'string',
      category: 'fd',
      description: 'File descriptor type',
      isDynamic: false,
    },
    {
      name: 'fd.typechar',
      type: 'string',
      category: 'fd',
      description: 'File descriptor type character',
      isDynamic: false,
    },
    {
      name: 'fd.directory',
      type: 'string',
      category: 'fd',
      description: 'Directory containing the file',
      isDynamic: false,
    },
    {
      name: 'fd.filename',
      type: 'string',
      category: 'fd',
      description: 'File name without path',
      isDynamic: false,
    },
    {
      name: 'fd.ip',
      type: 'ipaddr',
      category: 'fd',
      description: 'Remote IP address',
      isDynamic: false,
    },
    {
      name: 'fd.cip',
      type: 'ipaddr',
      category: 'fd',
      description: 'Client IP address',
      isDynamic: false,
    },
    {
      name: 'fd.sip',
      type: 'ipaddr',
      category: 'fd',
      description: 'Server IP address',
      isDynamic: false,
    },
    {
      name: 'fd.sip.name',
      type: 'string',
      category: 'fd',
      description: 'Server IP name',
      isDynamic: false,
    },
    {
      name: 'fd.cip.name',
      type: 'string',
      category: 'fd',
      description: 'Client IP name',
      isDynamic: false,
    },
    { name: 'fd.port', type: 'port', category: 'fd', description: 'Remote port', isDynamic: false },
    {
      name: 'fd.cport',
      type: 'port',
      category: 'fd',
      description: 'Client port',
      isDynamic: false,
    },
    {
      name: 'fd.sport',
      type: 'port',
      category: 'fd',
      description: 'Server port',
      isDynamic: false,
    },
    {
      name: 'fd.l4proto',
      type: 'string',
      category: 'fd',
      description: 'Layer 4 protocol',
      isDynamic: false,
    },
    { name: 'fd.net', type: 'ipnet', category: 'fd', description: 'Network', isDynamic: false },
    {
      name: 'fd.snet',
      type: 'ipnet',
      category: 'fd',
      description: 'Server network',
      isDynamic: false,
    },
    {
      name: 'fd.cnet',
      type: 'ipnet',
      category: 'fd',
      description: 'Client network',
      isDynamic: false,
    },
    {
      name: 'fd.connected',
      type: 'bool',
      category: 'fd',
      description: 'FD is connected',
      isDynamic: false,
    },
    {
      name: 'fd.sockfamily',
      type: 'string',
      category: 'fd',
      description: 'Socket family (e.g., ip, unix)',
      isDynamic: false,
    },
    {
      name: 'fd.rnet',
      type: 'string',
      category: 'fd',
      description: 'Remote network',
      isDynamic: false,
    },
    {
      name: 'fd.name_changed',
      type: 'bool',
      category: 'fd',
      description: 'FD name changed',
      isDynamic: false,
    },
    {
      name: 'fd.dev',
      type: 'uint32',
      category: 'fd',
      description: 'Device number',
      isDynamic: false,
    },
    {
      name: 'fd.ino',
      type: 'uint64',
      category: 'fd',
      description: 'Inode number',
      isDynamic: false,
    },
    // container.* fields
    {
      name: 'container.id',
      type: 'string',
      category: 'container',
      description: 'Container ID',
      isDynamic: false,
    },
    {
      name: 'container.name',
      type: 'string',
      category: 'container',
      description: 'Container name',
      isDynamic: false,
    },
    {
      name: 'container.image',
      type: 'string',
      category: 'container',
      description: 'Container image',
      isDynamic: false,
    },
    {
      name: 'container.image.id',
      type: 'string',
      category: 'container',
      description: 'Container image ID',
      isDynamic: false,
    },
    {
      name: 'container.image.repository',
      type: 'string',
      category: 'container',
      description: 'Container image repository',
      isDynamic: false,
    },
    {
      name: 'container.image.tag',
      type: 'string',
      category: 'container',
      description: 'Container image tag',
      isDynamic: false,
    },
    {
      name: 'container.image.digest',
      type: 'string',
      category: 'container',
      description: 'Container image digest',
      isDynamic: false,
    },
    {
      name: 'container.privileged',
      type: 'bool',
      category: 'container',
      description: 'Container is privileged',
      isDynamic: false,
    },
    {
      name: 'container.mounts',
      type: 'string',
      category: 'container',
      description: 'Container mounts',
      isDynamic: false,
    },
    {
      name: 'container.mount',
      type: 'string',
      category: 'container',
      description: 'Container mount info',
      isDynamic: true,
    },
    {
      name: 'container.mount.source',
      type: 'string',
      category: 'container',
      description: 'Mount source',
      isDynamic: true,
    },
    {
      name: 'container.mount.dest',
      type: 'string',
      category: 'container',
      description: 'Mount destination',
      isDynamic: true,
    },
    {
      name: 'container.mount.mode',
      type: 'string',
      category: 'container',
      description: 'Mount mode',
      isDynamic: true,
    },
    {
      name: 'container.mount.rdwr',
      type: 'string',
      category: 'container',
      description: 'Mount read/write mode',
      isDynamic: true,
    },
    {
      name: 'container.mount.propagation',
      type: 'string',
      category: 'container',
      description: 'Mount propagation',
      isDynamic: true,
    },
    {
      name: 'container.ip',
      type: 'ipaddr',
      category: 'container',
      description: 'Container IP',
      isDynamic: false,
    },
    // user.* and group.* fields
    {
      name: 'user.uid',
      type: 'uint32',
      category: 'user',
      description: 'User ID',
      isDynamic: false,
    },
    {
      name: 'user.name',
      type: 'string',
      category: 'user',
      description: 'User name',
      isDynamic: false,
    },
    {
      name: 'user.loginuid',
      type: 'int64',
      category: 'user',
      description: 'Login UID',
      isDynamic: false,
    },
    {
      name: 'user.loginname',
      type: 'string',
      category: 'user',
      description: 'Login user name',
      isDynamic: false,
    },
    {
      name: 'group.gid',
      type: 'uint32',
      category: 'group',
      description: 'Group ID',
      isDynamic: false,
    },
    {
      name: 'group.name',
      type: 'string',
      category: 'group',
      description: 'Group name',
      isDynamic: false,
    },
    // thread.* fields
    {
      name: 'thread.tid',
      type: 'int64',
      category: 'thread',
      description: 'Thread ID',
      isDynamic: false,
    },
    {
      name: 'thread.vtid',
      type: 'int64',
      category: 'thread',
      description: 'Virtual thread ID',
      isDynamic: false,
    },
    {
      name: 'thread.nametid',
      type: 'string',
      category: 'thread',
      description: 'Thread name and TID',
      isDynamic: false,
    },
    {
      name: 'thread.ismain',
      type: 'bool',
      category: 'thread',
      description: 'Is main thread',
      isDynamic: false,
    },
    {
      name: 'thread.exectime',
      type: 'reltime',
      category: 'thread',
      description: 'Thread execution time',
      isDynamic: false,
    },
    {
      name: 'thread.totexectime',
      type: 'reltime',
      category: 'thread',
      description: 'Thread total execution time',
      isDynamic: false,
    },
    {
      name: 'thread.cgroups',
      type: 'string',
      category: 'thread',
      description: 'Thread cgroups',
      isDynamic: false,
    },
    {
      name: 'thread.cap_permitted',
      type: 'string',
      category: 'thread',
      description: 'Thread permitted capabilities',
      isDynamic: false,
    },
    {
      name: 'thread.cap_effective',
      type: 'string',
      category: 'thread',
      description: 'Thread effective capabilities',
      isDynamic: false,
    },
    {
      name: 'thread.cap_inheritable',
      type: 'string',
      category: 'thread',
      description: 'Thread inheritable capabilities',
      isDynamic: false,
    },
    // k8s.* fields
    {
      name: 'k8s.pod.name',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes pod name',
      isDynamic: false,
    },
    {
      name: 'k8s.pod.id',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes pod ID',
      isDynamic: false,
    },
    {
      name: 'k8s.pod.label',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes pod label',
      isDynamic: true,
    },
    {
      name: 'k8s.pod.labels',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes pod labels',
      isDynamic: false,
    },
    {
      name: 'k8s.pod.ip',
      type: 'ipaddr',
      category: 'k8s',
      description: 'Kubernetes pod IP',
      isDynamic: false,
    },
    {
      name: 'k8s.pod.cni.json',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes pod CNI JSON',
      isDynamic: false,
    },
    {
      name: 'k8s.ns.name',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes namespace',
      isDynamic: false,
    },
    {
      name: 'k8s.rc.name',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes replication controller name',
      isDynamic: false,
    },
    {
      name: 'k8s.svc.name',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes service name',
      isDynamic: false,
    },
    {
      name: 'k8s.rs.name',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes replica set name',
      isDynamic: false,
    },
    {
      name: 'k8s.deployment.name',
      type: 'string',
      category: 'k8s',
      description: 'Kubernetes deployment name',
      isDynamic: false,
    },
    // fs.* fields
    {
      name: 'fs.path.name',
      type: 'string',
      category: 'fs',
      description: 'File system path name',
      isDynamic: false,
    },
    {
      name: 'fs.path.nameraw',
      type: 'string',
      category: 'fs',
      description: 'File system path name (raw)',
      isDynamic: false,
    },
    {
      name: 'fs.path.source',
      type: 'string',
      category: 'fs',
      description: 'File system path source',
      isDynamic: false,
    },
    {
      name: 'fs.path.sourceraw',
      type: 'string',
      category: 'fs',
      description: 'File system path source (raw)',
      isDynamic: false,
    },
    {
      name: 'fs.path.target',
      type: 'string',
      category: 'fs',
      description: 'File system path target',
      isDynamic: false,
    },
    {
      name: 'fs.path.targetraw',
      type: 'string',
      category: 'fs',
      description: 'File system path target (raw)',
      isDynamic: false,
    },
    // syscall.* fields
    {
      name: 'syscall.type',
      type: 'string',
      category: 'syscall',
      description: 'Syscall type',
      isDynamic: false,
    },
  ];
}

main()
  .then(() => process.exit(0))
  .catch(e => {
    console.error(e);
    process.exit(1);
  });
