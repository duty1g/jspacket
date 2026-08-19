import { build } from 'esbuild';
import { readdirSync, readFileSync, writeFileSync, chmodSync, copyFileSync } from 'fs';
import { join } from 'path';

const tools = readdirSync('src')
  .filter(f => f.endsWith('.ts'))
  .map(f => f.replace('.ts', ''));

await Promise.all(tools.map(tool =>
  build({
    entryPoints: [`src/${tool}.ts`],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile: `dist/${tool}.mjs`,
    packages: 'bundle',
    banner: { js: '#!/usr/bin/env node' },
    logLevel: 'warning',
  })
));

for (const tool of tools) {
  const p = join('dist', `${tool}.mjs`);
  let code = readFileSync(p, 'utf8');
  // esbuild banner + source shebang can produce duplicates — keep only the first
  const lines = code.split('\n');
  while (lines.length > 1 && lines[1].startsWith('#!')) lines.splice(1, 1);
  writeFileSync(p, lines.join('\n'));
  chmodSync(p, 0o755);
}

copyFileSync(join('..', 'README.md'), 'README.md');
console.log(`Built ${tools.length} tools → dist/`);
