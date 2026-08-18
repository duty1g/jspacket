import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

let _version: string;
try {
  const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  _version = pkg.version ?? '?';
} catch {
  _version = '?';
}

export const version = _version;

export const BANNER = `Impacket-JS v${version} - TypeScript port of Impacket\n`;

export const DEPRECATION_WARNING_BANNER = [
  '===============================================================================',
  '  Warning: This functionality will be deprecated in the next Impacket version  ',
  '===============================================================================',
].join('\n') + '\n';

export function getInstallationPath(): string {
  try {
    return `Impacket-JS Library Installation Path: ${dirname(fileURLToPath(import.meta.url))}`;
  } catch {
    return 'Impacket-JS Library Installation Path: unknown';
  }
}
