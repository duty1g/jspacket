#!/usr/bin/env node
/**
 * Impacket - Collection of TypeScript classes for working with network protocols.
 *
 * Remote registry manipulation tool. The idea is to provide similar
 * functionality as the REG.EXE Windows utility.
 *
 * e.g:
 *   reg Administrator:password@target query -keyName HKLM\\Software\\Microsoft\\WBEM -s
 *   reg Administrator:password@target add -keyName HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa -v DisableRestrictedAdmin -vt REG_DWORD -vd 1
 *   reg Administrator:password@target delete -keyName HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa -v DisableRestrictedAdmin
 *
 * Author (original impacket):
 *   Manuel Porto (@manuporto)
 *   Alberto Solino (@agsolino)
 *   TypeScript port.
 *
 * Reference for: [MS-RRP]
 */

import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error,
  debug,
  warning,
  critical,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import { SMBConnection, SessionError } from '@impacket/smb-connection';
import { RemoteOperations } from '@impacket/examples';
import {
  hOpenLocalMachine,
  hOpenCurrentUser,
  hOpenUsers,
  hOpenClassesRoot,
  hBaseRegOpenKey,
  hBaseRegQueryValue,
  hBaseRegEnumValue,
  hBaseRegEnumKey,
  hBaseRegSetValue,
  hBaseRegCreateKey,
  hBaseRegDeleteKey,
  hBaseRegDeleteValue,
  hBaseRegSaveKey,
  RRP_DCERPCSessionError,
  DCERPCException,
  MAXIMUM_ALLOWED,
  READ_CONTROL,
  KEY_READ,
  KEY_ENUMERATE_SUB_KEYS,
  KEY_QUERY_VALUE,
  KEY_SET_VALUE,
  KEY_CREATE_SUB_KEY,
  REG_OPTION_BACKUP_RESTORE,
  REG_OPTION_OPEN_LINK,
  REG_NONE,
  REG_SZ,
  REG_EXPAND_SZ,
  REG_BINARY,
  REG_DWORD,
  REG_DWORD_BIG_ENDIAN,
  REG_DWORD_LITTLE_ENDIAN,
  REG_LINK,
  REG_MULTI_SZ,
  REG_QWORD,
  REG_QWORD_LITTLE_ENDIAN,
  NULL,
} from '@impacket/dcerpc';
import { ERROR_NO_MORE_ITEMS } from '@impacket/system-errors';
import { hexdump } from '@impacket/structure';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REG_VALUES: Record<number, string> = {
  0: 'REG_NONE',
  1: 'REG_SZ',
  2: 'REG_EXPAND_SZ',
  3: 'REG_BINARY',
  4: 'REG_DWORD',
  5: 'REG_DWORD_BIG_ENDIAN',
  6: 'REG_LINK',
  7: 'REG_MULTI_SZ',
  11: 'REG_QWORD',
};

// Maps a "REG_*" type name (as passed via -vt) to its numeric type. Mirrors
// impacket's getattr(rrp, self.__options.vt).
const REG_TYPE_NAMES: Record<string, number> = {
  REG_NONE,
  REG_SZ,
  REG_EXPAND_SZ,
  REG_BINARY,
  REG_DWORD,
  REG_DWORD_BIG_ENDIAN,
  REG_DWORD_LITTLE_ENDIAN,
  REG_LINK,
  REG_MULTI_SZ,
  REG_QWORD,
  REG_QWORD_LITTLE_ENDIAN,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// impacket.winregistry.format_multi_sz
function formatMultiSz(valueData: unknown, separator = '\n\t\t'): string {
  if (typeof valueData === 'number' || typeof valueData === 'bigint') {
    return 'NULL';
  }
  let s: string;
  if (Buffer.isBuffer(valueData)) {
    s = valueData.toString('utf16le');
  } else {
    s = String(valueData);
  }
  // rstrip('\x00')
  s = s.replace(/\x00+$/, '');
  return s.replace(/\x00/g, separator);
}

// Dereference an NDR pointer/scalar field to its underlying value, matching the
// digging pattern used inside rrp's hBaseRegQueryValue helper.
function derefField(field: any): any {
  const outer = field?.fields?.['Data'];
  if (outer && typeof outer === 'object' && outer.fields?.['Data'] != null) {
    return outer.fields['Data'];
  }
  return outer;
}

function toBuffer(data: any): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.from(data as number[]);
  return Buffer.alloc(0);
}

// ---------------------------------------------------------------------------
// RegHandler
// ---------------------------------------------------------------------------

interface RegOptions {
  action: string;
  keyName?: string;
  v?: string;
  ve?: boolean;
  s?: boolean;
  vt?: string;
  vd?: string[];
  va?: boolean;
  persistent?: boolean;
  outputPath?: string;
  port: number;
}

class RegHandler {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash = '';
  private nthash = '';
  private aesKey: string | null;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private options: RegOptions;
  private action: string;
  private smbConnection: SMBConnection | null = null;
  private remoteOps: RemoteOperations | null = null;

  constructor(
    username: string,
    password: string,
    domain: string,
    options: RegOptions,
    opts: {
      hashes?: string | null;
      aesKey?: string | null;
      doKerberos?: boolean;
      kdcHost?: string | null;
    },
  ) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.options = options;
    this.action = options.action.toUpperCase();
    this.aesKey = opts.aesKey ?? null;
    this.doKerberos = opts.doKerberos ?? false;
    this.kdcHost = opts.kdcHost ?? null;
    if (opts.hashes) {
      const parts = opts.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  private async connect(remoteName: string, remoteHost: string): Promise<void> {
    this.smbConnection = new SMBConnection(remoteName, remoteHost, {
      sessPort: this.options.port,
    });
    await this.smbConnection.negotiateSession();
    if (this.doKerberos) {
      await this.smbConnection.kerberosLogin(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey ?? '',
        this.kdcHost,
      );
    } else {
      await this.smbConnection.login(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
      );
    }
  }

  async run(remoteName: string, remoteHost: string): Promise<void> {
    await this.connect(remoteName, remoteHost);
    this.remoteOps = new RemoteOperations(this.smbConnection, this.doKerberos, this.kdcHost);

    try {
      await this.remoteOps.enableRegistry();
    } catch (e) {
      debug(String(e));
      warning('Cannot check RemoteRegistry status. Triggering start trough named pipe...');
      await this.triggerWinReg();
      // connectWinReg is private on RemoteOperations; call it dynamically.
      await (this.remoteOps as any).connectWinReg();
    }

    try {
      const dce = this.remoteOps.getRRP();
      if (dce === null) {
        throw new Error('Could not connect to the remote registry');
      }

      if (this.action === 'QUERY') {
        await this.query(dce, this.options.keyName!);
      } else if (this.action === 'ADD') {
        await this.add(dce, this.options.keyName!, this.options.persistent === true);
      } else if (this.action === 'DELETE') {
        await this.delete(dce, this.options.keyName!);
      } else if (this.action === 'SAVE') {
        await this.save(dce, this.options.keyName!);
      } else if (this.action === 'BACKUP') {
        for (const hive of ['HKLM\\SAM', 'HKLM\\SYSTEM', 'HKLM\\SECURITY']) {
          await this.save(dce, hive);
        }
      } else {
        error(`Method ${this.action} not implemented yet!`);
      }
    } catch (e) {
      critical(String(e));
    } finally {
      if (this.remoteOps) {
        await this.remoteOps.finish();
      }
    }
  }

  private async triggerWinReg(): Promise<void> {
    // original idea from https://twitter.com/splinter_code/status/1715876413474025704
    const tid = await this.smbConnection!.connectTree('IPC$');
    try {
      await this.smbConnection!.openFile(
        tid,
        '\\winreg',
        0x12019f, // desiredAccess
        undefined, // shareMode (default)
        0x40, // creationOption
        undefined, // creationDisposition (default)
        0x80, // fileAttributes
      );
    } catch (e) {
      if (!(e instanceof SessionError)) {
        // STATUS_PIPE_NOT_AVAILABLE error is expected
        // fall through for other, unexpected errors is fine (ignored)
      }
    }
    // give remote registry time to start
    await sleep(1000);
  }

  private async save(dce: any, keyName: string): Promise<void> {
    const [hRootKey, subKey] = await this.stripRootKey(dce, keyName);
    const outputFileName = `${this.options.outputPath}\\${subKey}.save`;
    debug(
      `Dumping ${keyName}, be patient it can take a while for large hives (e.g. HKLM\\SYSTEM)`,
    );
    try {
      const ans2 = (await hBaseRegOpenKey(
        dce,
        hRootKey,
        subKey,
        REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK,
        KEY_READ,
      )) as any;
      await hBaseRegSaveKey(dce, ans2.get('phkResult'), outputFileName);
      info(`Saved ${keyName} to ${outputFileName}`);
    } catch (e) {
      error(`Couldn't save ${keyName}: ${e}`);
    }
  }

  private async query(dce: any, keyName: string): Promise<void> {
    const [hRootKey, subKey] = await this.stripRootKey(dce, keyName);

    const ans2 = (await hBaseRegOpenKey(
      dce,
      hRootKey,
      subKey,
      undefined,
      MAXIMUM_ALLOWED | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
    )) as any;
    const phkResult = ans2.get('phkResult');

    if (this.options.v) {
      console.log(keyName);
      const [vType, vData] = await hBaseRegQueryValue(dce, phkResult, this.options.v);
      this.printQueryValue(this.options.v, vType, vData);
    } else if (this.options.ve) {
      console.log(keyName);
      const [vType, vData] = await hBaseRegQueryValue(dce, phkResult, '');
      this.printQueryValue('(Default)', vType, vData);
    } else if (this.options.s) {
      await this.printAllSubkeysAndEntries(dce, subKey + '\\', phkResult);
    } else {
      console.log(keyName);
      await this.printKeyValues(dce, phkResult);
      let i = 0;
      while (true) {
        try {
          const key = (await hBaseRegEnumKey(dce, phkResult, i)) as any;
          console.log(keyName + '\\' + String(key.get('lpNameOut')).slice(0, -1));
          i += 1;
        } catch {
          break;
        }
      }
    }
  }

  private async add(dce: any, keyName: string, persistent: boolean): Promise<void> {
    const [hRootKey, subKey] = await this.stripRootKey(dce, keyName);

    // READ_CONTROL | KEY_SET_VALUE | KEY_CREATE_SUB_KEY == KEY_WRITE (0x20006)
    if (this.options.v === undefined) {
      // Try to create subkey
      const subKeyCreate = subKey;
      const parentSubKey = subKey.split('\\').slice(0, -1).join('\\');

      await hBaseRegOpenKey(
        dce,
        hRootKey,
        parentSubKey,
        undefined,
        READ_CONTROL | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
      );

      // dwOption 0 = Persistent, dwOption 1 = Volatile
      let dwOption = 0x00000001;
      if (persistent) {
        dwOption = 0x00000000;
      } else {
        console.log('[!] The created key is volatile and will not remain after a reboot. ');
      }

      const ans3 = (await hBaseRegCreateKey(
        dce,
        hRootKey,
        subKeyCreate,
        NULL,
        dwOption,
        READ_CONTROL | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
      )) as any;

      if (ans3.get('ErrorCode') === 0) {
        console.log(`Successfully set subkey ${keyName}`);
      } else {
        console.log(
          `Error 0x${(ans3.get('ErrorCode') >>> 0).toString(16).padStart(8, '0')} while creating subkey ${keyName}`,
        );
      }
    } else {
      // Try to set value of key
      const ans2 = (await hBaseRegOpenKey(
        dce,
        hRootKey,
        subKey,
        undefined,
        READ_CONTROL | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
      )) as any;

      const vt = this.options.vt ?? 'REG_SZ';
      const dwType = REG_TYPE_NAMES[vt];
      if (dwType === undefined || !vt.startsWith('REG_')) {
        throw new Error(`Error parsing value type ${vt}`);
      }

      const vdList = this.options.vd ?? [];
      let valueData: number | string | Buffer;
      let valueDataToPrint: string;

      if (dwType === REG_MULTI_SZ) {
        const vd = vdList.join('\0');
        // REG_MULTI_SZ ends with 2 null-bytes
        valueData = vd + '\0\0';
        valueDataToPrint = formatMultiSz(valueData, '\n\t\t');
      } else {
        const vd = vdList.length > 0 ? vdList[0]! : '';
        if (
          dwType === REG_DWORD ||
          dwType === REG_DWORD_BIG_ENDIAN ||
          dwType === REG_DWORD_LITTLE_ENDIAN ||
          dwType === REG_QWORD ||
          dwType === REG_QWORD_LITTLE_ENDIAN
        ) {
          valueData = parseInt(vd, 10);
          valueDataToPrint = String(valueData);
        } else if (dwType === REG_BINARY) {
          let binValueLen = vd.length;
          binValueLen += binValueLen & 1;
          valueData = Buffer.from(vd.padEnd(binValueLen, '0'), 'hex');
          valueDataToPrint = valueData.toString('hex');
        } else {
          // Add a NULL byte as terminator for non-binary values
          const terminated = vd + '\0';
          // REG_SZ / REG_EXPAND_SZ are packed to utf-16le downstream; REG_NONE /
          // REG_LINK are packed as raw bytes, so hand them a Buffer to avoid the
          // string-as-bytes path.
          if (dwType === REG_SZ || dwType === REG_EXPAND_SZ) {
            valueData = terminated;
          } else {
            valueData = Buffer.from(terminated, 'utf16le');
          }
          valueDataToPrint = terminated;
        }
      }

      const ans3 = (await hBaseRegSetValue(
        dce,
        ans2.get('phkResult'),
        this.options.v,
        dwType,
        valueData,
      )) as any;

      if (ans3.get('ErrorCode') === 0) {
        console.log(
          `Successfully set\n\tkey\t${keyName}\\${this.options.v}\n\ttype\t${vt}\n\tvalue\t${valueDataToPrint}`,
        );
      } else {
        console.log(
          `Error 0x${(ans3.get('ErrorCode') >>> 0).toString(16).padStart(8, '0')} while setting\n\tkey\t${keyName}\\${this.options.v}\n\ttype\t${vt}\n\tvalue\t${valueDataToPrint}`,
        );
      }
    }
  }

  private async delete(dce: any, keyName: string): Promise<void> {
    const [hRootKey, subKey] = await this.stripRootKey(dce, keyName);

    if (this.options.v === undefined && !this.options.va && !this.options.ve) {
      // Try to delete subkey
      const subKeyDelete = subKey;
      const parentSubKey = subKey.split('\\').slice(0, -1).join('\\');

      await hBaseRegOpenKey(
        dce,
        hRootKey,
        parentSubKey,
        undefined,
        READ_CONTROL | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
      );

      let ans3: any;
      try {
        ans3 = await hBaseRegDeleteKey(dce, hRootKey, subKeyDelete);
      } catch (e) {
        if (e instanceof DCERPCException && (e as any).error_code === 5) {
          console.log(
            `Cannot delete key ${keyName}. Possibly it contains subkeys or insufficient privileges`,
          );
          return;
        } else if (e instanceof DCERPCException) {
          throw e;
        } else {
          error('Unhandled exception while hBaseRegDeleteKey');
          return;
        }
      }

      if (ans3.get('ErrorCode') === 0) {
        console.log(`Successfully deleted subkey ${keyName}`);
      } else {
        console.log(
          `Error 0x${(ans3.get('ErrorCode') >>> 0).toString(16).padStart(8, '0')} while deleting subkey ${keyName}`,
        );
      }
    } else if (this.options.v) {
      // Delete single value
      const ans2 = (await hBaseRegOpenKey(
        dce,
        hRootKey,
        subKey,
        undefined,
        READ_CONTROL | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
      )) as any;

      const ans3 = (await hBaseRegDeleteValue(dce, ans2.get('phkResult'), this.options.v)) as any;
      if (ans3.get('ErrorCode') === 0) {
        console.log(`Successfully deleted key ${keyName}\\${this.options.v}`);
      } else {
        console.log(
          `Error 0x${(ans3.get('ErrorCode') >>> 0).toString(16).padStart(8, '0')} while deleting key ${keyName}\\${this.options.v}`,
        );
      }
    } else if (this.options.ve) {
      const ans2 = (await hBaseRegOpenKey(
        dce,
        hRootKey,
        subKey,
        undefined,
        READ_CONTROL | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
      )) as any;

      const ans3 = (await hBaseRegDeleteValue(dce, ans2.get('phkResult'), '')) as any;
      if (ans3.get('ErrorCode') === 0) {
        console.log(`Successfully deleted value ${keyName}\\Default`);
      } else {
        console.log(
          `Error 0x${(ans3.get('ErrorCode') >>> 0).toString(16).padStart(8, '0')} while deleting value ${keyName}\\${this.options.v}`,
        );
      }
    } else if (this.options.va) {
      const ans2 = (await hBaseRegOpenKey(
        dce,
        hRootKey,
        subKey,
        undefined,
        MAXIMUM_ALLOWED | KEY_ENUMERATE_SUB_KEYS,
      )) as any;

      let i = 0;
      const allSubKeys: string[] = [];
      while (true) {
        try {
          const ans3 = (await hBaseRegEnumValue(dce, ans2.get('phkResult'), i)) as any;
          const lpValueName = String(ans3.get('lpValueNameOut')).slice(0, -1);
          allSubKeys.push(lpValueName);
          i += 1;
        } catch (e) {
          if (
            e instanceof RRP_DCERPCSessionError &&
            (e as RRP_DCERPCSessionError).getErrorCode() === ERROR_NO_MORE_ITEMS
          ) {
            break;
          }
          throw e;
        }
      }

      const ans4 = (await hBaseRegOpenKey(
        dce,
        hRootKey,
        subKey,
        undefined,
        MAXIMUM_ALLOWED | KEY_ENUMERATE_SUB_KEYS,
      )) as any;
      for (const valueName of allSubKeys) {
        try {
          const ans5 = (await hBaseRegDeleteValue(dce, ans4.get('phkResult'), valueName)) as any;
          if (ans5.get('ErrorCode') === 0) {
            console.log(`Successfully deleted value ${keyName}\\${valueName}`);
          } else {
            console.log(
              `Error 0x${(ans5.get('ErrorCode') >>> 0).toString(16).padStart(8, '0')} in deletion of value ${keyName}\\${valueName}`,
            );
          }
        } catch (e) {
          console.log(`Unhandled error ${e} in deletion of value ${keyName}\\${valueName}`);
        }
      }
    }
  }

  private async stripRootKey(dce: any, keyName: string): Promise<[any, string]> {
    let rootKey: string;
    let subKey: string;
    try {
      const parts = keyName.split('\\');
      rootKey = parts[0]!;
      subKey = parts.slice(1).join('\\');
    } catch {
      throw new Error(`Error parsing keyName ${keyName}`);
    }
    let ans: any;
    const ru = rootKey.toUpperCase();
    if (ru === 'HKLM') {
      ans = await hOpenLocalMachine(dce);
    } else if (ru === 'HKCU') {
      ans = await hOpenCurrentUser(dce);
    } else if (ru === 'HKU') {
      ans = await hOpenUsers(dce);
    } else if (ru === 'HKCR') {
      ans = await hOpenClassesRoot(dce);
    } else {
      throw new Error(`Invalid root key ${rootKey} `);
    }
    return [ans.get('phKey'), subKey];
  }

  private async printKeyValues(dce: any, keyHandler: any): Promise<void> {
    let i = 0;
    while (true) {
      try {
        const ans4 = (await hBaseRegEnumValue(dce, keyHandler, i)) as any;
        let lpValueName = String(ans4.get('lpValueNameOut')).slice(0, -1);
        if (lpValueName.length === 0) {
          lpValueName = '(Default)';
        }
        const lpType = derefField(ans4.fields['lpType']) as number;
        const lpData = toBuffer(derefField(ans4.fields['lpData']));
        const typeName = REG_VALUES[lpType] ?? 'KEY_NOT_FOUND';
        process.stdout.write('\t' + lpValueName + '\t' + typeName + '\t ');
        const separator = '\n\t' + ' '.repeat(lpValueName.length) + '\t' + ' '.repeat(typeName.length) + '\t ';
        this.parseLpData(lpType, lpData, separator);
        i += 1;
      } catch (e: any) {
        if (
          (e instanceof RRP_DCERPCSessionError || e instanceof DCERPCException) &&
          (e.getErrorCode?.() === ERROR_NO_MORE_ITEMS || e.error_code === ERROR_NO_MORE_ITEMS)
        ) {
          break;
        }
        throw e;
      }
    }
  }

  private async printAllSubkeysAndEntries(
    dce: any,
    keyName: string,
    keyHandler: any,
  ): Promise<void> {
    let index = 0;
    while (true) {
      let subkey: any;
      try {
        subkey = (await hBaseRegEnumKey(dce, keyHandler, index)) as any;
        index += 1;
        const ans = (await hBaseRegOpenKey(
          dce,
          keyHandler,
          String(subkey.get('lpNameOut')),
          undefined,
          MAXIMUM_ALLOWED | KEY_ENUMERATE_SUB_KEYS,
        )) as any;
        const newKeyName = keyName + String(subkey.get('lpNameOut')).slice(0, -1) + '\\';
        console.log(newKeyName);
        await this.printKeyValues(dce, ans.get('phkResult'));
        await this.printAllSubkeysAndEntries(dce, newKeyName, ans.get('phkResult'));
      } catch (e) {
        if (
          e instanceof RRP_DCERPCSessionError &&
          (e as RRP_DCERPCSessionError).getErrorCode() === ERROR_NO_MORE_ITEMS
        ) {
          break;
        }
        if (e instanceof DCERPCException) {
          const msg = String(e);
          if (msg.includes('access_denied')) {
            error(
              `Cannot access subkey ${subkey ? String(subkey.get('lpNameOut')).slice(0, -1) : ''}, bypassing it`,
            );
            continue;
          } else if (msg.includes('rpc_x_bad_stub_data')) {
            error(
              `Fault call, cannot retrieve value for ${subkey ? String(subkey.get('lpNameOut')).slice(0, -1) : ''}, bypassing it`,
            );
            return;
          }
          throw e;
        }
        throw e;
      }
    }
  }

  private formatQueryValue(valueType: number, valueData: unknown, multiSzSeparator: string): string {
    if (valueType === REG_MULTI_SZ) {
      return formatMultiSz(valueData, multiSzSeparator);
    }
    return String(valueData);
  }

  private printQueryValue(valueName: string, valueType: number, valueData: unknown): void {
    const valueTypeName = REG_VALUES[valueType] ?? 'KEY_NOT_FOUND';
    const separator = '\n\t' + ' '.repeat(valueName.length) + '\t' + ' '.repeat(valueTypeName.length) + '\t ';
    console.log(
      '\t' + valueName + '\t' + valueTypeName + '\t ' + this.formatQueryValue(valueType, valueData, separator),
    );
  }

  // impacket RegHandler.__parse_lp_data -- prints the decoded value.
  private parseLpData(valueType: number, valueData: Buffer, multiSzSeparator = '\n\t\t'): void {
    try {
      if (valueType === REG_SZ || valueType === REG_EXPAND_SZ) {
        if (valueData.length === 0) {
          console.log('NULL');
        } else {
          console.log(valueData.toString('utf16le').slice(0, -1));
        }
      } else if (valueType === REG_BINARY) {
        console.log('');
        process.stdout.write(hexdump(valueData, '\t'));
      } else if (valueType === REG_DWORD) {
        console.log('0x' + valueData.readUInt32LE(0).toString(16));
      } else if (valueType === REG_QWORD) {
        console.log('0x' + valueData.readBigUInt64LE(0).toString(16));
      } else if (valueType === REG_NONE) {
        if (valueData.length > 1) {
          console.log('');
          process.stdout.write(hexdump(valueData, '\t'));
        } else {
          console.log(' NULL');
        }
      } else if (valueType === REG_MULTI_SZ) {
        console.log(formatMultiSz(valueData, multiSzSeparator));
      } else {
        console.log(`Unknown Type 0x${valueType.toString(16)}!`);
        process.stdout.write(hexdump(valueData));
      }
    } catch (e) {
      debug(`Exception thrown when printing reg value ${e}`);
      console.log('Invalid data');
    }
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Windows Register manipulation script.

usage: reg [-h] [-debug] [-ts] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
           [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address]
           [-port [{139,445}]]
           target {query,add,delete,save,backup} ...

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  {query,add,delete,save,backup}
                        actions

query options:
  -keyName KEYNAME      Full path of the subkey (must include a valid root key:
                        HKLM, HKU, HKCU, HKCR)
  -v VALUENAME          Registry value name to query (all if omitted)
  -ve                   Query for the default / empty value name
  -s                    Query all subkeys and value names recursively

add options:
  -keyName KEYNAME      Full path of the subkey
  -v VALUENAME          Registry value name to set ("" for the (Default) value)
  -vt VALUETYPE         Registry value type (default REG_SZ)
  -vd VALUEDATA         Registry value data (repeat for each REG_MULTI_SZ line)
  --persistent          Create a persistent (non-volatile) key

delete options:
  -keyName KEYNAME      Full path of the subkey
  -v VALUENAME          Registry value name to delete
  -va                   Delete all values under this key
  -ve                   Delete the value of empty value name (Default)

save/backup options:
  -keyName KEYNAME      (save) Full path of the subkey
  -o \\\\192.168.0.2\\share  Output UNC path the target must export saves to

authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key to use for Kerberos Authentication

connection:
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port {139,445}       Destination port to connect to SMB Server`);
}

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      options: {
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        keyName: { type: 'string' },
        v: { type: 'string' },
        ve: { type: 'boolean', default: false },
        s: { type: 'boolean', default: false },
        vt: { type: 'string', default: 'REG_SZ' },
        vd: { type: 'string', multiple: true },
        va: { type: 'boolean', default: false },
        persistent: { type: 'boolean', default: false },
        o: { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: true,
      strict: true,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    printUsage();
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const target = positionals[0]!;
  const action = positionals[1];

  const validActions = ['query', 'add', 'delete', 'save', 'backup'];
  if (!action || !validActions.includes(action)) {
    error(`Missing or invalid action. Valid actions: ${validActions.join(', ')}`);
    process.exit(1);
  }

  // Required-argument checks mirroring argparse's per-subparser requirements.
  if ((action === 'query' || action === 'add' || action === 'delete' || action === 'save') && !values.keyName) {
    error(`the following arguments are required: -keyName`);
    process.exit(1);
  }
  if ((action === 'save' || action === 'backup') && !values.o) {
    error(`the following arguments are required: -o`);
    process.exit(1);
  }

  const [domain, username, passwordFromTarget, remoteName] = parseTarget(target);
  const resolvedDomain = domain || '';

  const targetIp = values['target-ip'] ?? remoteName;

  let doKerberos = values.k ?? false;
  if (values.aesKey) {
    doKerberos = true;
  }

  let password = passwordFromTarget;
  if (
    password === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass'] &&
    !values.aesKey
  ) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    password = await new Promise<string>((resolve) => {
      rl.question('Password: ', (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  const options: RegOptions = {
    action,
    keyName: values.keyName,
    v: values.v,
    ve: values.ve,
    s: values.s,
    vt: values.vt,
    vd: values.vd ?? [],
    va: values.va,
    persistent: values.persistent,
    outputPath: values.o,
    port: parseInt(values.port!, 10),
  };

  const regHandler = new RegHandler(username, password, resolvedDomain, options, {
    hashes: values.hashes ?? null,
    aesKey: values.aesKey ?? null,
    doKerberos,
    kdcHost: values['dc-ip'] ?? null,
  });

  try {
    await regHandler.run(remoteName, targetIp);
  } catch (e) {
    error(String(e));
    process.exit(1);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
