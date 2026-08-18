#!/usr/bin/env node
/**
 * jspacket - dpapi
 *
 * Example for using the DPAPI/Vault structures to unlock Windows Secrets.
 *
 * You can unlock masterkeys, credentials and vaults. For the three, you will
 * specify the file name (using -file for masterkeys and credentials, and -vpol
 * and -vcrd for vaults). If no other parameter is sent, the contents of these
 * resources will be shown, with their encrypted data as well. If you specify a
 * -key blob (in the form of '0xabcdef...') that key will be used to decrypt the
 * contents. In the case of vaults, you might need to also provide the user's
 * sid (and the user password will be asked). For system secrets, instead of a
 * password you will need to specify the system and security hives.
 *
 * Original Python implementation by Alberto Solino (@agsolino). TypeScript port.
 */

import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import {
  createPrivateKey,
  privateDecrypt,
  createDecipheriv,
  constants as cryptoConstants,
} from 'node:crypto';

import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug as logDebug,
  critical,
  getLevel,
  LogLevel,
  normalizeArgs,
  LocalOperations,
  LSASecrets,
  BANNER,
} from '@impacket/examples';

import {
  MasterKeyFile,
  MasterKey,
  CredHist,
  DomainKey,
  CredentialFile,
  DPAPI_BLOB,
  CREDENTIAL_BLOB,
  VAULT_VCRD,
  VAULT_VPOL,
  VAULT_KNOWN_SCHEMAS,
  VAULT_VPOL_KEYS,
  P_BACKUP_KEY,
  PREFERRED_BACKUP_KEY,
  PVK_FILE_HDR,
  PRIVATE_KEY_BLOB,
  privatekeyblobToPkcs1,
  DPAPI_DOMAIN_RSA_MASTER_KEY,
  deriveKeysFromUser,
  deriveKeysFromUserkey,
  CREDHIST_FILE,
  binToString,
} from '@impacket/dpapi';

import {
  DCERPCTransportFactory,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  RPC_C_AUTHN_GSS_NEGOTIATE,
  MSRPC_UUID_BKRP,
  BACKUPKEY_RESTORE_GUID,
  hBackuprKey,
  MSRPC_UUID_LSAD,
  POLICY_GET_PRIVATE_INFORMATION,
  hLsarOpenPolicy2,
  hLsarRetrievePrivateData,
} from '@impacket/dcerpc';

import { SMBConnection } from '@impacket/smb-connection';
import { decryptSecret } from '@impacket/crypto';
import { hexdump } from '@impacket/structure';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Parse a "0xabcdef..." hex key into raw bytes. */
function parseHexKey(key: string): Buffer {
  return Buffer.from(key.replace(/^0x/, ''), 'hex');
}

/** Prompt for a password on stderr (equivalent to Python getpass). */
async function getpass(promptText = 'Password:'): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise<string>((resolve) => {
    rl.question(promptText, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/** Print a structure's dump() output to stdout. */
function dumpToStdout(obj: { dump(): string[] }): void {
  for (const line of obj.dump()) console.log(line);
}

// ---------------------------------------------------------------------------
// DPAPI runner
// ---------------------------------------------------------------------------

interface Options {
  action: string;
  file?: string;
  sid?: string;
  pvk?: string;
  key?: string;
  password?: string;
  system?: string;
  security?: string;
  target?: string;
  hashes?: string;
  noPass: boolean;
  k: boolean;
  aesKey?: string;
  dcIp?: string;
  export: boolean;
  vcrd?: string;
  vpol?: string;
  entropy?: string;
  entropyFile?: string;
  outfile?: string;
  entry?: number;
}

class DPAPI {
  private options: Options;
  private dpapiSystem: { MachineKey?: Buffer; UserKey?: Buffer } = {};

  constructor(options: Options) {
    this.options = options;
  }

  private getDPAPI_SYSTEM(_secretType: number, secret: string): void {
    if (secret.startsWith('dpapi_machinekey:')) {
      const [machineLine, userLine] = secret.split('\n');
      const machineKey = machineLine!.split(':')[1]!;
      const userKey = userLine!.split(':')[1]!;
      this.dpapiSystem.MachineKey = parseHexKey(machineKey);
      this.dpapiSystem.UserKey = parseHexKey(userKey);
    }
  }

  private async getLSA(): Promise<void> {
    const localOperations = new LocalOperations(this.options.system!);
    const bootKey = localOperations.getBootKey();

    const lsaSecrets = new LSASecrets(
      this.options.security!,
      bootKey,
      null,
      false,
      false,
      (t, s) => this.getDPAPI_SYSTEM(t, s),
    );

    await lsaSecrets.dumpSecrets();

    if (
      this.dpapiSystem.MachineKey === undefined ||
      this.dpapiSystem.UserKey === undefined
    ) {
      logError('Cannot grab MachineKey/UserKey from LSA, aborting...');
      process.exit(1);
    }
  }

  async run(): Promise<void> {
    const action = this.options.action.toUpperCase();

    if (action === 'MASTERKEY') {
      await this.runMasterKey();
    } else if (action === 'BACKUPKEYS') {
      await this.runBackupKeys();
    } else if (action === 'CREDENTIAL') {
      this.runCredential();
    } else if (action === 'VAULT') {
      this.runVault();
    } else if (action === 'UNPROTECT') {
      this.runUnprotect();
    } else if (action === 'CREDHIST') {
      await this.runCredHist();
    }
  }

  // -------------------------------------------------------------------------
  // masterkey
  // -------------------------------------------------------------------------

  private async runMasterKey(): Promise<void> {
    let data = readFileSync(this.options.file!);
    const mkf = new MasterKeyFile(data);
    dumpToStdout(mkf);
    data = data.subarray(mkf.length);

    let mk: MasterKey | null = null;
    let bkmk: MasterKey | null = null;
    let ch: CredHist | null = null;
    let dk: DomainKey | null = null;

    const mkLen = Number(mkf.get('MasterKeyLen'));
    const bkLen = Number(mkf.get('BackupKeyLen'));
    const chLen = Number(mkf.get('CredHistLen'));
    const dkLen = Number(mkf.get('DomainKeyLen'));

    if (mkLen > 0) {
      mk = new MasterKey(data.subarray(0, mkLen));
      data = data.subarray(mk.length);
    }
    if (bkLen > 0) {
      bkmk = new MasterKey(data.subarray(0, bkLen));
      data = data.subarray(bkmk.length);
    }
    if (chLen > 0) {
      ch = new CredHist(data.subarray(0, chLen));
      data = data.subarray(ch.length);
    }
    if (dkLen > 0) {
      dk = new DomainKey(data.subarray(0, dkLen));
      data = data.subarray(dk.length);
    }

    const opt = this.options;

    const report = (label: string, key: Buffer): void => {
      console.log(label);
      console.log(`Decrypted key: 0x${key.toString('hex')}`);
    };

    if (opt.system && opt.security && opt.sid == null) {
      // We have hives, let's try to decrypt with them
      await this.getLSA();
      let dec = mk!.decrypt(this.dpapiSystem.UserKey!);
      if (dec) return report('Decrypted key with UserKey', dec);
      dec = mk!.decrypt(this.dpapiSystem.MachineKey!);
      if (dec) return report('Decrypted key with MachineKey', dec);
      dec = bkmk!.decrypt(this.dpapiSystem.UserKey!);
      if (dec) return report('Decrypted Backup key with UserKey', dec);
      dec = bkmk!.decrypt(this.dpapiSystem.MachineKey!);
      if (dec) return report('Decrypted Backup key with MachineKey', dec);
    } else if (opt.system && opt.security) {
      // Use SID + hash
      await this.getLSA();
      const [key1, key2] = deriveKeysFromUserkey(opt.sid!, this.dpapiSystem.UserKey!);
      let dec = mk!.decrypt(key1!);
      if (dec) return report('Decrypted key with UserKey + SID', dec);
      dec = bkmk!.decrypt(key1!);
      if (dec) return report('Decrypted Backup key with UserKey + SID', dec);
      if (key2) {
        dec = mk!.decrypt(key2);
        if (dec) return report('Decrypted key with UserKey + SID', dec);
        dec = bkmk!.decrypt(key2);
        if (dec) return report('Decrypted Backup key with UserKey + SID', dec);
      }
    } else if (opt.key && opt.sid) {
      const key = parseHexKey(opt.key);
      const [key1, key2] = deriveKeysFromUserkey(opt.sid, key);
      let dec = mk!.decrypt(key1!);
      if (dec) return report('Decrypted key with key provided + SID', dec);
      if (key2) {
        dec = mk!.decrypt(key2);
        if (dec) return report('Decrypted key with key provided + SID', dec);
      }
    } else if (opt.key) {
      const key = parseHexKey(opt.key);
      const dec = mk!.decrypt(key);
      if (dec) return report('Decrypted key with key provided', dec);
    } else if (opt.pvk && dk) {
      const pvkfile = readFileSync(opt.pvk);
      const hdrLen = new PVK_FILE_HDR().length;
      const keyBlob = new PRIVATE_KEY_BLOB(pvkfile.subarray(hdrLen));
      const decryptedKey = this.rsaPkcs1Decrypt(keyBlob, Buffer.from(dk.get('SecretData') as Buffer).reverse());
      if (decryptedKey) {
        const domainMasterKey = new DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey);
        const cb = Number(domainMasterKey.get('cbMasterKey'));
        const key = (domainMasterKey.get('buffer') as Buffer).subarray(0, cb);
        console.log('Decrypted key with domain backup key provided');
        console.log(`Decrypted key: 0x${key.toString('hex')}`);
      }
      return;
    } else if (opt.sid && opt.key == null) {
      let password = opt.password;
      if (password == null) password = await getpass('Password:');
      const [key1, key2, key3] = deriveKeysFromUser(opt.sid, password);

      // if mkf['flags'] & 4 ? SHA1 : MD4
      let dec = mk!.decrypt(key3!);
      if (dec) return report('Decrypted key with User Key (MD4 protected)', dec);
      dec = mk!.decrypt(key2!);
      if (dec) return report('Decrypted key with User Key (MD4)', dec);
      dec = mk!.decrypt(key1!);
      if (dec) return report('Decrypted key with User Key (SHA1)', dec);
      dec = bkmk!.decrypt(key3!);
      if (dec) return report('Decrypted Backup key with User Key (MD4 protected)', dec);
      dec = bkmk!.decrypt(key2!);
      if (dec) return report('Decrypted Backup key with User Key (MD4)', dec);
      dec = bkmk!.decrypt(key1!);
      if (dec) return report('Decrypted Backup key with User Key (SHA1)', dec);
    } else if (opt.target != null) {
      await this.decryptMasterKeyViaRpc(dk!);
      return;
    } else {
      // Just print key's data
      if (mkLen > 0) dumpToStdout(mk!);
      if (bkLen > 0) dumpToStdout(bkmk!);
      if (chLen > 0) dumpToStdout(ch!);
      if (dkLen > 0) dumpToStdout(dk!);
      return;
    }

    console.log('Cannot decrypt (specify -key or -sid whenever applicable) ');
  }

  /** Decrypt a DomainKey via the BackupKey RPC protocol (@gentilkiwi). */
  private async decryptMasterKeyViaRpc(dk: DomainKey): Promise<void> {
    const opt = this.options;
    const [domain, username, tPassword, remoteName] = parseTarget(opt.target!);
    let password = tPassword;
    const dom = domain || '';

    if (
      password === '' &&
      username !== '' &&
      opt.hashes == null &&
      opt.noPass === false &&
      opt.aesKey == null
    ) {
      password = await getpass('Password:');
    }

    let lmhash = '';
    let nthash = '';
    if (opt.hashes != null) {
      const parts = opt.hashes.split(':');
      lmhash = parts[0] ?? '';
      nthash = parts[1] ?? '';
    }

    const stringBinding = `ncacn_np:${remoteName}[\\PIPE\\protected_storage]`;
    const rpctransport = DCERPCTransportFactory(stringBinding);
    if ('setCredentials' in rpctransport) {
      (rpctransport as any).setCredentials(username, password, dom, lmhash, nthash, opt.aesKey ?? null);
    }
    rpctransport.setKerberos(opt.k, opt.dcIp ?? null);

    const dce = rpctransport.getDceRpc();
    dce.setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
    if (opt.k === true) {
      dce.setAuthType(RPC_C_AUTHN_GSS_NEGOTIATE);
    }
    await dce.connect();
    await dce.bind(MSRPC_UUID_BKRP!);

    const dkData = dk.getData();
    const resp = await hBackuprKey(dce as any, BACKUPKEY_RESTORE_GUID, dkData, 0);

    // Strip heading zeros resulting from asymmetric decryption
    const out = collectBytes((resp as any).fields['ppDataOut']);
    let beginning = 0;
    while (beginning < out.length && out[beginning] === 0) beginning++;
    const masterkey = out.subarray(beginning);
    console.log('Decrypted key using rpc call');
    console.log(`Decrypted key: 0x${masterkey.toString('hex')}`);
  }

  /** PKCS#1 v1.5 RSA decrypt using a PRIVATE_KEY_BLOB. */
  private rsaPkcs1Decrypt(keyBlob: PRIVATE_KEY_BLOB, ciphertext: Buffer): Buffer | null {
    const { n, e, d, p, q } = privatekeyblobToPkcs1(keyBlob);
    const pem = buildRsaPrivateKeyPem(n, e, d, p, q);
    const keyObject = createPrivateKey({ key: pem, format: 'pem', type: 'pkcs1' });
    try {
      return privateDecrypt(
        { key: keyObject, padding: cryptoConstants.RSA_PKCS1_PADDING },
        ciphertext,
      );
    } catch {
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // backupkeys (credit to @gentilkiwi)
  // -------------------------------------------------------------------------

  private async runBackupKeys(): Promise<void> {
    const opt = this.options;
    const [domain, username, tPassword, address] = parseTarget(opt.target!);
    let password = tPassword;
    const dom = domain || '';

    if (
      password === '' &&
      username !== '' &&
      opt.hashes == null &&
      opt.noPass === false &&
      opt.aesKey == null
    ) {
      password = await getpass('Password:');
    }

    let lmhash = '';
    let nthash = '';
    if (opt.hashes != null) {
      const parts = opt.hashes.split(':');
      lmhash = parts[0] ?? '';
      nthash = parts[1] ?? '';
    }

    const connection = new SMBConnection(address, address);
    await connection.negotiateSession();
    if (opt.k) {
      await connection.kerberosLogin(username, password, dom, lmhash, nthash, opt.aesKey ?? '', opt.dcIp ?? null);
    } else {
      await connection.login(username, password, dom, lmhash, nthash);
    }

    const rpctransport = DCERPCTransportFactory('ncacn_np:445[\\pipe\\lsarpc]');
    if ('setSmbConnection' in rpctransport) {
      (rpctransport as any).setSmbConnection(connection);
    }
    const dce = rpctransport.getDceRpc();
    if (opt.k) {
      dce.setAuthType(RPC_C_AUTHN_GSS_NEGOTIATE);
    }
    await dce.connect();
    await dce.bind(MSRPC_UUID_LSAD);

    try {
      const resp = await hLsarOpenPolicy2(dce as any, POLICY_GET_PRIVATE_INFORMATION);
      const policyHandle = resp.get
        ? resp.get('PolicyHandle')
        : resp.fields['PolicyHandle'];

      for (const keyname of ['G$BCKUPKEY_PREFERRED', 'G$BCKUPKEY_P']) {
        const bufEnc = await hLsarRetrievePrivateData(dce as any, policyHandle, keyname);
        const buffer = decryptSecret(connection.getSessionKey(), bufEnc);
        const guid = binToString(buffer);
        const name = `G$BCKUPKEY_${guid}`;
        const secretEnc = await hLsarRetrievePrivateData(dce as any, policyHandle, name);
        const secret = decryptSecret(connection.getSessionKey(), secretEnc);

        const keyVersion = secret.readUInt32LE(0);
        if (keyVersion === 1) {
          // legacy key
          const backupKey = new P_BACKUP_KEY(secret);
          const backupkey = backupKey.get('Data') as Buffer;
          if (opt.export) {
            logDebug(`Exporting key to file ${name}.key`);
            writeFileSync(`${name}.key`, backupkey);
          } else {
            console.log('Legacy key:');
            console.log(`0x${backupkey.toString('hex')}`);
            console.log('\n');
          }
        } else if (keyVersion === 2) {
          // preferred key
          const backupKey = new PREFERRED_BACKUP_KEY(secret);
          const keyLength = Number(backupKey.get('KeyLength'));
          const certLength = Number(backupKey.get('CertificateLength'));
          const dataBuf = backupKey.get('Data') as Buffer;
          const pvk = dataBuf.subarray(0, keyLength);
          const cert = dataBuf.subarray(keyLength, keyLength + certLength);

          const header = new PVK_FILE_HDR();
          header.set('dwMagic', 0xb0b5f11e);
          header.set('dwVersion', 0);
          header.set('dwKeySpec', 1);
          header.set('dwEncryptType', 0);
          header.set('cbEncryptData', 0);
          header.set('cbPvk', keyLength);
          const backupkeyPvk = Buffer.concat([header.getData(), pvk]);

          if (opt.export) {
            logDebug(`Exporting certificate to file ${name}.der`);
            writeFileSync(`${name}.der`, cert);
            logDebug(`Exporting private key to file ${name}.pvk`);
            writeFileSync(`${name}.pvk`, backupkeyPvk);
          } else {
            console.log('Preferred key:');
            dumpToStdout(header);
            console.log(`PRIVATEKEYBLOB:{${backupkeyPvk.toString('hex')}}`);
            console.log('\n');
          }
        }
      }
    } finally {
      await connection.close();
    }
  }

  // -------------------------------------------------------------------------
  // credential
  // -------------------------------------------------------------------------

  private runCredential(): void {
    const data = readFileSync(this.options.file!);
    const cred = new CredentialFile(data);
    const blob = new DPAPI_BLOB(cred.get('Data') as Buffer);

    if (this.options.key != null) {
      const key = parseHexKey(this.options.key);
      const decrypted = blob.decrypt(key);
      if (decrypted != null) {
        const creds = new CREDENTIAL_BLOB(decrypted);
        dumpToStdout(creds);
        return;
      }
    } else {
      dumpToStdout(blob);
      return;
    }
    console.log('Cannot decrypt (specify -key or -sid whenever applicable) ');
  }

  // -------------------------------------------------------------------------
  // vault
  // -------------------------------------------------------------------------

  private runVault(): void {
    const opt = this.options;
    if (opt.vcrd == null && opt.vpol == null) {
      console.log('You must specify either -vcrd or -vpol parameter. Type --help for more info');
      return;
    }

    if (opt.vcrd != null) {
      const data = readFileSync(opt.vcrd);
      const blob = new VAULT_VCRD(data);

      if (opt.key != null) {
        const key = parseHexKey(opt.key);
        let cleartext: Buffer | null = null;
        for (let i = 0; i < blob.attributesLen.length; i++) {
          if (blob.attributesLen[i]! > 28) {
            const attribute = blob.attributes[i]!;
            const ivField = (attribute as any).fields?.['IV'] as Buffer | undefined;
            const algo = key.length === 16 ? 'aes-128-cbc' : key.length === 24 ? 'aes-192-cbc' : 'aes-256-cbc';
            let decipher;
            if (ivField != null && ivField.length === 16) {
              decipher = createDecipheriv(algo, key, ivField);
            } else {
              decipher = createDecipheriv(algo, key, Buffer.alloc(16, 0));
            }
            decipher.setAutoPadding(false);
            const encData = attribute.get('Data') as Buffer;
            cleartext = Buffer.concat([decipher.update(encData), decipher.final()]);
          }
        }

        if (cleartext != null) {
          const friendly = (blob.get('FriendlyName') as Buffer).toString('utf16le').slice(0, -1);
          const schema = VAULT_KNOWN_SCHEMAS[friendly];
          if (schema != null) {
            const vault = new (schema as any)(cleartext);
            dumpToStdout(vault);
          } else {
            console.log(hexdump(cleartext));
          }
          return;
        }
      } else {
        dumpToStdout(blob);
        return;
      }
    } else if (opt.vpol != null) {
      const data = readFileSync(opt.vpol);
      const vpol = new VAULT_VPOL(data);
      dumpToStdout(vpol);

      if (opt.key != null) {
        const key = parseHexKey(opt.key);
        const blob = vpol.get('Blob') as unknown as DPAPI_BLOB;
        const decrypted = blob.decrypt(key);
        if (decrypted != null) {
          const keys = new VAULT_VPOL_KEYS(decrypted);
          dumpToStdout(keys);
          return;
        }
      }
    }
    console.log('Cannot decrypt (specify -key or -sid whenever applicable) ');
  }

  // -------------------------------------------------------------------------
  // unprotect (CryptUnprotectData)
  // -------------------------------------------------------------------------

  private runUnprotect(): void {
    const opt = this.options;
    const data = readFileSync(opt.file!);
    const blob = new DPAPI_BLOB(data);

    if (opt.key != null) {
      const key = parseHexKey(opt.key);
      let entropy: Buffer | null = null;
      if (opt.entropyFile != null) {
        entropy = readFileSync(opt.entropyFile);
      } else if (opt.entropy != null) {
        entropy = Buffer.from(opt.entropy, 'latin1');
      }

      const decrypted = blob.decrypt(key, entropy);
      if (decrypted != null) {
        console.log('Successfully decrypted data');
        if (opt.outfile != null) {
          writeFileSync(opt.outfile, decrypted);
        } else {
          console.log(hexdump(decrypted));
        }
        return;
      }
    } else {
      dumpToStdout(blob);
      return;
    }
    console.log('Cannot decrypt (specify -key or -sid whenever applicable) ');
  }

  // -------------------------------------------------------------------------
  // credhist
  // -------------------------------------------------------------------------

  private async runCredHist(): Promise<void> {
    const opt = this.options;
    const data = readFileSync(opt.file!);
    const chf = new CREDHIST_FILE(data);

    if (chf.credhistEntriesList.length === 0) {
      console.log('The CREDHIST file is empty');
      return;
    }

    let keys: Buffer[];
    if (opt.key) {
      const key = parseHexKey(opt.key);
      keys = deriveKeysFromUserkey(chf.credhistEntriesList[0]!.sid, key);
    } else {
      let password = opt.password;
      if (password == null) password = await getpass('Password:');
      keys = deriveKeysFromUser(chf.credhistEntriesList[0]!.sid, password);
    }

    if (opt.entry == null) {
      let realKey: Buffer | null = null;
      for (const k of keys) {
        chf.decryptEntryByIndex(0, k);
        if (chf.credhistEntriesList[0]!.pwdhash != null) {
          realKey = k;
          break;
        }
      }

      if (realKey == null) {
        dumpToStdout(chf);
        console.log();
        console.log('Cannot decrypt (wrong key or password)');
        return;
      }

      chf.decrypt(realKey);
      dumpToStdout(chf);
      if (chf.credhistEntriesList[chf.credhistEntriesList.length - 1]!.pwdhash != null) {
        return;
      }
    } else {
      for (const k of keys) {
        chf.decryptEntryByIndex(opt.entry, k);
        if (chf.credhistEntriesList[opt.entry]!.pwdhash != null) {
          dumpToStdout(chf.credhistEntriesList[opt.entry]!);
          return;
        }
      }
      dumpToStdout(chf.credhistEntriesList[opt.entry]!);
      console.log();
      console.log('Cannot decrypt (wrong key or password)');
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// RPC ppDataOut extraction
// ---------------------------------------------------------------------------

/** Collect an NDR byte array (pointer/array/numbers) into a single Buffer. */
function collectBytes(node: any): Buffer {
  if (node == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(node)) return node;
  // Unwrap NDR structures with a nested Data field.
  if (node.fields != null && node.fields['Data'] !== undefined) {
    return collectBytes(node.fields['Data']);
  }
  if (Array.isArray(node)) {
    const parts: Buffer[] = [];
    for (const el of node) {
      if (Buffer.isBuffer(el)) parts.push(el);
      else if (typeof el === 'number') parts.push(Buffer.from([el & 0xff]));
      else parts.push(collectBytes(el));
    }
    return Buffer.concat(parts);
  }
  return Buffer.alloc(0);
}

// ---------------------------------------------------------------------------
// RSA private key PEM builder (PKCS#1) from n, e, d, p, q
// ---------------------------------------------------------------------------

function modinv(a: bigint, m: bigint): bigint {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  return ((old_s % m) + m) % m;
}

/** DER-encode a length prefix. */
function derLen(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** DER-encode an INTEGER from a non-negative bigint. */
function derInteger(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = '0' + hex;
  let bytes = Buffer.from(hex, 'hex');
  if (bytes.length === 0) bytes = Buffer.from([0]);
  // Prepend 0x00 if high bit set (to keep it positive).
  if ((bytes[0]! & 0x80) !== 0) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([0x02]), derLen(bytes.length), bytes]);
}

/** DER-encode a SEQUENCE from already-encoded members. */
function derSequence(...members: Buffer[]): Buffer {
  const body = Buffer.concat(members);
  return Buffer.concat([Buffer.from([0x30]), derLen(body.length), body]);
}

/** Build a PKCS#1 RSA private key PEM from CRT components. */
function buildRsaPrivateKeyPem(n: bigint, e: bigint, d: bigint, p: bigint, q: bigint): string {
  const dmp1 = d % (p - 1n);
  const dmq1 = d % (q - 1n);
  const iqmp = modinv(q, p);
  const der = derSequence(
    derInteger(0n), // version
    derInteger(n),
    derInteger(e),
    derInteger(d),
    derInteger(p),
    derInteger(q),
    derInteger(dmp1),
    derInteger(dmq1),
    derInteger(iqmp),
  );
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN RSA PRIVATE KEY-----\n${b64}\n-----END RSA PRIVATE KEY-----\n`;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------


function printUsage(): void {
  console.log(`
Example for using the DPAPI/Vault structures to unlock Windows Secrets.

usage: dpapi [-h] [-debug] [-ts]
             {masterkey,credential,vault,unprotect,credhist,backupkeys} ...

actions:
  masterkey   masterkey related functions
                -file FILE (required) -sid SID -pvk PVK -key KEY
                -password PASSWORD -system SYSTEM -security SECURITY
                -t/--target TARGET -hashes LMHASH:NTHASH -no-pass -k
                -aesKey hex key -dc-ip ip address
  credential  credential related functions
                -file FILE (required) -key KEY
  vault       vault credential related functions
                -vcrd VCRD -vpol VPOL -key KEY
  unprotect   Provides CryptUnprotectData functionality
                -file FILE (required) -key KEY -entropy ENTROPY
                -entropy-file FILE -outfile FILE
  credhist    CREDHIST related functions
                -file FILE (required) -key KEY -password PASSWORD -entry INT
  backupkeys  domain backup key related functions
                -t/--target TARGET (required) -hashes LMHASH:NTHASH -no-pass
                -k -aesKey hex key -dc-ip ip address --export

options:
  -h, --help  show this help message and exit
  -debug      Turn DEBUG output ON
  -ts         Adds timestamp to every logging output
`);
}

async function main(): Promise<void> {
  const args = normalizeArgs(process.argv.slice(2));

  console.log(BANNER);

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        // shared / masterkey / backupkeys
        target: { type: 'string', short: 't' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        export: { type: 'boolean', default: false },
        // masterkey / credential / vault / unprotect / credhist
        file: { type: 'string' },
        sid: { type: 'string' },
        pvk: { type: 'string' },
        key: { type: 'string' },
        password: { type: 'string' },
        system: { type: 'string' },
        security: { type: 'string' },
        // vault
        vcrd: { type: 'string' },
        vpol: { type: 'string' },
        // unprotect
        entropy: { type: 'string' },
        'entropy-file': { type: 'string' },
        outfile: { type: 'string' },
        // credhist
        entry: { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  const action = positionals[0];
  if (values.help || action == null) {
    printUsage();
    process.exit(action == null ? 1 : 0);
  }

  initProxy(values.proxy);

  const validActions = ['masterkey', 'credential', 'vault', 'unprotect', 'credhist', 'backupkeys'];
  if (!validActions.includes(action)) {
    critical(`Invalid action: ${action}`);
    printUsage();
    process.exit(1);
  }

  initLogger({ ts: values.ts, debug: values.debug });

  const options: Options = {
    action,
    file: values.file,
    sid: values.sid,
    pvk: values.pvk,
    key: values.key,
    password: values.password,
    system: values.system,
    security: values.security,
    target: values.target,
    hashes: values.hashes,
    noPass: values['no-pass'] ?? false,
    k: values.k ?? false,
    aesKey: values.aesKey,
    dcIp: values['dc-ip'],
    export: values.export ?? false,
    vcrd: values.vcrd,
    vpol: values.vpol,
    entropy: values.entropy,
    entropyFile: values['entropy-file'],
    outfile: values.outfile,
    entry: values.entry != null ? parseInt(values.entry, 10) : undefined,
  };

  // Required-argument validation mirroring argparse subparsers.
  if ((action === 'masterkey' || action === 'credential' || action === 'unprotect' || action === 'credhist') && options.file == null) {
    critical(`the following arguments are required: -file`);
    process.exit(1);
  }
  if (action === 'backupkeys' && options.target == null) {
    critical('the following arguments are required: -t/--target');
    process.exit(1);
  }

  try {
    const executer = new DPAPI(options);
    await executer.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    console.log(`ERROR: ${String(e)}`);
  }
}

main();
