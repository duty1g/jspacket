#!/usr/bin/env node
/**
 * Impacket-js - describeTicket
 *
 * Parses and displays Kerberos ticket details from a ccache or kirbi file.
 * If a decryption key is provided, decrypts the ticket enc-part and displays
 * the PAC (Privilege Attribute Certificate) contents including logon info,
 * client info, UPN/DNS info, and checksum signatures.
 *
 * Python implementation by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  init as initLogger,
  info,
  error as logError,
  debug as logDebug,
  normalizeArgs,
  BANNER,
  initProxy,
} from '@impacket/examples';

import {
  CCache as KrbCCache,
  Constants,
  Asn1 as KrbAsn1,
  Crypto,
  Pac,
} from '@impacket/krb5';

import type { AnyValue } from '@impacket/asn1';

// ---------------------------------------------------------------------------
// Encryption type display names
// ---------------------------------------------------------------------------

const ENCTYPE_NAMES: Record<number, string> = {
  1: 'DES-CBC-CRC',
  2: 'DES-CBC-MD4',
  3: 'DES-CBC-MD5',
  5: 'DES3-CBC-MD5',
  7: 'DES3-CBC-SHA1',
  16: 'DES3-CBC-SHA1-KD',
  17: 'AES128-CTS-HMAC-SHA1-96',
  18: 'AES256-CTS-HMAC-SHA1-96',
  23: 'RC4-HMAC',
  24: 'RC4-HMAC-EXP',
};

// ---------------------------------------------------------------------------
// Checksum type display names
// ---------------------------------------------------------------------------

const CHECKSUM_NAMES: Record<number, string> = {
  [-138]: 'HMAC-MD5',
  4: 'RSA-MD4-DES',
  8: 'RSA-MD5-DES',
  12: 'HMAC-SHA1-DES3-KD',
  15: 'HMAC-SHA1-96-AES128',
  16: 'HMAC-SHA1-96-AES256',
};

// ---------------------------------------------------------------------------
// Ticket flag bit names (bit position -> display name)
// ---------------------------------------------------------------------------

const FLAG_NAMES: Record<number, string> = {
  [Constants.TicketFlags.reserved]: 'reserved',
  [Constants.TicketFlags.forwardable]: 'forwardable',
  [Constants.TicketFlags.forwarded]: 'forwarded',
  [Constants.TicketFlags.proxiable]: 'proxiable',
  [Constants.TicketFlags.proxy]: 'proxy',
  [Constants.TicketFlags.may_postdate]: 'may-postdate',
  [Constants.TicketFlags.postdated]: 'postdated',
  [Constants.TicketFlags.invalid]: 'invalid',
  [Constants.TicketFlags.renewable]: 'renewable',
  [Constants.TicketFlags.initial]: 'initial',
  [Constants.TicketFlags.pre_authent]: 'pre-authent',
  [Constants.TicketFlags.hw_authent]: 'hw-authent',
  [Constants.TicketFlags.transited_policy_checked]: 'transited-policy-checked',
  [Constants.TicketFlags.ok_as_delegate]: 'ok-as-delegate',
  [Constants.TicketFlags.enc_pa_rep]: 'enc-pa-rep',
  [Constants.TicketFlags.anonymous]: 'anonymous',
};

// ---------------------------------------------------------------------------
// PAC buffer type display names
// ---------------------------------------------------------------------------

const PAC_TYPE_NAMES: Record<number, string> = {
  [Pac.PAC_LOGON_INFO]: 'LOGON_INFO',
  [Pac.PAC_CREDENTIALS_INFO]: 'CREDENTIALS_INFO',
  [Pac.PAC_SERVER_CHECKSUM]: 'SERVER_CHECKSUM',
  [Pac.PAC_PRIVSVR_CHECKSUM]: 'KDC_CHECKSUM',
  [Pac.PAC_CLIENT_INFO_TYPE]: 'CLIENT_INFO',
  [Pac.PAC_DELEGATION_INFO]: 'DELEGATION_INFO',
  [Pac.PAC_UPN_DNS_INFO]: 'UPN_DNS_INFO',
  [Pac.PAC_ATTRIBUTES_INFO]: 'ATTRIBUTES_INFO',
  [Pac.PAC_REQUESTOR_INFO]: 'REQUESTOR_INFO',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatEncType(enctype: number): string {
  return ENCTYPE_NAMES[enctype] ?? `etype-${enctype}`;
}

function formatChecksumType(cstype: number): string {
  return CHECKSUM_NAMES[cstype] ?? `cksumtype-${cstype}`;
}

function formatTime(epoch: number): string {
  if (epoch === 0) return '<never>';
  const d = new Date(epoch * 1000);
  return d.toISOString().replace('T', ' ').replace(/\.000Z$/, ' UTC');
}

function formatAsn1Time(value: AnyValue | undefined): string {
  if (value === undefined || value === null) return '<not set>';
  if (value instanceof Date) return value.toISOString().replace('T', ' ').replace(/\.000Z$/, ' UTC');
  if (typeof value === 'string') {
    try {
      const d = new Date(value);
      return d.toISOString().replace('T', ' ').replace(/\.000Z$/, ' UTC');
    } catch {
      return value;
    }
  }
  return String(value);
}

function formatFlags(flagsValue: number): string[] {
  const names: string[] = [];
  for (let bit = 0; bit < 32; bit++) {
    // Kerberos flags: bit 0 is MSB (bit 31 of the 32-bit integer)
    if (flagsValue & (1 << (31 - bit))) {
      const name = FLAG_NAMES[bit];
      if (name) names.push(name);
    }
  }
  return names;
}

function formatFlagsFromBuffer(flagsBuf: Buffer): string[] {
  const names: string[] = [];
  for (let bit = 0; bit < 32 && bit < flagsBuf.length * 8; bit++) {
    const byteIdx = Math.floor(bit / 8);
    const bitIdx = 7 - (bit % 8);
    if (flagsBuf[byteIdx]! & (1 << bitIdx)) {
      const name = FLAG_NAMES[bit];
      if (name) names.push(name);
    }
  }
  return names;
}

function hexDump(buf: Buffer): string {
  return buf.toString('hex');
}

function formatSid(sid: unknown): string {
  if (sid && typeof sid === 'object' && 'formatCanonical' in sid) {
    return (sid as { formatCanonical(): string }).formatCanonical();
  }
  return String(sid);
}

function filetimeToDate(low: number, high: number): Date {
  const ft = (BigInt(high) << 32n) | (BigInt(low) & 0xFFFFFFFFn);
  if (ft === 0n || ft === 0x7FFFFFFFFFFFFFFFn) return new Date(0);
  const unixMs = Number((ft - 116444736000000000n) / 10000n);
  return new Date(unixMs);
}

function formatFiletime(low: number | unknown, high: number | unknown): string {
  if (typeof low !== 'number' || typeof high !== 'number') return '<unknown>';
  const d = filetimeToDate(low, high);
  if (d.getTime() === 0) return '<never>';
  return d.toISOString().replace('T', ' ').replace(/\.000Z$/, ' UTC');
}

// ---------------------------------------------------------------------------
// DescribeTicket
// ---------------------------------------------------------------------------

class DescribeTicket {
  private ticketPath: string;
  private key: Buffer | null;
  private password: string | Buffer | null;
  private salt: string | null;

  constructor(
    ticketPath: string,
    key: Buffer | null,
    password: string | Buffer | null = null,
    salt: string | null = null,
  ) {
    this.ticketPath = ticketPath;
    this.key = key;
    this.password = password;
    this.salt = salt;
  }

  async run(): Promise<void> {
    const data = readFileSync(this.ticketPath);

    if (data.length < 2) {
      logError('File is too small to be a valid ticket');
      process.exit(1);
    }

    // Detect format: ccache starts with 0x0504, kirbi is ASN.1 DER
    const isKirbi = !this.isCCache(data);

    if (isKirbi) {
      info(`[*] Loading kirbi file: ${this.ticketPath}`);
      this.processKirbi(data);
    } else {
      info(`[*] Loading ccache file: ${this.ticketPath}`);
      this.processCCache(data);
    }
  }

  private isCCache(data: Buffer): boolean {
    // CCache v4 starts with 0x0504; v3 starts with 0x0503
    return data[0] === 0x05 && (data[1] === 0x04 || data[1] === 0x03);
  }

  private processCCache(data: Buffer): void {
    const ccache = new KrbCCache.CCache(data);

    if (ccache.credentials.length === 0) {
      logError('No credentials found in ccache file');
      return;
    }

    info(`[*] Number of credentials in cache: ${ccache.credentials.length}`);
    info(`[*] Default principal: ${ccache.principal.prettyPrint()}`);
    info('');

    for (let i = 0; i < ccache.credentials.length; i++) {
      const cred = ccache.credentials[i]!;
      info(`[*] Credential [${i}]:`);
      this.displayCCacheCredential(cred);
      info('');

      if (this.key || this.password !== null) {
        this.decryptCCacheTicket(cred);
      }
    }
  }

  private displayCCacheCredential(cred: KrbCCache.Credential): void {
    info(`  Client: ${cred.client.prettyPrint()}`);
    info(`  Server: ${cred.server.prettyPrint()}`);
    info(`  Key type: ${formatEncType(cred.key.keytype)} (${cred.key.keytype})`);
    info(`  Key value: ${hexDump(cred.key.keyvalue)}`);
    info(`  Auth time: ${formatTime(cred.time.authtime)}`);
    info(`  Start time: ${formatTime(cred.time.starttime)}`);
    info(`  End time: ${formatTime(cred.time.endtime)}`);
    info(`  Renew till: ${formatTime(cred.time.renew_till)}`);

    const flags = formatFlags(cred.tktflags);
    info(`  Flags: 0x${cred.tktflags.toString(16).padStart(8, '0')} (${flags.join(', ')})`);
  }

  private decryptCCacheTicket(cred: KrbCCache.Credential): void {
    // The credential's ticket field contains the ASN.1-encoded Ticket
    const ticketData = cred.ticket.data;
    if (ticketData.length === 0) {
      logError('  [!] No ticket data found in credential');
      return;
    }

    try {
      const ticketNode = KrbAsn1.Ticket();
      ticketNode.decode(ticketData);

      const encPart = ticketNode.get('enc-part') as Record<string, AnyValue>;
      const enctype = Number(encPart['etype']);
      const kvno = encPart['kvno'] !== undefined ? Number(encPart['kvno']) : null;
      const ciphertext = encPart['cipher'] as Buffer;

      info(`  [*] Encrypted part:`);
      info(`    Enc type: ${formatEncType(enctype)} (${enctype})`);
      if (kvno !== null) {
        info(`    Key version: ${kvno}`);
      }

      this.decryptAndDisplay(enctype, ciphertext);
    } catch (e) {
      logError(`  [!] Failed to parse/decrypt ticket: ${(e as Error).message}`);
      logDebug(`  ${(e as Error).stack ?? ''}`);
    }
  }

  private processKirbi(data: Buffer): void {
    try {
      const krbCred = KrbAsn1.KRB_CRED();
      krbCred.decode(data);

      // Extract tickets from KRB-CRED
      const ticketsValue = krbCred.get('tickets');
      const encPartValue = krbCred.get('enc-part') as Record<string, AnyValue>;

      // In a kirbi, enc-part is usually plaintext (etype 0) containing EncKrbCredPart
      const etype = Number(encPartValue['etype'] ?? 0);
      const cipher = encPartValue['cipher'] as Buffer;

      let credInfoList: Record<string, AnyValue>[] = [];
      if (etype === 0) {
        // Plaintext EncKrbCredPart
        const encKrbCredPart = KrbAsn1.EncKrbCredPart();
        encKrbCredPart.decode(cipher);
        const ticketInfoNodes = encKrbCredPart.get('ticket-info') as unknown[];
        credInfoList = ticketInfoNodes.map((node) => {
          if (node && typeof node === 'object' && 'values' in node) {
            return (node as { values: Record<string, AnyValue> }).values;
          }
          return node as Record<string, AnyValue>;
        });
      }

      // Get actual ticket ASN.1 nodes
      let ticketNodes: unknown[] = [];
      if (Array.isArray(ticketsValue)) {
        ticketNodes = ticketsValue;
      } else if (ticketsValue && typeof ticketsValue === 'object') {
        ticketNodes = [ticketsValue];
      }

      info(`[*] Number of credentials: ${Math.max(credInfoList.length, ticketNodes.length)}`);
      info('');

      const count = Math.max(credInfoList.length, ticketNodes.length);
      for (let i = 0; i < count; i++) {
        info(`[*] Credential [${i}]:`);

        const credInfo = credInfoList[i];
        if (credInfo) {
          this.displayKirbiCredInfo(credInfo);
        }

        info('');

        if ((this.key || this.password !== null) && i < ticketNodes.length) {
          this.decryptKirbiTicket(ticketNodes[i]!);
        }
      }
    } catch (e) {
      logError(`[!] Failed to parse kirbi file: ${(e as Error).message}`);
      logDebug(`${(e as Error).stack ?? ''}`);
    }
  }

  private displayKirbiCredInfo(credInfo: Record<string, AnyValue>): void {
    // Key
    const key = credInfo['key'] as Record<string, AnyValue> | undefined;
    if (key) {
      const keytype = Number(key['keytype'] ?? 0);
      const keyvalue = key['keyvalue'] as Buffer | undefined;
      info(`  Session key type: ${formatEncType(keytype)} (${keytype})`);
      if (keyvalue) {
        info(`  Session key value: ${hexDump(keyvalue)}`);
      }
    }

    // Principal realm / name
    const prealm = credInfo['prealm'] as string | undefined;
    const pname = credInfo['pname'] as Record<string, AnyValue> | undefined;
    if (pname) {
      const nameType = Number(pname['name-type'] ?? 0);
      void nameType;
      const nameString = pname['name-string'] as unknown[];
      const parts = (nameString ?? []).map((s) => {
        if (s && typeof s === 'object' && 'value' in s) return String((s as { value: unknown }).value);
        return String(s);
      });
      info(`  Client: ${parts.join('/')}@${prealm ?? ''}`);
    }

    // Server realm / name
    const srealm = credInfo['srealm'] as string | undefined;
    const sname = credInfo['sname'] as Record<string, AnyValue> | undefined;
    if (sname) {
      const nameString = sname['name-string'] as unknown[];
      const parts = (nameString ?? []).map((s) => {
        if (s && typeof s === 'object' && 'value' in s) return String((s as { value: unknown }).value);
        return String(s);
      });
      info(`  Server: ${parts.join('/')}@${srealm ?? ''}`);
    }

    // Flags
    const flagsVal = credInfo['flags'];
    if (flagsVal !== undefined) {
      if (Buffer.isBuffer(flagsVal)) {
        const names = formatFlagsFromBuffer(flagsVal);
        info(`  Flags: ${names.join(', ')}`);
      }
    }

    // Times
    info(`  Auth time: ${formatAsn1Time(credInfo['authtime'])}`);
    info(`  Start time: ${formatAsn1Time(credInfo['starttime'])}`);
    info(`  End time: ${formatAsn1Time(credInfo['endtime'])}`);
    info(`  Renew till: ${formatAsn1Time(credInfo['renew-till'])}`);
  }

  private decryptKirbiTicket(ticketNode: unknown): void {
    try {
      let encPart: Record<string, AnyValue>;
      if (ticketNode && typeof ticketNode === 'object' && 'values' in ticketNode) {
        const tktValues = (ticketNode as { values: Record<string, AnyValue> }).values;
        encPart = tktValues['enc-part'] as Record<string, AnyValue>;
      } else {
        encPart = (ticketNode as Record<string, AnyValue>)['enc-part'] as Record<string, AnyValue>;
      }

      const enctype = Number(encPart['etype']);
      const kvno = encPart['kvno'] !== undefined ? Number(encPart['kvno']) : null;
      const ciphertext = encPart['cipher'] as Buffer;

      info(`  [*] Encrypted part:`);
      info(`    Enc type: ${formatEncType(enctype)} (${enctype})`);
      if (kvno !== null) {
        info(`    Key version: ${kvno}`);
      }

      this.decryptAndDisplay(enctype, ciphertext);
    } catch (e) {
      logError(`  [!] Failed to parse/decrypt kirbi ticket: ${(e as Error).message}`);
      logDebug(`  ${(e as Error).stack ?? ''}`);
    }
  }

  private decryptAndDisplay(enctype: number, ciphertext: Buffer): void {
    let key: InstanceType<typeof Crypto.Key> | null = null;

    if (this.key) {
      key = new Crypto.Key(enctype, this.key);
    } else if (this.password !== null) {
      info(`  [*] Deriving key from password for enctype ${formatEncType(enctype)} (${enctype})`);
      const salt = this.salt ?? '';
      key = Crypto.string_to_key(enctype, this.password, salt, null);
      info(`  [*] Derived key: ${key.contents.toString('hex')}`);
    }

    if (!key) return;

    try {
      // Key usage 2 = AS-REP Ticket and TGS-REP Ticket
      const plaintext = Crypto.decrypt(key, 2, ciphertext);

      info('  [*] Decrypted EncTicketPart:');

      const encTicketPart = KrbAsn1.EncTicketPart();
      encTicketPart.decode(plaintext);

      // Flags
      const flagsVal = encTicketPart.get('flags');
      if (flagsVal !== undefined && flagsVal !== null) {
        if (Buffer.isBuffer(flagsVal)) {
          const names = formatFlagsFromBuffer(flagsVal);
          info(`    Flags: ${names.join(', ')}`);
        }
      }

      // Session key
      const sessionKey = encTicketPart.get('key') as Record<string, AnyValue> | undefined;
      if (sessionKey) {
        const skType = Number(sessionKey['keytype'] ?? 0);
        const skValue = sessionKey['keyvalue'] as Buffer | undefined;
        info(`    Session key: ${formatEncType(skType)} (${skType})`);
        if (skValue) {
          info(`    Session key value: ${hexDump(skValue)}`);
        }
      }

      // Client
      const crealm = encTicketPart.get('crealm') as string | undefined;
      const cname = encTicketPart.get('cname') as Record<string, AnyValue> | undefined;
      if (cname) {
        const nameString = cname['name-string'] as unknown[];
        const parts = (nameString ?? []).map((s) => {
          if (s && typeof s === 'object' && 'value' in s) return String((s as { value: unknown }).value);
          return String(s);
        });
        info(`    Client: ${parts.join('/')}@${crealm ?? ''}`);
      }

      // Times
      info(`    Auth time: ${formatAsn1Time(encTicketPart.get('authtime'))}`);
      info(`    Start time: ${formatAsn1Time(encTicketPart.get('starttime'))}`);
      info(`    End time: ${formatAsn1Time(encTicketPart.get('endtime'))}`);
      info(`    Renew till: ${formatAsn1Time(encTicketPart.get('renew-till'))}`);

      // Authorization data (contains PAC)
      const authData = encTicketPart.get('authorization-data');
      if (authData) {
        this.processAuthorizationData(authData);
      }
    } catch (e) {
      logError(`  [!] Decryption failed: ${(e as Error).message}`);
      logDebug(`  ${(e as Error).stack ?? ''}`);
      logError('  [!] Make sure the provided key is correct for this ticket\'s encryption type');
    }
  }

  private processAuthorizationData(authData: unknown): void {
    // AuthorizationData is a SEQUENCE OF { ad-type INTEGER, ad-data OCTET STRING }
    let adEntries: unknown[];
    if (Array.isArray(authData)) {
      adEntries = authData;
    } else {
      adEntries = [authData];
    }

    for (const entry of adEntries) {
      let adType: number;
      let adData: Buffer;

      if (entry && typeof entry === 'object' && 'values' in entry) {
        const vals = (entry as { values: Record<string, AnyValue> }).values;
        adType = Number(vals['ad-type']);
        adData = vals['ad-data'] as Buffer;
      } else {
        const vals = entry as Record<string, AnyValue>;
        adType = Number(vals['ad-type']);
        adData = vals['ad-data'] as Buffer;
      }

      if (adType === Constants.AuthorizationDataType.AD_IF_RELEVANT) {
        // AD-IF-RELEVANT wraps another AuthorizationData sequence
        const innerAuthData = KrbAsn1.AuthorizationData();
        innerAuthData.decode(adData);
        // decodeValue returns Asn1Node[]
        const innerItems = innerAuthData.items ?? [];
        for (const innerEntry of innerItems) {
          let innerType: number;
          let innerData: Buffer;

          if (innerEntry && typeof innerEntry === 'object' && 'values' in innerEntry) {
            const vals = (innerEntry as { values: Record<string, AnyValue> }).values;
            innerType = Number(vals['ad-type']);
            innerData = vals['ad-data'] as Buffer;
          } else {
            const vals = innerEntry as unknown as Record<string, AnyValue>;
            innerType = Number(vals['ad-type']);
            innerData = vals['ad-data'] as Buffer;
          }

          if (innerType === Constants.AuthorizationDataType.AD_WIN2K_PAC) {
            info('');
            info('  [*] PAC found:');
            this.displayPac(innerData);
          }
        }
      } else if (adType === Constants.AuthorizationDataType.AD_WIN2K_PAC) {
        info('');
        info('  [*] PAC found:');
        this.displayPac(adData);
      }
    }
  }

  private displayPac(pacData: Buffer): void {
    try {
      const pacType = new Pac.PACTYPE(pacData);
      const cBuffers = Number(pacType.get('cBuffers'));
      const version = Number(pacType.get('Version'));
      info(`    PAC Version: ${version}, Buffer count: ${cBuffers}`);

      const buffersData = pacType.get('Buffers') as Buffer;
      const infoBufferSize = 16; // PAC_INFO_BUFFER is 16 bytes (L + L + Q)

      for (let i = 0; i < cBuffers; i++) {
        const ibData = buffersData.subarray(i * infoBufferSize, (i + 1) * infoBufferSize);
        const infoBuffer = new Pac.PAC_INFO_BUFFER(ibData);
        const ulType = Number(infoBuffer.get('ulType'));
        const cbBufferSize = Number(infoBuffer.get('cbBufferSize'));
        const offset = Number(infoBuffer.get('Offset'));

        const typeName = PAC_TYPE_NAMES[ulType] ?? `UNKNOWN(${ulType})`;
        info('');
        info(`    === ${typeName} (type ${ulType}) ===`);

        // Extract buffer data from the full PAC
        const bufferContent = pacData.subarray(offset, offset + cbBufferSize);

        try {
          switch (ulType) {
            case Pac.PAC_LOGON_INFO:
              this.displayLogonInfo(bufferContent);
              break;
            case Pac.PAC_CLIENT_INFO_TYPE:
              this.displayClientInfo(bufferContent);
              break;
            case Pac.PAC_UPN_DNS_INFO:
              this.displayUpnDnsInfo(bufferContent);
              break;
            case Pac.PAC_SERVER_CHECKSUM:
              this.displayChecksum(bufferContent, 'Server');
              break;
            case Pac.PAC_PRIVSVR_CHECKSUM:
              this.displayChecksum(bufferContent, 'KDC');
              break;
            default:
              info(`    Size: ${cbBufferSize} bytes`);
              break;
          }
        } catch (e) {
          logError(`    [!] Failed to parse ${typeName}: ${(e as Error).message}`);
          logDebug(`    ${(e as Error).stack ?? ''}`);
        }
      }
    } catch (e) {
      logError(`    [!] Failed to parse PAC: ${(e as Error).message}`);
      logDebug(`    ${(e as Error).stack ?? ''}`);
    }
  }

  private displayLogonInfo(data: Buffer): void {
    const validationInfo = new Pac.VALIDATION_INFO(data);
    const kerbValInfo = validationInfo.get('Data') as unknown;

    // Navigate through PKERB_VALIDATION_INFO -> KERB_VALIDATION_INFO
    let logonInfo: { get(key: string): unknown };
    if (kerbValInfo && typeof kerbValInfo === 'object' && 'get' in kerbValInfo) {
      logonInfo = kerbValInfo as { get(key: string): unknown };
    } else {
      info('    (Unable to parse KERB_VALIDATION_INFO)');
      return;
    }

    const effectiveName = logonInfo.get('EffectiveName');
    const fullName = logonInfo.get('FullName');
    const logonServer = logonInfo.get('LogonServer');
    const logonDomainName = logonInfo.get('LogonDomainName');

    info(`    Effective name: ${effectiveName ?? '<empty>'}`);
    info(`    Full name: ${fullName ?? '<empty>'}`);
    info(`    Logon server: ${logonServer ?? '<empty>'}`);
    info(`    Logon domain: ${logonDomainName ?? '<empty>'}`);

    const userId = logonInfo.get('UserId');
    const primaryGroupId = logonInfo.get('PrimaryGroupId');
    info(`    User ID: ${userId}`);
    info(`    Primary group ID: ${primaryGroupId}`);

    // Domain SID
    const domainSid = logonInfo.get('LogonDomainId');
    if (domainSid) {
      info(`    Domain SID: ${formatSid(domainSid)}`);
    }

    // User account control
    const uac = logonInfo.get('UserAccountControl');
    if (typeof uac === 'number') {
      info(`    User account control: 0x${uac.toString(16).padStart(8, '0')}`);
    }

    // Group memberships
    const groupCount = Number(logonInfo.get('GroupCount') ?? 0);
    const groupIds = logonInfo.get('GroupIds');
    if (groupCount > 0 && groupIds) {
      info(`    Group memberships (${groupCount}):`);
      const groups = Array.isArray(groupIds) ? groupIds : [];
      for (const g of groups) {
        if (g && typeof g === 'object' && 'get' in g) {
          const gObj = g as { get(key: string): unknown };
          info(`      RID: ${gObj.get('RelativeId')}, Attributes: 0x${(Number(gObj.get('Attributes')) >>> 0).toString(16)}`);
        }
      }
    }

    // Logon time
    const logonTime = logonInfo.get('LogonTime');
    if (logonTime && typeof logonTime === 'object' && 'get' in logonTime) {
      const ft = logonTime as { get(key: string): unknown };
      info(`    Logon time: ${formatFiletime(ft.get('dwLowDateTime') as number, ft.get('dwHighDateTime') as number)}`);
    }

    // Extra SIDs
    const sidCount = Number(logonInfo.get('SidCount') ?? 0);
    const extraSids = logonInfo.get('ExtraSids');
    if (sidCount > 0 && extraSids) {
      info(`    Extra SIDs (${sidCount}):`);
      const sids = Array.isArray(extraSids) ? extraSids : [];
      for (const s of sids) {
        if (s && typeof s === 'object' && 'get' in s) {
          const sObj = s as { get(key: string): unknown };
          const sid = sObj.get('Sid');
          const attrs = Number(sObj.get('Attributes') ?? 0) >>> 0;
          info(`      SID: ${formatSid(sid)}, Attributes: 0x${attrs.toString(16)}`);
        }
      }
    }
  }

  private displayClientInfo(data: Buffer): void {
    const clientInfo = new Pac.PAC_CLIENT_INFO(data);
    const clientId = clientInfo.get('ClientId') as bigint | number;
    const nameLength = Number(clientInfo.get('NameLength'));
    const nameData = clientInfo.get('Name') as Buffer;

    // ClientId is a FILETIME (100-ns intervals since 1601-01-01)
    const ft = BigInt(clientId);
    let dateStr: string;
    if (ft === 0n) {
      dateStr = '<never>';
    } else {
      const unixMs = Number((ft - 116444736000000000n) / 10000n);
      dateStr = new Date(unixMs).toISOString().replace('T', ' ').replace(/\.000Z$/, ' UTC');
    }
    info(`    Auth time: ${dateStr}`);

    let clientName: string;
    if (nameData && nameLength > 0) {
      clientName = nameData.subarray(0, nameLength).toString('utf16le');
    } else {
      clientName = '<empty>';
    }
    info(`    Client name: ${clientName}`);
  }

  private displayUpnDnsInfo(data: Buffer): void {
    // Try the full version first (with SamName + SID), fall back to basic
    try {
      const flags = data.readUInt32LE(8);
      const hasExtended = (flags & 0x02) !== 0; // U flag means extended fields present

      if (hasExtended && data.length >= 20) {
        const upnInfo = new Pac.UPN_DNS_INFO_FULL(data.subarray(0, 20));
        const upnLength = Number(upnInfo.get('UpnLength'));
        const upnOffset = Number(upnInfo.get('UpnOffset'));
        const dnsLength = Number(upnInfo.get('DnsDomainNameLength'));
        const dnsOffset = Number(upnInfo.get('DnsDomainNameOffset'));

        const upn = data.subarray(upnOffset, upnOffset + upnLength).toString('utf16le');
        const dns = data.subarray(dnsOffset, dnsOffset + dnsLength).toString('utf16le');

        info(`    UPN: ${upn}`);
        info(`    DNS Domain: ${dns}`);
        info(`    Flags: 0x${flags.toString(16).padStart(8, '0')}`);

        const samLength = Number(upnInfo.get('SamNameLength'));
        const samOffset = Number(upnInfo.get('SamNameOffset'));
        if (samLength > 0 && samOffset > 0) {
          const samName = data.subarray(samOffset, samOffset + samLength).toString('utf16le');
          info(`    SAM Name: ${samName}`);
        }
      } else {
        const upnInfo = new Pac.UPN_DNS_INFO(data.subarray(0, 12));
        const upnLength = Number(upnInfo.get('UpnLength'));
        const upnOffset = Number(upnInfo.get('UpnOffset'));
        const dnsLength = Number(upnInfo.get('DnsDomainNameLength'));
        const dnsOffset = Number(upnInfo.get('DnsDomainNameOffset'));

        const upn = data.subarray(upnOffset, upnOffset + upnLength).toString('utf16le');
        const dns = data.subarray(dnsOffset, dnsOffset + dnsLength).toString('utf16le');

        info(`    UPN: ${upn}`);
        info(`    DNS Domain: ${dns}`);
        info(`    Flags: 0x${flags.toString(16).padStart(8, '0')}`);
      }
    } catch (e) {
      logError(`    [!] Failed to parse UPN_DNS_INFO: ${(e as Error).message}`);
    }
  }

  private displayChecksum(data: Buffer, label: string): void {
    const sigData = new Pac.PAC_SIGNATURE_DATA(data);
    const signatureType = Number(sigData.get('SignatureType'));
    const signature = sigData.get('Signature') as Buffer;

    info(`    ${label} checksum type: ${formatChecksumType(signatureType)} (${signatureType})`);
    info(`    ${label} checksum: ${hexDump(signature)}`);
  }
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

function usage(): never {
  console.log(`Ticket describer. Parses ticket, decrypts the enc-part, and parses the PAC.

usage: describeTicket [-h] [-debug] [-ts]
                      [-p PASSWORD] [-hp HEXPASSWORD] [-u USER] [-d DOMAIN]
                      [-s SALT] [-rc4 RC4] [-aes HEXKEY]
                      [-asrep-key HEXKEY]
                      ticket

positional arguments:
  ticket                Path to the ticket.ccache file

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

ticket decryption credentials (optional):
  -p PASSWORD, --password PASSWORD
                        Cleartext password
  -hp HEXPASSWORD, --hex-password HEXPASSWORD
                        Hex password
  -u USER, --user USER  Service account name
  -d DOMAIN, --domain DOMAIN
                        FQDN Domain
  -s SALT, --salt SALT  Salt for key calculation
  --rc4 RC4             RC4 KEY / NT hash
  --aes HEXKEY          AES128 or AES256 key

PAC Credentials decryption material:
  --asrep-key HEXKEY    AS reply key for PAC Credentials decryption
`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = normalizeArgs(process.argv.slice(2));

  if (args.length === 0) {
    usage();
  }

  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        key: { type: 'string' },
        password: { type: 'string', short: 'p' },
        'hex-password': { type: 'string' },
        user: { type: 'string', short: 'u' },
        domain: { type: 'string', short: 'd' },
        salt: { type: 'string', short: 's' },
        rc4: { type: 'string' },
        aes: { type: 'string' },
        'asrep-key': { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        proxy: { type: 'string' },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
  }

  if (values.help || positionals.length < 1) {
    usage();
  }

  initProxy(values.proxy);

  const ticketPath = positionals[0]!;

  initLogger({ ts: values.ts, debug: values.debug });

  let key: Buffer | null = null;
  if (values.key) {
    key = Buffer.from(values.key, 'hex');
  } else if (values.rc4) {
    key = Buffer.from(values.rc4, 'hex');
  } else if (values.aes) {
    key = Buffer.from(values.aes, 'hex');
  } else if (values['asrep-key']) {
    key = Buffer.from(values['asrep-key'], 'hex');
  }
  if (key && key.length === 0) {
    logError('[!] Invalid key: must be a non-empty hex string');
    process.exit(1);
  }
  // Derive password and salt for key derivation when no explicit key is given
  let password: string | Buffer | null = null;
  let salt: string | null = null;

  if (!key) {
    if (values['hex-password']) {
      password = Buffer.from(values['hex-password'], 'hex');
    } else if (values.password) {
      password = values.password;
    }

    if (password !== null) {
      if (values.salt) {
        salt = values.salt;
      } else if (values.domain && values.user) {
        salt = values.domain.toUpperCase() + values.user;
      } else if (values.domain) {
        salt = values.domain.toUpperCase();
      }
      info(`[*] Will derive key from password (salt: ${salt ? `"${salt}"` : '<empty>'})`);
    }
  }

  if (key) {
    info(`[*] Using decryption key: ${key.toString('hex')}`);
  }

  const describer = new DescribeTicket(ticketPath, key, password, salt);
  await describer.run();
}

main().catch((e: unknown) => {
  logError(`[!] ${(e as Error).message}`);
  process.exit(1);
});
