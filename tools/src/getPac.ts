#!/usr/bin/env node
/**
 * Impacket-js - getPac
 *
 * This script will get the PAC of the specified target user just having a
 * normal authenticated user's credentials. It does so by using a mix of
 * [MS-SFU]'s S4USelf + User to User Kerberos Authentication.
 *
 * Original idea (or accidental discovery :) ) of adding U2U capabilities
 * inside a S4USelf by Benjamin Delpy (@gentilkiwi).
 *
 * References:
 *   - U2U: https://tools.ietf.org/html/draft-ietf-cat-user2user-02
 *   - [MS-SFU]: https://msdn.microsoft.com/en-us/library/cc246071.aspx
 *
 * Python implementation by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { createHash, createHmac } from 'node:crypto';
import { parseArgs } from 'node:util';

import {
  parseIdentity,
  init as initLogger,
  initProxy,
  error as logError,
  debug as logDebug,
  getLevel,
  LogLevel,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import {
  KerberosV5,
  Types,
  Constants,
  Asn1,
  Crypto,
  Pac,
} from '@impacket/krb5';

import {
  type AnyValue,
  type Asn1Sequence,
  Asn1SequenceOf,
  parseTLV,
  parseTLVs,
  TagClass,
} from '@impacket/asn1';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Extract the raw DER bytes of the ticket field ([5]) from a KDC-REP
 * (AS-REP or TGS-REP) so it can be set on an Asn1 Ticket node via _rawData.
 */
function extractRawTicket(kdcRepBytes: Buffer): Buffer {
  let tlv = parseTLV(kdcRepBytes);
  // Unwrap APPLICATION tag (AS-REP=11, TGS-REP=13)
  if (tlv.cls === TagClass.APPLICATION) tlv = parseTLV(tlv.value);
  // Inside the SEQUENCE, find context tag [5] (ticket)
  const inner = parseTLVs(tlv.value);
  for (const t of inner) {
    if (t.cls === TagClass.CONTEXT && t.tag === 5) {
      return t.value;
    }
  }
  throw new Error('Ticket not found in KDC-REP');
}

function buildPrincipalName(type: number, components: string[]): Asn1Sequence {
  return Asn1.principalToAsn1({ type, components });
}

function hexdump(data: Buffer): void {
  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.subarray(i, i + 16);
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ')
      .padEnd(16 * 3 - 1, ' ');
    const ascii = Array.from(chunk)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'))
      .join('');
    console.log(`${i.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`);
  }
}

function formatSid(sid: unknown): string {
  if (sid && typeof sid === 'object' && 'formatCanonical' in sid) {
    return (sid as { formatCanonical(): string }).formatCanonical();
  }
  return String(sid);
}

// ---------------------------------------------------------------------------
// S4U2SELF
// ---------------------------------------------------------------------------

class S4U2SELF {
  private username: string;
  private password: string;
  private domain: string;
  private behalfUser: string;
  private lmhash: string;
  private nthash: string;
  private kdcHost: string | null;

  constructor(
    behalfUser: string,
    username: string,
    password: string,
    domain: string,
    lmhash: string,
    nthash: string,
    kdcHost: string | null = null,
  ) {
    this.behalfUser = behalfUser;
    this.username = username;
    this.password = password;
    this.domain = domain.toUpperCase();
    this.lmhash = lmhash;
    this.nthash = nthash;
    this.kdcHost = kdcHost;
  }

  private printPac(data: Buffer): void {
    const isDebug = getLevel() === LogLevel.DEBUG;

    // Decode the decrypted EncTicketPart
    const encTicketPart = Asn1.EncTicketPart();
    encTicketPart.decode(data);

    // authorization-data[0]['ad-data'] wraps an AD-IF-RELEVANT sequence
    const authData = encTicketPart.get('authorization-data') as unknown;
    const adEntries: unknown[] = Array.isArray(authData) ? authData : [authData];
    const firstAd = adEntries[0];
    const firstAdData = this.getAdData(firstAd);

    const adIfRelevant = Asn1.AD_IF_RELEVANT();
    adIfRelevant.decode(firstAdData);
    const ifRelItems = (adIfRelevant.items ?? []) as unknown[];
    const pacRaw = this.getAdData(ifRelItems[0]);

    // So here we have the PAC
    const pacType = new Pac.PACTYPE(pacRaw);
    const cBuffers = Number(pacType.get('cBuffers'));
    const buffersData = pacType.get('Buffers') as Buffer;
    const infoBufferSize = 16; // PAC_INFO_BUFFER is 16 bytes (L + L + Q)

    for (let i = 0; i < cBuffers; i++) {
      const ibData = buffersData.subarray(i * infoBufferSize, (i + 1) * infoBufferSize);
      const infoBuffer = new Pac.PAC_INFO_BUFFER(ibData);
      const ulType = Number(infoBuffer.get('ulType'));
      const cbBufferSize = Number(infoBuffer.get('cbBufferSize'));
      const offset = Number(infoBuffer.get('Offset'));

      // Slice the buffer contents out of the full PAC blob
      const bufData = pacRaw.subarray(offset, offset + cbBufferSize);

      if (isDebug) {
        console.log(`TYPE 0x${ulType.toString(16)}`);
      }

      if (ulType === Pac.PAC_LOGON_INFO) {
        this.printLogonInfo(bufData);
      } else if (ulType === Pac.PAC_CLIENT_INFO_TYPE) {
        if (isDebug) {
          const clientInfo = new Pac.PAC_CLIENT_INFO(bufData);
          console.log(clientInfo.dump ? clientInfo.dump() : clientInfo);
          console.log();
        }
      } else if (ulType === Pac.PAC_SERVER_CHECKSUM) {
        if (isDebug) {
          const sig = new Pac.PAC_SIGNATURE_DATA(bufData);
          this.dumpSignature(sig);
        }
      } else if (ulType === Pac.PAC_PRIVSVR_CHECKSUM) {
        if (isDebug) {
          const sig = new Pac.PAC_SIGNATURE_DATA(bufData);
          this.dumpSignature(sig);
        }
      } else if (ulType === Pac.PAC_UPN_DNS_INFO) {
        if (isDebug) {
          this.dumpUpnDnsInfo(bufData);
        }
      } else {
        hexdump(bufData);
      }

      if (isDebug) {
        console.log('#'.repeat(80));
      }
    }
  }

  private getAdData(entry: unknown): Buffer {
    if (entry && typeof entry === 'object' && 'values' in entry) {
      const vals = (entry as { values: Record<string, AnyValue> }).values;
      return vals['ad-data'] as Buffer;
    }
    const vals = entry as Record<string, AnyValue>;
    return vals['ad-data'] as Buffer;
  }

  private printLogonInfo(data: Buffer): void {
    // I'm skipping here the ReferentID for the pointer; VALIDATION_INFO wraps
    // TypeSerialization1 + PKERB_VALIDATION_INFO and mirrors impacket's
    // TypeSerialization1(data) + KERB_VALIDATION_INFO.fromString flow.
    const validationInfo = new Pac.VALIDATION_INFO(data);
    const kerbValInfo = validationInfo.get('Data') as unknown;

    let logonInfo: { get(key: string): unknown };
    if (kerbValInfo && typeof kerbValInfo === 'object' && 'get' in kerbValInfo) {
      logonInfo = kerbValInfo as { get(key: string): unknown };
    } else {
      console.log('(Unable to parse KERB_VALIDATION_INFO)');
      return;
    }

    console.log(`EffectiveName: ${logonInfo.get('EffectiveName') ?? ''}`);
    console.log(`FullName: ${logonInfo.get('FullName') ?? ''}`);
    console.log(`LogonServer: ${logonInfo.get('LogonServer') ?? ''}`);
    console.log(`LogonDomainName: ${logonInfo.get('LogonDomainName') ?? ''}`);
    console.log(`UserId: ${logonInfo.get('UserId')}`);
    console.log(`PrimaryGroupId: ${logonInfo.get('PrimaryGroupId')}`);

    const uac = logonInfo.get('UserAccountControl');
    if (typeof uac === 'number') {
      console.log(`UserAccountControl: 0x${(uac >>> 0).toString(16).padStart(8, '0')}`);
    }

    const groupCount = Number(logonInfo.get('GroupCount') ?? 0);
    const groupIds = logonInfo.get('GroupIds');
    if (groupCount > 0 && groupIds) {
      const groups = Array.isArray(groupIds) ? groupIds : [];
      console.log(`Groups (${groupCount}):`);
      for (const g of groups) {
        if (g && typeof g === 'object' && 'get' in g) {
          const gObj = g as { get(key: string): unknown };
          console.log(
            `  RID: ${gObj.get('RelativeId')}, Attributes: 0x${(Number(gObj.get('Attributes')) >>> 0).toString(16)}`,
          );
        }
      }
    }

    const sidCount = Number(logonInfo.get('SidCount') ?? 0);
    const extraSids = logonInfo.get('ExtraSids');
    if (sidCount > 0 && extraSids) {
      const sids = Array.isArray(extraSids) ? extraSids : [];
      console.log(`ExtraSids (${sidCount}):`);
      for (const s of sids) {
        if (s && typeof s === 'object' && 'get' in s) {
          const sObj = s as { get(key: string): unknown };
          console.log(
            `  SID: ${formatSid(sObj.get('Sid'))}, Attributes: 0x${(Number(sObj.get('Attributes') ?? 0) >>> 0).toString(16)}`,
          );
        }
      }
    }

    console.log();
    console.log(`Domain SID: ${formatSid(logonInfo.get('LogonDomainId'))}`);
    console.log();
  }

  private dumpSignature(sig: InstanceType<typeof Pac.PAC_SIGNATURE_DATA>): void {
    const sigType = Number(sig.get('SignatureType'));
    const signature = sig.get('Signature') as Buffer;
    console.log(`SignatureType: ${sigType}`);
    console.log(`Signature: ${signature.toString('hex')}`);
    console.log();
  }

  private dumpUpnDnsInfo(data: Buffer): void {
    const upnInfo = new Pac.UPN_DNS_INFO(data.subarray(0, 12));
    const upnLength = Number(upnInfo.get('UpnLength'));
    const upnOffset = Number(upnInfo.get('UpnOffset'));
    const dnsLength = Number(upnInfo.get('DnsDomainNameLength'));
    const dnsOffset = Number(upnInfo.get('DnsDomainNameOffset'));
    const upn = data.subarray(upnOffset, upnOffset + upnLength).toString('utf16le');
    const dns = data.subarray(dnsOffset, dnsOffset + dnsLength).toString('utf16le');
    console.log(`UPN: ${upn}`);
    console.log(`DNS Domain: ${dns}`);
    console.log();
  }

  /**
   * Build the PA-FOR-USER padata structure with the HMAC-MD5 checksum for
   * the S4U2Self request, exactly as impacket does.
   */
  private buildPAForUser(sessionKey: Crypto.Key): Buffer {
    const behalfPrincipal = new Types.Principal(
      this.behalfUser,
      null,
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );

    const paForUser = Asn1.PA_FOR_USER_ENC();
    paForUser.set(
      'userName',
      buildPrincipalName(behalfPrincipal.type, behalfPrincipal.components),
    );
    paForUser.set('userRealm', this.domain);
    paForUser.set('auth-package', 'Kerberos');

    // S4UByteArray = struct.pack('<I', NT_PRINCIPAL) + behalfUser + domain + 'Kerberos'
    const nameTypeLE = Buffer.alloc(4);
    nameTypeLE.writeInt32LE(Constants.PrincipalNameType.NT_PRINCIPAL, 0);
    const s4uByteArray = Buffer.concat([
      nameTypeLE,
      Buffer.from(this.behalfUser, 'utf8'),
      Buffer.from(this.domain, 'utf8'),
      Buffer.from('Kerberos', 'utf8'),
    ]);

    if (getLevel() === LogLevel.DEBUG) {
      logDebug('S4UByteArray');
      hexdump(s4uByteArray);
    }

    // cksum = KERB_CHECKSUM_HMAC_MD5(sessionKey, msg-type=17, S4UByteArray)
    // For HMAC-MD5 the keyed checksum is:
    //   Ksign = HMAC-MD5(key, "signaturekey\0")
    //   tmp   = MD5( LE32(keyusage) || text )
    //   mac   = HMAC-MD5(Ksign, tmp)
    const ksign = createHmac('md5', sessionKey.contents)
      .update(Buffer.from('signaturekey\x00', 'binary'))
      .digest();
    const usageBuf = Buffer.alloc(4);
    usageBuf.writeUInt32LE(17, 0);
    const tmp = createHash('md5').update(Buffer.concat([usageBuf, s4uByteArray])).digest();
    const checkSum = createHmac('md5', ksign).update(tmp).digest();

    if (getLevel() === LogLevel.DEBUG) {
      logDebug('CheckSum');
      hexdump(checkSum);
    }

    const cksum = Asn1.Checksum();
    cksum.set('cksumtype', Constants.ChecksumTypes.hmac_md5);
    cksum.set('checksum', checkSum);
    paForUser.set('cksum', cksum);

    return paForUser.encode();
  }

  /**
   * Build the AP-REQ (PA-TGS-REQ) authenticator, encrypted with the TGT
   * session key (key usage 7).
   */
  private buildApReq(
    tgt: Buffer,
    cipher: Crypto.EnctypeProfile,
    sessionKey: Crypto.Key,
  ): Buffer {
    const asRep = Asn1.AS_REP();
    asRep.decode(tgt);
    const decodedTGT = asRep.values;

    const ticketNode = Asn1.Ticket();
    ticketNode._rawData = extractRawTicket(tgt);

    const apReq = Asn1.AP_REQ();
    apReq.set('pvno', 5);
    apReq.set('msg-type', Constants.ApplicationTagNumbers.AP_REQ);
    Asn1.seqSetFlags(apReq, 'ap-options', []);
    apReq.set('ticket', ticketNode);

    const authenticator = Asn1.Authenticator();
    authenticator.set('authenticator-vno', 5);
    authenticator.set('crealm', decodedTGT.crealm as string);

    const cname = decodedTGT.cname as Record<string, AnyValue>;
    const cnameType = Number(cname['name-type']);
    const cnameItems = cname['name-string'] as unknown as { value: string }[];
    const cnameStrings = cnameItems.map((i) => i.value);
    authenticator.set('cname', buildPrincipalName(cnameType, cnameStrings));

    const now = new Date();
    authenticator.set('cusec', now.getUTCMilliseconds() * 1000);
    authenticator.set('ctime', now);

    const encodedAuthenticator = authenticator.encode();
    const encrypted = cipher.encrypt(sessionKey, 7, encodedAuthenticator, null);

    const encPart = Asn1.EncryptedData();
    encPart.set('etype', cipher.enctype);
    encPart.set('cipher', encrypted);
    apReq.set('authenticator', encPart);

    return apReq.encode();
  }

  async dump(): Promise<void> {
    const userName = new Types.Principal(
      this.username,
      null,
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );

    // Step 1: get a TGT for our own credentials
    const tgtResult = await KerberosV5.getKerberosTGT(
      userName,
      this.password,
      this.domain,
      this.lmhash,
      this.nthash,
      '',
      this.kdcHost,
    );

    const tgt = tgtResult.tgt;
    const cipher = tgtResult.cipher;
    const sessionKey = tgtResult.sessionKey;

    // Build the PA-TGS-REQ (AP-REQ)
    const encodedApReq = this.buildApReq(tgt, cipher, sessionKey);

    // Build the PA-FOR-USER for the target (impersonated) user
    const encodedPaForUser = this.buildPAForUser(sessionKey);

    // Build the TGS-REQ
    const tgsReq = Asn1.TGS_REQ();
    tgsReq.set('pvno', 5);
    tgsReq.set('msg-type', Constants.ApplicationTagNumbers.TGS_REQ);

    const padataSeq = new Asn1SequenceOf(Asn1.PA_DATA());
    const paTgs = Asn1.PA_DATA();
    paTgs.set('padata-type', Constants.PreAuthenticationDataTypes.PA_TGS_REQ);
    paTgs.set('padata-value', encodedApReq);
    padataSeq.add(paTgs);

    const paUser = Asn1.PA_DATA();
    paUser.set('padata-type', Constants.PreAuthenticationDataTypes.PA_FOR_USER);
    paUser.set('padata-value', encodedPaForUser);
    padataSeq.add(paUser);

    tgsReq.set('padata', padataSeq);

    const reqBody = Asn1.KDC_REQ_BODY();
    Asn1.seqSetFlags(reqBody, 'kdc-options', [
      Constants.KDCOptions.forwardable,
      Constants.KDCOptions.renewable,
      Constants.KDCOptions.renewable_ok,
      Constants.KDCOptions.canonicalize,
      Constants.KDCOptions.enc_tkt_in_skey,
    ]);

    // sname is our own service principal (NT_UNKNOWN)
    const serverName = new Types.Principal(
      this.username,
      null,
      Constants.PrincipalNameType.NT_UNKNOWN,
    );
    reqBody.set('sname', buildPrincipalName(serverName.type, serverName.components));

    // realm = crealm of the TGT
    const asRep = Asn1.AS_REP();
    asRep.decode(tgt);
    reqBody.set('realm', asRep.values.crealm as string);

    const till = new Date(Date.now() + 86400000);
    reqBody.set('till', till);
    reqBody.set('nonce', Math.floor(Math.random() * 0x7fffffff));

    const etypeSeq = new Asn1SequenceOf(new Asn1.Int32());
    etypeSeq.add(new Asn1.Int32(Constants.EncryptionTypes.aes256_cts_hmac_sha1_96));
    etypeSeq.add(new Asn1.Int32(Constants.EncryptionTypes.aes128_cts_hmac_sha1_96));
    etypeSeq.add(new Asn1.Int32(cipher.enctype));
    etypeSeq.add(new Asn1.Int32(Constants.EncryptionTypes.rc4_hmac));
    reqBody.set('etype', etypeSeq);

    // additional-tickets = [our own TGT ticket] (enables U2U inside S4USelf)
    const additionalTicketSeq = new Asn1SequenceOf(Asn1.Ticket());
    const addlTicketNode = Asn1.Ticket();
    addlTicketNode._rawData = extractRawTicket(tgt);
    additionalTicketSeq.add(addlTicketNode);
    reqBody.set('additional-tickets', additionalTicketSeq);

    tgsReq.set('req-body', reqBody);

    const message = tgsReq.encode();

    // Send/receive against the KDC (resolved from the domain)
    const response = await KerberosV5.sendReceive(message, this.domain, this.kdcHost);

    // Decode the TGS-REP (may be a KRB_ERROR)
    const tgsRep = Asn1.TGS_REP();
    try {
      tgsRep.decode(response);
    } catch {
      const krbErr = Asn1.KRB_ERROR();
      krbErr.decode(response);
      throw new KerberosV5.KerberosError({ packet: krbErr.values });
    }

    const ticketPart = tgsRep.values.ticket as Record<string, AnyValue>;
    const encPart = ticketPart['enc-part'] as Record<string, AnyValue>;
    const cipherText = encPart['cipher'] as Buffer;
    const ticketEtype = Number(encPart['etype']);

    // Key Usage 2: AS-REP/TGS-REP Ticket enc-part.
    // For plain U2U the ticket is encrypted with the service key; for the
    // S4USelf + U2U case (ours) it is encrypted with our TGT session key.
    let plainText: Buffer;
    try {
      if (this.nthash !== '') {
        const newCipher = Crypto._get_enctype_profile(ticketEtype);
        const key = new Crypto.Key(ticketEtype, Buffer.from(this.nthash, 'hex'));
        plainText = newCipher.decrypt(key, 2, cipherText);
      } else {
        throw new Error('no service key');
      }
    } catch {
      // S4USelf + U2U uses the TGT session key
      plainText = cipher.decrypt(sessionKey, 2, cipherText);
    }

    this.printPac(plainText);
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage(): never {
  console.log(`usage: getPac [-h] -targetUser TARGETUSER [-debug] [-ts]
              [-hashes LMHASH:NTHASH]
              credentials

positional arguments:
  credentials           domain/username[:password]. Valid domain credentials
                        to use for grabbing targetUser's PAC

options:
  -h, --help            show this help message and exit
  -targetUser TARGETUSER
                        the target user to retrieve the PAC of
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
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
        targetUser: { type: 'string' },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'dc-ip': { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
  }

  if (values.help || positionals.length < 1 || !values.targetUser) {
    usage();
  }

  initProxy(values.proxy);

  const credentials = positionals[0]!;

  initLogger({ ts: values.ts, debug: values.debug });

  const identity = parseIdentity(credentials, { hashes: values.hashes });

  try {
    const dumper = new S4U2SELF(
      values.targetUser!,
      identity.username,
      identity.password,
      identity.domain,
      identity.lmhash,
      identity.nthash,
      values['dc-ip'] ?? null,
    );
    await dumper.dump();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    if (e instanceof KerberosV5.KerberosError) {
      logError(e.message);
    } else {
      logError(String(e));
    }
  }
}

main();
