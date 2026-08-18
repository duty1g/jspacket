/** @impacket/ntlm - NTLM crypto: hashes, DES, NTLMv1/v2 response computation ([MS-NLMP] 3.3). */

import { Buffer } from 'node:buffer';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { desEcbEncryptBlock, expandDesKey7, md4, rc4 } from '@impacket/crypto';
import { AV_PAIRS } from './avpairs.js';
import {
  KNOWN_DES_INPUT,
  NTLMSSP_AV_CHANNEL_BINDINGS,
  NTLMSSP_AV_DNS_HOSTNAME,
  NTLMSSP_AV_EOL,
  NTLMSSP_AV_TARGET_NAME,
  NTLMSSP_AV_TIME,
  NTLMSSP_NEGOTIATE_56,
  NTLMSSP_NEGOTIATE_128,
  NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
  NTLMSSP_NEGOTIATE_KEY_EXCH,
  NTLMSSP_NEGOTIATE_LM_KEY,
  NTLMSSP_NEGOTIATE_NTLM,
  NTLMSSP_NEGOTIATE_SEAL,
  NTLMSSP_NEGOTIATE_SIGN,
  NTLMSSP_NEGOTIATE_TARGET_INFO,
  NTLMSSP_NEGOTIATE_UNICODE,
  NTLMSSP_NEGOTIATE_VERSION,
  NTLMSSP_REQUEST_TARGET,
  TEST_CASE,
} from './constants.js';

/** Expand a 7-byte key into an 8-byte DES key (parity bits). */
function expandDesKey(key: Buffer): Buffer {
  return expandDesKey7(key);
}

function desBlock(key: Buffer, msg: Buffer): Buffer {
  return desEcbEncryptBlock(expandDesKey(key), msg);
}

/** [MS-NLMP] 3.3.1 - ntlmssp_DES_encrypt: DES-encrypt an 8-byte challenge with a 21-byte key. */
export function ntlmsspDesEncrypt(key: Buffer, challenge: Buffer): Buffer {
  let answer = desBlock(key.subarray(0, 7), challenge);
  answer = Buffer.concat([answer, desBlock(key.subarray(7, 14), challenge)]);
  answer = Buffer.concat([answer, desBlock(key.subarray(14, 21), challenge)]);
  return answer;
}

/** [MS-NLMP] 3.3.1 - get_ntlmv1_response. */
export function getNtlmv1Response(key: Buffer, challenge: Buffer): Buffer {
  return ntlmsspDesEncrypt(key, challenge);
}

export function hmacMd5(key: Buffer, data: Buffer): Buffer {
  return createHmac('md5', key).update(data).digest();
}

/** [MS-NLMP] 3.3.1 - compute_lmhash (Samba LM hash). */
export function computeLmhash(password: string): Buffer {
  try {
    Buffer.from(password, 'latin1');
  } catch {
    return Buffer.from('AAD3B435B51404EEAAD3B435B51404EE', 'hex');
  }
  const upper = password.toUpperCase();
  const p = Buffer.from(upper, 'latin1');
  let lmhash = desBlock(p.subarray(0, 7), KNOWN_DES_INPUT);
  lmhash = Buffer.concat([lmhash, desBlock(p.subarray(7, 14), KNOWN_DES_INPUT)]);
  return lmhash;
}

/** [MS-NLMP] 3.3.1 - compute_nthash (MD4 of UTF-16LE password). */
export function computeNthash(password: string): Buffer {
  return md4(Buffer.from(String(password), 'utf16le'));
}

/** [MS-NLMP] 3.3.1 - NTOWFv1. */
export function ntowfV1(
  password: string,
  _lmhash: Buffer | string = '',
  nthash: Buffer | string = '',
): Buffer {
  const nt = typeof nthash === 'string' ? Buffer.from(nthash, 'hex') : nthash;
  if (nt.length > 0) return nt;
  return computeNthash(password);
}

/** [MS-NLMP] 3.3.1 - LMOWFv1. */
export function lmowfV1(
  password: string,
  lmhash: Buffer | string = '',
  _nthash: Buffer | string = '',
): Buffer {
  const lm = typeof lmhash === 'string' ? Buffer.from(lmhash, 'hex') : lmhash;
  if (lm.length > 0) return lm;
  return computeLmhash(password);
}

/** [MS-NLMP] 3.3.1 - generateSessionKeyV1. */
export function generateSessionKeyV1(
  password: string,
  lmhash: Buffer | string,
  nthash: Buffer | string,
): Buffer {
  return md4(ntowfV1(password, lmhash, nthash));
}

/** [MS-NLMP] 3.3.2 - NTOWFv2. */
export function ntowfV2(
  user: string,
  password: string,
  domain: string,
  hash: Buffer | string = '',
): Buffer {
  const theHash =
    hash === ''
      ? computeNthash(password)
      : typeof hash === 'string'
        ? Buffer.from(hash, 'hex')
        : hash;
  return hmacMd5(
    theHash,
    Buffer.concat([Buffer.from(user.toUpperCase(), 'utf16le'), Buffer.from(domain, 'utf16le')]),
  );
}

/** [MS-NLMP] 3.3.2 - LMOWFv2 (same as NTOWFv2). */
export function lmowfV2(
  user: string,
  password: string,
  domain: string,
  lmhash: Buffer | string = '',
): Buffer {
  return ntowfV2(user, password, domain, lmhash);
}

/** [MS-NLMP] 3.3.2 - generateEncryptedSessionKey (RC4). */
export function generateEncryptedSessionKey(
  keyExchangeKey: Buffer,
  exportedSessionKey: Buffer,
): Buffer {
  return rc4(keyExchangeKey, exportedSessionKey);
}

/** [MS-NLMP] 3.2.5.1.2 / 3.2.5.2 - KXKEY. */
export function kxKey(
  flags: number,
  sessionBaseKey: Buffer,
  lmChallengeResponse: Buffer,
  serverChallenge: Buffer,
  password: string,
  lmhash: Buffer | string,
  _nthash: Buffer | string,
  useNtlmv2 = true,
): Buffer {
  if (useNtlmv2) return sessionBaseKey;
  if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
    if (flags & NTLMSSP_NEGOTIATE_NTLM)
      return hmacMd5(
        sessionBaseKey,
        Buffer.concat([serverChallenge, lmChallengeResponse.subarray(0, 8)]),
      );
    return sessionBaseKey;
  }
  if (flags & NTLMSSP_NEGOTIATE_NTLM) {
    if (flags & NTLMSSP_NEGOTIATE_LM_KEY) {
      const lm = lmowfV1(password, lmhash);
      const part1 = desBlock(lm.subarray(0, 7), lmChallengeResponse.subarray(0, 8));
      const part2Key = Buffer.concat([
        lm.subarray(7, 8),
        Buffer.from([0xbd, 0xbd, 0xbd, 0xbd, 0xbd, 0xbd]),
      ]);
      const part2 = desBlock(part2Key, lmChallengeResponse.subarray(0, 8));
      return Buffer.concat([part1, part2]);
    }
    if (flags & 0x00400000) {
      // NTLMSSP_REQUEST_NON_NT_SESSION_KEY
      const lm = lmowfV1(password, lmhash);
      return Buffer.concat([lm.subarray(0, 8), Buffer.alloc(8, 0)]);
    }
    return sessionBaseKey;
  }
  throw new Error("Can't create a valid KXKEY!");
}

/** [MS-NLMP] 3.3.1 - computeResponseNTLMv1. */
export function computeResponseNTLMv1(
  flags: number,
  serverChallenge: Buffer,
  clientChallenge: Buffer,
  _serverName: Buffer,
  _domain: string,
  _user: string,
  password: string,
  lmhash: Buffer | string = '',
  nthash: Buffer | string = '',
  _useNtlmv2 = true,
): [Buffer, Buffer, Buffer] {
  let lmResponse: Buffer;
  let ntResponse: Buffer;
  if (_user === '' && password === '') {
    lmResponse = Buffer.alloc(0);
    ntResponse = Buffer.alloc(0);
  } else {
    const lm = lmowfV1(password, lmhash, nthash);
    const nt = ntowfV1(password, lmhash, nthash);
    if (flags & NTLMSSP_NEGOTIATE_LM_KEY) {
      ntResponse = Buffer.alloc(0);
      lmResponse = getNtlmv1Response(lm, serverChallenge);
    } else if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
      const md5 = createHash('md5')
        .update(Buffer.concat([serverChallenge, clientChallenge]))
        .digest();
      ntResponse = ntlmsspDesEncrypt(nt, md5.subarray(0, 8));
      lmResponse = Buffer.concat([clientChallenge, Buffer.alloc(16, 0)]);
    } else {
      ntResponse = getNtlmv1Response(nt, serverChallenge);
      lmResponse = getNtlmv1Response(lm, serverChallenge);
    }
  }
  const sessionBaseKey = generateSessionKeyV1(password, lmhash, nthash);
  return [ntResponse, lmResponse, sessionBaseKey];
}

/** [MS-NLMP] 3.3.2 - computeResponseNTLMv2. */
export function computeResponseNTLMv2(
  _flags: number,
  serverChallenge: Buffer,
  clientChallenge: Buffer,
  serverName: Buffer,
  domain: string,
  user: string,
  password: string,
  _lmhash: Buffer | string = '',
  nthash: Buffer | string = '',
  _useNtlmv2 = true,
  channelBindingValue: Buffer = Buffer.alloc(0),
  service = 'cifs',
): [Buffer, Buffer, Buffer] {
  const responseServerVersion = Buffer.from([0x01]);
  const hiResponseServerVersion = Buffer.from([0x01]);
  const responseKeyNT = ntowfV2(user, password, domain, nthash);
  const avPairs = new AV_PAIRS(serverName);
  let aTime: Buffer;
  if (!TEST_CASE) {
    const dnsHost = avPairs.get(NTLMSSP_AV_DNS_HOSTNAME);
    if (dnsHost != null) {
      avPairs.set(
        NTLMSSP_AV_TARGET_NAME,
        Buffer.concat([Buffer.from(`${service}/`, 'utf16le'), dnsHost[1]]),
      );
    }
    const t = avPairs.get(NTLMSSP_AV_TIME);
    if (t != null) {
      aTime = t[1];
    } else {
      const b = Buffer.alloc(8);
      const unix100ns = BigInt(Math.floor(Date.now() / 1000)) * 10000000n + 116444736000000000n;
      b.writeBigInt64LE(unix100ns & 0xffffffffffffffffn, 0);
      aTime = b;
      avPairs.set(NTLMSSP_AV_TIME, aTime);
    }
    serverName = avPairs.getData();
  } else {
    aTime = Buffer.alloc(8, 0);
  }

  if (channelBindingValue.length > 0) {
    avPairs.set(NTLMSSP_AV_CHANNEL_BINDINGS, channelBindingValue);
  }

  let temp = responseServerVersion;
  temp = Buffer.concat([temp, hiResponseServerVersion]);
  temp = Buffer.concat([temp, Buffer.alloc(2, 0)]); // Reserved1
  temp = Buffer.concat([temp, Buffer.alloc(4, 0)]); // Reserved2
  temp = Buffer.concat([temp, aTime]); // TimeStamp
  temp = Buffer.concat([temp, clientChallenge]); // ChallengeFromClient
  temp = Buffer.concat([temp, Buffer.alloc(4, 0)]); // Reserved
  temp = Buffer.concat([temp, avPairs.getData()]); // AvPairs

  const ntProofStr = hmacMd5(responseKeyNT, Buffer.concat([serverChallenge, temp]));
  const ntChallengeResponse = Buffer.concat([ntProofStr, temp]);
  const lmChallengeResponse = Buffer.concat([
    hmacMd5(responseKeyNT, Buffer.concat([serverChallenge, clientChallenge])),
    clientChallenge,
  ]);
  const sessionBaseKey = hmacMd5(responseKeyNT, ntProofStr);

  if (user === '' && password === '') {
    return [Buffer.alloc(0), Buffer.alloc(0), sessionBaseKey];
  }
  return [ntChallengeResponse, lmChallengeResponse, sessionBaseKey];
}

/** Top-level dispatch matching impacket computeResponse. */
export function computeResponse(
  flags: number,
  serverChallenge: Buffer,
  clientChallenge: Buffer,
  serverName: Buffer,
  domain: string,
  user: string,
  password: string,
  lmhash: Buffer | string = '',
  nthash: Buffer | string = '',
  useNtlmv2 = true,
  channelBindingValue: Buffer = Buffer.alloc(0),
  service = 'cifs',
): [Buffer, Buffer, Buffer] {
  if (useNtlmv2) {
    return computeResponseNTLMv2(
      flags,
      serverChallenge,
      clientChallenge,
      serverName,
      domain,
      user,
      password,
      lmhash,
      nthash,
      useNtlmv2,
      channelBindingValue,
      service,
    );
  }
  return computeResponseNTLMv1(
    flags,
    serverChallenge,
    clientChallenge,
    serverName,
    domain,
    user,
    password,
    lmhash,
    nthash,
    useNtlmv2,
  );
}

/** [MS-NLMP] 3.4.5.1 - SIGNKEY. */
export function signKey(
  flags: number,
  randomSessionKey: Buffer,
  mode: 'Client' | 'Server' = 'Client',
): Buffer | null {
  if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
    const label =
      mode === 'Client'
        ? 'session key to client-to-server signing key magic constant\x00'
        : 'session key to server-to-client signing key magic constant\x00';
    return createHash('md5')
      .update(Buffer.concat([randomSessionKey, Buffer.from(label, 'latin1')]))
      .digest();
  }
  return null;
}

/** [MS-NLMP] 3.4.5.2 - SEALKEY. */
export function sealKey(
  flags: number,
  randomSessionKey: Buffer,
  mode: 'Client' | 'Server' = 'Client',
): Buffer {
  let sealKey: Buffer;
  if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
    if (flags & NTLMSSP_NEGOTIATE_128) sealKey = randomSessionKey;
    else if (flags & NTLMSSP_NEGOTIATE_56) sealKey = randomSessionKey.subarray(0, 7);
    else sealKey = randomSessionKey.subarray(0, 5);
    const label =
      mode === 'Client'
        ? 'session key to client-to-server sealing key magic constant\x00'
        : 'session key to server-to-client sealing key magic constant\x00';
    sealKey = createHash('md5')
      .update(Buffer.concat([sealKey, Buffer.from(label, 'latin1')]))
      .digest();
  } else if (flags & NTLMSSP_NEGOTIATE_56) {
    sealKey = Buffer.concat([randomSessionKey.subarray(0, 7), Buffer.from([0xa0])]);
  } else {
    sealKey = Buffer.concat([randomSessionKey.subarray(0, 5), Buffer.from([0xe5, 0x38, 0xb0])]);
  }
  return sealKey;
}

export interface NTLMMessageSignature {
  Version: number;
  Checksum: Buffer;
  SeqNum: number;
  getData(): Buffer;
}

export function NTLMMessageSignature(_flags: number): NTLMMessageSignature {
  const sig = {
    Version: 1,
    Checksum: Buffer.alloc(8, 0),
    SeqNum: 0,
    getData(): Buffer {
      const buf = Buffer.alloc(16);
      buf.writeUInt32LE(this.Version, 0);
      this.Checksum.copy(buf, 4, 0, 8);
      buf.writeUInt32LE(this.SeqNum, 12);
      return buf;
    },
  };
  return sig;
}

export function MAC(
  flags: number,
  handle: (data: Buffer) => Buffer,
  signingKey: Buffer,
  seqNum: number,
  message: Buffer,
): NTLMMessageSignature {
  const messageSignature = NTLMMessageSignature(flags);
  if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeInt32LE(seqNum, 0);
    const hmac = hmacMd5(signingKey, Buffer.concat([seqBuf, message]));
    messageSignature.Version = 1;
    messageSignature.Checksum = handle(hmac.subarray(0, 8));
    messageSignature.SeqNum = seqNum;
  } else {
    const crc = (crc32(message) & 0xffffffff) >>> 0;
    messageSignature.Version = 1;
    messageSignature.Checksum = Buffer.alloc(8, 0);
    messageSignature.Checksum.writeUInt32LE(crc, 0);
    messageSignature.SeqNum = 0;
  }
  return messageSignature;
}

export function SEAL(
  flags: number,
  signingKey: Buffer,
  _sealingKey: Buffer,
  messageToSign: Buffer,
  messageToEncrypt: Buffer,
  seqNum: number,
  handle: (data: Buffer) => Buffer,
): [Buffer, NTLMMessageSignature] {
  const sealedMessage = handle(messageToEncrypt);
  const signature = MAC(flags, handle, signingKey, seqNum, messageToSign);
  return [sealedMessage, signature];
}

export function SIGN(
  flags: number,
  signingKey: Buffer,
  message: Buffer,
  seqNum: number,
  handle: (data: Buffer) => Buffer,
): NTLMMessageSignature {
  return MAC(flags, handle, signingKey, seqNum, message);
}

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i]!;
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export { randomBytes };
