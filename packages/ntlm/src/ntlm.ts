/** @impacket/ntlm - high-level NTLMSSP helpers (getNTLMSSPType1 / getNTLMSSPType3). */

import { Buffer } from 'node:buffer';
import {
  NTLMSSP_NEGOTIATE_56,
  NTLMSSP_NEGOTIATE_128,
  NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
  NTLMSSP_NEGOTIATE_KEY_EXCH,
  NTLMSSP_NEGOTIATE_NTLM,
  NTLMSSP_NEGOTIATE_SEAL,
  NTLMSSP_NEGOTIATE_SIGN,
  NTLMSSP_NEGOTIATE_TARGET_INFO,
  NTLMSSP_NEGOTIATE_UNICODE,
  NTLMSSP_NEGOTIATE_VERSION,
  NTLMSSP_REQUEST_TARGET,
  USE_NTLMv2,
} from './constants.js';
import { computeResponse, generateEncryptedSessionKey, kxKey, randomBytes } from './crypto.js';
import { NTLMAuthChallenge, NTLMAuthChallengeResponse, NTLMAuthNegotiate } from './structures.js';

/** [MS-NLMP] 3.2.1 - build a Type 1 (NEGOTIATE) message. */
export function getNTLMSSPType1(
  workstation = '',
  _domain = '',
  signingRequired = false,
  useNtlmv2 = USE_NTLMv2,
  version: Buffer | null = null,
): NTLMAuthNegotiate {
  const auth = new NTLMAuthNegotiate();
  auth.set('flags', 0);
  let flags = Number(auth.get('flags'));
  if (signingRequired) {
    flags =
      NTLMSSP_NEGOTIATE_KEY_EXCH |
      NTLMSSP_NEGOTIATE_SIGN |
      NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
      NTLMSSP_NEGOTIATE_SEAL;
  }
  if (useNtlmv2) flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;
  flags |=
    NTLMSSP_NEGOTIATE_NTLM |
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
    NTLMSSP_NEGOTIATE_UNICODE |
    NTLMSSP_REQUEST_TARGET |
    NTLMSSP_NEGOTIATE_128 |
    NTLMSSP_NEGOTIATE_56;
  auth.set('flags', flags);
  if (version != null) {
    auth.set('flags', flags | NTLMSSP_NEGOTIATE_VERSION);
    auth.set('os_version', version);
  }
  auth.setWorkstation(workstation);
  return auth;
}

/** [MS-NLMP] 3.2.2 - build a Type 3 (AUTHENTICATE) message from a Type 1 + Type 2. */
export function getNTLMSSPType3(
  type1: NTLMAuthNegotiate,
  type2: Buffer,
  user: string,
  password: string,
  domain: string,
  lmhash: Buffer | string = '',
  nthash: Buffer | string = '',
  useNtlmv2 = USE_NTLMv2,
  channelBindingValue: Buffer = Buffer.alloc(0),
  service = 'cifs',
  version: Buffer | null = null,
): [NTLMAuthChallengeResponse, Buffer] {
  if (password == null) password = '';
  const ntlmChallenge = new NTLMAuthChallenge(type2);
  const responseFlags = Number(type1.get('flags'));
  const ntlmChallengeResponse = new NTLMAuthChallengeResponse(
    user,
    password,
    ntlmChallenge.get('challenge') as Buffer,
  );
  const clientChallenge = randomBytes(8);
  const serverName = ntlmChallenge.get('TargetInfoFields') as Buffer;

  const [ntResponse, lmResponse, sessionBaseKey] = computeResponse(
    Number(ntlmChallenge.get('flags')),
    ntlmChallenge.get('challenge') as Buffer,
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

  let rf = responseFlags;
  const cf = Number(ntlmChallenge.get('flags'));
  if ((cf & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) === 0)
    rf &= 0xffffffff ^ NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
  if ((cf & NTLMSSP_NEGOTIATE_128) === 0) rf &= 0xffffffff ^ NTLMSSP_NEGOTIATE_128;
  if ((cf & NTLMSSP_NEGOTIATE_KEY_EXCH) === 0) rf &= 0xffffffff ^ NTLMSSP_NEGOTIATE_KEY_EXCH;
  if ((cf & NTLMSSP_NEGOTIATE_SEAL) === 0) rf &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SEAL;
  if ((cf & NTLMSSP_NEGOTIATE_SIGN) === 0) rf &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SIGN;
  if ((cf & NTLMSSP_NEGOTIATE_ALWAYS_SIGN) === 0) rf &= 0xffffffff ^ NTLMSSP_NEGOTIATE_ALWAYS_SIGN;

  let keyExchangeKey = kxKey(
    cf,
    sessionBaseKey,
    lmResponse,
    ntlmChallenge.get('challenge') as Buffer,
    password,
    lmhash,
    nthash,
    useNtlmv2,
  );

  if (user === '' && password === '' && lmhash === '' && nthash === '') {
    keyExchangeKey = Buffer.alloc(16, 0);
  }

  let exportedSessionKey: Buffer;
  let encryptedRandomSessionKey: Buffer | null = null;
  if (cf & NTLMSSP_NEGOTIATE_KEY_EXCH) {
    exportedSessionKey = randomBytes(16);
    encryptedRandomSessionKey = generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey);
  } else {
    exportedSessionKey = keyExchangeKey;
  }

  ntlmChallengeResponse.set('flags', rf);
  ntlmChallengeResponse.set('domain_name', Buffer.from(domain, 'utf16le'));
  ntlmChallengeResponse.set('host_name', Buffer.from(type1.getWorkstation(), 'utf16le'));
  if (lmResponse.length === 0) ntlmChallengeResponse.set('lanman', Buffer.from([0]));
  else ntlmChallengeResponse.set('lanman', lmResponse);
  if (version != null) ntlmChallengeResponse.set('Version', version);
  ntlmChallengeResponse.set('ntlm', ntResponse);
  if (encryptedRandomSessionKey != null)
    ntlmChallengeResponse.set('session_key', encryptedRandomSessionKey);

  return [ntlmChallengeResponse, exportedSessionKey];
}
