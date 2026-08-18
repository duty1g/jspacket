/** @impacket/ntlm - NTLMSSP message structures ([MS-NLMP] 2.2.2). */

import { Buffer } from 'node:buffer';
import { type FieldDescriptor, Structure } from '@impacket/structure';
import type { AV_PAIRS } from './avpairs.js';
import {
  NTLMSSP_NEGOTIATE_128,
  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
  NTLMSSP_NEGOTIATE_KEY_EXCH,
  NTLMSSP_NEGOTIATE_NTLM,
  NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED,
  NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
  NTLMSSP_NEGOTIATE_SEAL,
  NTLMSSP_NEGOTIATE_SIGN,
  NTLMSSP_NEGOTIATE_TARGET_INFO,
  NTLMSSP_NEGOTIATE_UNICODE,
  NTLMSSP_NEGOTIATE_VERSION,
} from './constants.js';

/** [MS-NLMP] 2.2.2.10 VERSION */
export class VERSION extends Structure {
  static NTLMSSP_REVISION_W2K3 = 0x0f;
  static structure: FieldDescriptor[] = [
    ['ProductMajorVersion', '<B=0'],
    ['ProductMinorVersion', '<B=0'],
    ['ProductBuild', '<H=0'],
    ['Reserved', '3s=""'],
    ['NTLMRevisionCurrent', '<B=self.NTLMSSP_REVISION_W2K3'],
  ];
}

/** [MS-NLMP] 2.2.1.1 NEGOTIATE_MESSAGE */
export class NTLMAuthNegotiate extends Structure {
  static structure: FieldDescriptor[] = [
    ['', '"NTLMSSP\x00'],
    ['message_type', '<L=1'],
    ['flags', '<L'],
    ['domain_len', '<H-domain_name'],
    ['domain_max_len', '<H-domain_name'],
    ['domain_offset', '<L=0'],
    ['host_len', '<H-host_name'],
    ['host_maxlen', '<H-host_name'],
    ['host_offset', '<L=0'],
    ['os_version', ':'],
    ['host_name', ':'],
    ['domain_name', ':'],
  ];

  _workstation = '';

  constructor(data?: Buffer) {
    if (data) {
      super(data);
      return;
    }
    super();
    this.set(
      'flags',
      NTLMSSP_NEGOTIATE_128 |
        NTLMSSP_NEGOTIATE_KEY_EXCH |
        NTLMSSP_NEGOTIATE_NTLM |
        NTLMSSP_NEGOTIATE_UNICODE |
        NTLMSSP_NEGOTIATE_SIGN |
        NTLMSSP_NEGOTIATE_SEAL |
        0,
    );
    this.set('host_name', Buffer.alloc(0));
    this.set('domain_name', Buffer.alloc(0));
    this.set('os_version', Buffer.alloc(0));
  }

  setWorkstation(w: string): void {
    this._workstation = w;
  }

  getWorkstation(): string {
    return this._workstation;
  }

  hasNegotiateVersion(): boolean {
    return (Number(this.get('flags')) & NTLMSSP_NEGOTIATE_VERSION) === NTLMSSP_NEGOTIATE_VERSION;
  }

  getData(): Buffer {
    const host = this.get('host_name') as Buffer;
    const domain = this.get('domain_name') as Buffer;
    let flags = Number(this.get('flags'));
    if (host.length > 0) flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
    if (domain.length > 0) flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
    const versionLen = (this.get('os_version') as Buffer).length;
    if (versionLen > 0) flags |= NTLMSSP_NEGOTIATE_VERSION;
    else if (this.hasNegotiateVersion())
      throw new Error(
        'Must provide the os_version field if the NTLMSSP_NEGOTIATE_VERSION flag is set',
      );
    this.set('flags', flags);
    if (flags & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED)
      this.set('host_offset', 32 + versionLen);
    if (flags & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED)
      this.set('domain_offset', 32 + host.length + versionLen);
    return Structure.prototype.getData.call(this);
  }

  fromString(data: Buffer): this {
    super.fromString(data);
    const domainOffset = Number(this.get('domain_offset'));
    const domainEnd = domainOffset + Number(this.get('domain_len'));
    this.set('domain_name', data.subarray(domainOffset, domainEnd));
    const hostOffset = Number(this.get('host_offset'));
    const hostEnd = hostOffset + Number(this.get('host_len'));
    this.set('host_name', data.subarray(hostOffset, hostEnd));
    if (data.length >= 36 && this.hasNegotiateVersion())
      this.set('os_version', new VERSION(data.subarray(32)));
    else this.set('os_version', Buffer.alloc(0));
    return this;
  }
}

/** [MS-NLMP] 2.2.1.2 CHALLENGE_MESSAGE */
export class NTLMAuthChallenge extends Structure {
  static structure: FieldDescriptor[] = [
    ['', '"NTLMSSP\x00'],
    ['message_type', '<L=2'],
    ['domain_len', '<H-domain_name'],
    ['domain_max_len', '<H-domain_name'],
    ['domain_offset', '<L=40'],
    ['flags', '<L=0'],
    ['challenge', '8s'],
    ['reserved', '8s=""'],
    ['TargetInfoFields_len', '<H-TargetInfoFields'],
    ['TargetInfoFields_max_len', '<H-TargetInfoFields'],
    ['TargetInfoFields_offset', '<L'],
    ['VersionLen', '_-Version', 'self.constructor.checkVersion(self["flags"])'],
    ['Version', ':'],
    ['domain_name', ':'],
    ['TargetInfoFields', ':'],
  ];

  static checkVersion(flags: number | undefined): number {
    if (flags != null && (flags & NTLMSSP_NEGOTIATE_VERSION) === 0) return 0;
    return 8;
  }

  getData(): Buffer {
    const ti = this.get('TargetInfoFields');
    if (ti != null && !(ti instanceof Buffer)) {
      const raw = (ti as AV_PAIRS).getData();
      this.set('TargetInfoFields', raw);
    }
    const flags = (this.get('flags') as number) ?? 0;
    const versionLen = NTLMAuthChallenge.checkVersion(flags);
    if (versionLen === 0 && this.get('Version') == null) {
      this.set('Version', Buffer.alloc(0));
    }
    const domainName = this.get('domain_name') as Buffer | string;
    const domainLen = domainName ? (Buffer.isBuffer(domainName) ? domainName.length : Buffer.from(domainName, 'latin1').length) : 0;
    // Fixed header: 48 bytes + Version
    const domainOffset = 48 + versionLen;
    this.set('domain_offset', domainOffset);
    this.set('TargetInfoFields_offset', domainOffset + domainLen);
    return Structure.prototype.getData.call(this);
  }

  fromString(data: Buffer): this {
    super.fromString(data);
    const domainOffset = Number(this.get('domain_offset'));
    const domainLen = Number(this.get('domain_len'));
    this.set('domain_name', data.subarray(domainOffset, domainOffset + domainLen));
    const tiOffset = Number(this.get('TargetInfoFields_offset'));
    const tiLen = Number(this.get('TargetInfoFields_len'));
    this.set('TargetInfoFields', data.subarray(tiOffset, tiOffset + tiLen));
    return this;
  }
}

/** [MS-NLMP] 2.2.1.3 AUTHENTICATE_MESSAGE */
export class NTLMAuthChallengeResponse extends Structure {
  static structure: FieldDescriptor[] = [
    ['', '"NTLMSSP\x00'],
    ['message_type', '<L=3'],
    ['lanman_len', '<H-lanman'],
    ['lanman_max_len', '<H-lanman'],
    ['lanman_offset', '<L'],
    ['ntlm_len', '<H-ntlm'],
    ['ntlm_max_len', '<H-ntlm'],
    ['ntlm_offset', '<L'],
    ['domain_len', '<H-domain_name'],
    ['domain_max_len', '<H-domain_name'],
    ['domain_offset', '<L'],
    ['user_len', '<H-user_name'],
    ['user_max_len', '<H-user_name'],
    ['user_offset', '<L'],
    ['host_len', '<H-host_name'],
    ['host_max_len', '<H-host_name'],
    ['host_offset', '<L'],
    ['session_key_len', '<H-session_key'],
    ['session_key_max_len', '<H-session_key'],
    ['session_key_offset', '<L'],
    ['flags', '<L'],
    ['VersionLen', '_-Version', 'self.constructor.checkVersion(self["flags"])'],
    ['Version', ':=""'],
    ['MICLen', '_-MIC', 'self.constructor.checkMIC(self["flags"])'],
    ['MIC', ':=""'],
    ['domain_name', ':'],
    ['user_name', ':'],
    ['host_name', ':'],
    ['lanman', ':'],
    ['ntlm', ':'],
    ['session_key', ':'],
  ];

  constructor(
    username = '',
    _password = '',
    challenge: Buffer | string = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
    _flags = 0,
  ) {
    super();
    this.set('session_key', Buffer.alloc(0));
    this.set('user_name', Buffer.from(username, 'utf16le'));
    this.set('domain_name', Buffer.alloc(0));
    this.set('host_name', Buffer.alloc(0));
    this.set(
      'flags',
      NTLMSSP_NEGOTIATE_128 |
        NTLMSSP_NEGOTIATE_KEY_EXCH |
        NTLMSSP_NEGOTIATE_NTLM |
        NTLMSSP_NEGOTIATE_UNICODE |
        NTLMSSP_NEGOTIATE_SIGN |
        NTLMSSP_NEGOTIATE_SEAL |
        0,
    );
    const ch = typeof challenge === 'string' ? Buffer.from(challenge) : challenge;
    const lm = typeof lmhash === 'string' ? Buffer.from(lmhash, 'hex') : lmhash;
    const nt = typeof nthash === 'string' ? Buffer.from(nthash, 'hex') : nthash;
    if (username && (lm.length > 0 || nt.length > 0)) {
      this.set('lanman', getNtlmv1Response(lm, ch));
      this.set('ntlm', getNtlmv1Response(nt, ch));
    } else {
      this.set('lanman', Buffer.alloc(0));
      this.set('ntlm', Buffer.alloc(0));
      if (!(this.get('host_name') as Buffer).length)
        this.set('host_name', Buffer.from('NULL', 'utf16le'));
    }
  }

  static checkVersion(flags: number | undefined): number {
    if (flags != null && (flags & NTLMSSP_NEGOTIATE_VERSION) === 0) return 0;
    return 8;
  }

  static checkMIC(flags: number | undefined): number {
    if (flags != null && (flags & NTLMSSP_NEGOTIATE_VERSION) === 0) return 0;
    return 16;
  }

  getData(): Buffer {
    const flags = Number(this.get('flags'));
    const mic = NTLMAuthChallengeResponse.checkMIC(flags);
    const ver = NTLMAuthChallengeResponse.checkVersion(flags);
    const base = 64 + mic + ver;
    this.set('domain_offset', base);
    this.set('user_offset', base + (this.get('domain_name') as Buffer).length);
    this.set(
      'host_offset',
      Number(this.get('user_offset')) + (this.get('user_name') as Buffer).length,
    );
    this.set(
      'lanman_offset',
      Number(this.get('host_offset')) + (this.get('host_name') as Buffer).length,
    );
    this.set(
      'ntlm_offset',
      Number(this.get('lanman_offset')) + (this.get('lanman') as Buffer).length,
    );
    this.set(
      'session_key_offset',
      Number(this.get('ntlm_offset')) + (this.get('ntlm') as Buffer).length,
    );
    return Structure.prototype.getData.call(this);
  }

  fromString(data: Buffer): this {
    super.fromString(data);
    const dOff = Number(this.get('domain_offset'));
    this.set('domain_name', data.subarray(dOff, dOff + Number(this.get('domain_len'))));
    const hOff = Number(this.get('host_offset'));
    this.set('host_name', data.subarray(hOff, hOff + Number(this.get('host_len'))));
    const uOff = Number(this.get('user_offset'));
    this.set('user_name', data.subarray(uOff, uOff + Number(this.get('user_len'))));
    const nOff = Number(this.get('ntlm_offset'));
    this.set('ntlm', data.subarray(nOff, nOff + Number(this.get('ntlm_len'))));
    const lOff = Number(this.get('lanman_offset'));
    this.set('lanman', data.subarray(lOff, lOff + Number(this.get('lanman_len'))));
    return this;
  }

  getUserString(): string {
    const flags = Number(this.get('flags'));
    const unicode = (flags & NTLMSSP_NEGOTIATE_UNICODE) !== 0;
    const userBuf = this.get('user_name') as Buffer;
    const domainBuf = this.get('domain_name') as Buffer;
    let user = unicode ? userBuf.toString('utf16le') : userBuf.toString('latin1');
    let domain = unicode ? domainBuf.toString('utf16le') : domainBuf.toString('latin1');
    if (!domain && user.includes('@')) {
      const idx = user.lastIndexOf('@');
      domain = user.slice(idx + 1);
      user = user.slice(0, idx);
    }
    return `${domain}/${user}`.toUpperCase();
  }
}

// Forward import to avoid circular dep at module load time
import { getNtlmv1Response } from './crypto.js';
