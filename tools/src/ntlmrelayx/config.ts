import type { TargetsProcessor } from './targets.js';

export interface ProtocolClientConstructor {
  new (config: NTLMRelayxConfig, target: URL, options?: { targetPort?: number; extendedSecurity?: boolean }): ProtocolClientInstance;
  PLUGIN_NAME: string;
}

export interface ProtocolClientInstance {
  initConnection(): Promise<boolean>;
  killConnection(): void;
  sendNegotiate(negotiateMessage: Buffer): Promise<any>;
  sendAuth(authenticateMessageBlob: Buffer, serverChallenge?: Buffer): Promise<[any, number]>;
  keepAlive(): Promise<void>;
  isAdmin(): Promise<string>;
  setClientId(): void;
  getStandardSecurityChallenge(): Buffer | null;
  session: any;
  sessionData: Record<string, any>;
  targetHost: string;
  targetPort: number;
  target: URL;
  client_id: number;
}

export interface ProtocolAttackConstructor {
  new (config: NTLMRelayxConfig, client: any, username: string, target?: URL, relayClient?: ProtocolClientInstance): ProtocolAttackInstance;
  PLUGIN_NAMES: string[];
}

export interface ProtocolAttackInstance {
  run(): Promise<void>;
}

export class NTLMRelayxConfig {
  interfaceIp: string | null = null;
  listeningPort: number | null = null;
  domainIp: string | null = null;
  machineAccount: string | null = null;
  machineHashes: string | null = null;
  target: TargetsProcessor | null = null;
  mode: 'RELAY' | 'REFLECTION' = 'RELAY';
  redirecthost: string | null = null;
  outputFile: string | null = null;
  dumpHashes = false;
  attacks: Record<string, ProtocolAttackConstructor> = {};
  lootdir = '.';
  randomtargets = false;
  encoding = 'utf-8';
  ipv6 = false;
  remove_mic = false;
  remove_sign_seal = false;
  disableMulti = false;
  keepRelaying = false;
  https = false;
  certfile: string | null = null;
  keyfile: string | null = null;
  command: string | null = null;
  serve_wpad = false;
  wpad_host: string | null = null;
  wpad_auth_num = 0;
  smb2support = false;
  exeFile: string | null = null;
  interactive = false;
  enumLocalAdmins = false;
  SMBServerChallenge: string | null = null;
  rpc_attack: string | null = null;
  rpc_mode = 'TSCH';
  rpc_use_smb = false;
  auth_smb = '';
  smblmhash = '';
  smbnthash = '';
  port_smb = 445;
  dumpdomain = true;
  addda = true;
  aclattack = true;
  validateprivs = true;
  escalateuser: string | null = null;
  queries: string[] = [];
  database: string | null = null;
  protocolClients: Record<string, ProtocolClientConstructor> = {};
  runSocks = false;
  socksServer: any = null;
  remove_target = false;
  serve_image = false;
  isADCSAttack = false;
  template: string | null = null;
  altName: string | null = null;
  altSid: string | null = null;
  enumTemplates = false;
  IsShadowCredentialsAttack = false;
  ShadowCredentialsTarget: string | null = null;
  ShadowCredentialsPFXPassword: string | null = null;
  ShadowCredentialsExportType: string | null = null;
  ShadowCredentialsOutfilePath: string | null = null;
  addComputerSMB: string[] | null = null;
  delegateaccess = false;
  dumplaps = false;
  dumpgmsa = false;
  dumpadcs = false;
  sid = false;
  adddnsrecord: string[] | null = null;
  dumpinfoattr = false;
  dumppre2k = false;

  setProtocolClients(clients: Record<string, ProtocolClientConstructor>): void {
    this.protocolClients = clients;
  }

  setAttacks(attacks: Record<string, ProtocolAttackConstructor>): void {
    this.attacks = attacks;
  }

  setTargets(target: TargetsProcessor): void {
    this.target = target;
  }

  setExploitOptions(removeMic: boolean, removeTarget: boolean, removeSignSeal = false): void {
    this.remove_mic = removeMic;
    this.remove_target = removeTarget;
    this.remove_sign_seal = removeSignSeal;
  }

  setLDAPOptions(opts: {
    dumpdomain?: boolean;
    addda?: boolean;
    aclattack?: boolean;
    validateprivs?: boolean;
    escalateuser?: string | null;
    addcomputer?: string[] | null;
    delegateaccess?: boolean;
    dumplaps?: boolean;
    dumpgmsa?: boolean;
    dumpadcs?: boolean;
    sid?: boolean;
    adddnsrecord?: string[] | null;
    dumpinfoattr?: boolean;
    dumppre2k?: boolean;
  }): void {
    if (opts.dumpdomain !== undefined) this.dumpdomain = opts.dumpdomain;
    if (opts.addda !== undefined) this.addda = opts.addda;
    if (opts.aclattack !== undefined) this.aclattack = opts.aclattack;
    if (opts.validateprivs !== undefined) this.validateprivs = opts.validateprivs;
    if (opts.escalateuser !== undefined) this.escalateuser = opts.escalateuser;
    if (opts.addcomputer !== undefined) this.addComputerSMB = opts.addcomputer;
    if (opts.delegateaccess !== undefined) this.delegateaccess = opts.delegateaccess;
    if (opts.dumplaps !== undefined) this.dumplaps = opts.dumplaps;
    if (opts.dumpgmsa !== undefined) this.dumpgmsa = opts.dumpgmsa;
    if (opts.dumpadcs !== undefined) this.dumpadcs = opts.dumpadcs;
    if (opts.sid !== undefined) this.sid = opts.sid;
    if (opts.adddnsrecord !== undefined) this.adddnsrecord = opts.adddnsrecord;
    if (opts.dumpinfoattr !== undefined) this.dumpinfoattr = opts.dumpinfoattr;
    if (opts.dumppre2k !== undefined) this.dumppre2k = opts.dumppre2k;
  }
}
