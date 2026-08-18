/**
 * @impacket/dhcp - TypeScript port of impacket/dhcp.py
 *
 * BOOTP/DHCP protocol implementation.
 *   - DHCP: https://www.ietf.org/rfc/rfc2131.txt
 *   - DHCP Options: https://www.ietf.org/rfc/rfc1533.txt
 */

import { Buffer } from 'node:buffer';
import { Structure, type FieldDescriptor, type PackValue } from '@impacket/structure';

// ---------------------------------------------------------------------------
// BootpPacket
// ---------------------------------------------------------------------------

export class BootpPacket extends Structure {
  static override commonHdr: FieldDescriptor[] = [
    ['op',       'b'],
    ['htype',    'b=1'],
    ['hlen',     'b=len(chaddr)'],
    ['hops',     'b=0'],
    ['xid',      '!L=0'],
    ['secs',     '!H=0'],
    ['flags',    '!H=0'],
    ['ciaddr',   '!L=0'],
    ['yiaddr',   '!L=0'],
    ['siaddr',   '!L=0'],
    ['giaddr',   '!L=0'],
    ['_chaddr',  '16s=chaddr'],
    ['chaddr',   '_', '_chaddr[:hlen]'],
    ['sname',    '64s=""'],
    ['file',     '128s=""'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
  }
}

// ---------------------------------------------------------------------------
// DhcpPacket
// ---------------------------------------------------------------------------

/** DHCP option definition: [optionCode, formatString] */
type DhcpOptionDef = [number, string];

/** DHCP option name/value pair as returned by unpackOptions */
export type DhcpOption = [string | number, PackValue];

export class DhcpPacket extends Structure {
  static readonly MAGIC_NUMBER = 0x63825363;
  static readonly BOOTREQUEST  = 1;
  static readonly BOOTREPLY    = 2;

  static readonly DHCPDISCOVER = 1;
  static readonly DHCPOFFER    = 2;
  static readonly DHCPREQUEST  = 3;
  static readonly DHCPDECLINE  = 4;
  static readonly DHCPACK      = 5;
  static readonly DHCPNAK      = 6;
  static readonly DHCPRELEASE  = 7;
  static readonly DHCPINFORM   = 8;

  static readonly options: Record<string, DhcpOptionDef> = {
    // 3. Vendor Extensions
    'pad':                                [0,   '_'],
    'subnet-mask':                        [1,   '!L'],
    'time-offset':                        [2,   '!L'],
    'router':                             [3,   '*!L'],
    'time-server':                        [4,   '*!L'],
    'name-server':                        [5,   '*!L'],
    'domain-name-server':                 [6,   '*!L'],
    'log-server':                         [7,   '*!L'],
    'cookie-server':                      [8,   '*!L'],
    'lpr-server':                         [9,   '*!L'],
    'impress-server':                     [10,  '*!L'],
    'resource-locator-server':            [11,  '*!L'],
    'host-name':                          [12,  ':'],
    'boot-file-size':                     [13,  '!H'],
    'merit-dump-file':                    [14,  ':'],
    'domain-name':                        [15,  ':'],
    'swap-server':                        [16,  ':'],
    'root-path':                          [17,  ':'],
    'extensions-path':                    [18,  ':'],
    // 4. IP Layer Parameters per Host
    'ip-forwarding':                      [19,  'B'],
    'non-local-source-routing':           [20,  'B'],
    'policy-filter':                      [21,  '*!L'],
    'maximum-datagram-reassembly-size':   [22,  '!H'],
    'default-ip-ttl':                     [23,  'B'],
    'path-mtu-aging-timeout':             [24,  '!L'],
    'path-mtu-plateau-table':             [25,  '*!H'],
    // 5. IP Layer Parameters per Interface
    'interface-mtu':                      [26,  '!H'],
    'all-subnets-are-local':              [27,  'B'],
    'broadcast-address':                  [28,  '!L'],
    'perform-mask-discovery':             [29,  'B'],
    'mask-supplier':                      [30,  'B'],
    'perform-router-discovery':           [31,  'B'],
    'router-solicitation-address':        [32,  '!L'],
    'static-route':                       [33,  '*!L'],
    // 6. Link Layer Parameters per Interface
    'trailer-encapsulation':              [34,  'B'],
    'arp-cache-timeout':                  [35,  '!L'],
    'ethernet-encapsulation':             [36,  'B'],
    // 7. TCP parameters
    'tcp-default-ttl':                    [37,  'B'],
    'tcp-keepalive-interval':             [38,  '!L'],
    'tcp-keepalive-garbage':              [39,  'B'],
    // 8. Application and Service parameters
    'nis-domain':                         [40,  ':'],
    'nis-servers':                        [41,  '*!L'],
    'ntp-servers':                        [42,  '*!L'],
    'vendor-specific':                    [43,  ':'],
    'netbios-name-server':                [44,  '*!L'],
    'netbios-datagrame-distribution-server': [45, '*!L'],
    'netbios-node-type':                  [46,  'B'],
    'netbios-scope':                      [47,  ':'],
    'x11-font-server':                    [48,  '*!L'],
    'x11-display-manager':                [49,  '*!L'],
    // 9. DHCP Extensions
    'requested-ip':                       [50,  '!L'],
    'lease-time':                         [51,  '!L'],
    'option-overload':                    [52,  'B'],
    'message-type':                       [53,  'B'],
    'server-id':                          [54,  '!L'],
    'parameter-request-list':             [55,  ':'],
    'message':                            [56,  ':'],
    'maximum-dhcp-message-size':          [57,  '!H'],
    'renewal-time':                       [58,  '!L'],
    'rebinding-time':                     [59,  '!L'],
    'vendor-class':                       [60,  ':'],
    'client-id':                          [61,  ':'],
    // Other non-RFC1533 options
    'slp-directory-agent':                [78,  ':'],
    'slp-service-scope':                  [79,  ':'],
    'fully-qualified-domain-name':        [81,  ':'],
    'default-url':                        [114, ':'],
    'auto-configuration':                 [116, 'B'],
    'domain-search-list':                 [119, ':'],
    'classless-route-121':                [121, ':'],
    'classless-route-249':                [249, ':'],
    'proxy-autoconfig':                   [252, ':'],
    'eof':                                [255, '_'],
  };

  static override commonHdr: FieldDescriptor[] = [
    ['op',       'b'],
    ['htype',    'b=1'],
    ['hlen',     'b=len(chaddr)'],
    ['hops',     'b=0'],
    ['xid',      '!L=0'],
    ['secs',     '!H=0'],
    ['flags',    '!H=0'],
    ['ciaddr',   '!L=0'],
    ['yiaddr',   '!L=0'],
    ['siaddr',   '!L=0'],
    ['giaddr',   '!L=0'],
    ['_chaddr',  '16s=chaddr'],
    ['chaddr',   '_', '_chaddr[:hlen]'],
    ['sname',    '64s=""'],
    ['file',     '128s=""'],
  ];

  static override structure: FieldDescriptor[] = [
    ['cookie',    '!L'],
    ['_options',  ':=self.packOptions(options)'],
    ['options',   '_', 'self.unpackOptions(_options)'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
  }

  packOptions(options: DhcpOption[]): Buffer {
    let answer = Buffer.alloc(0);
    for (const [name, value] of options) {
      const optDef = DhcpPacket.options[name as string];
      if (!optDef) continue;
      const [code, format] = optDef;
      const val = this.pack(format, value);
      const header = Buffer.alloc(2);
      header[0] = code;
      header[1] = val.length;
      answer = Buffer.concat([answer, header, val]);
    }
    return answer;
  }

  getOptionNameAndFormat(optionCode: number): [string | number, string] {
    for (const k of Object.keys(DhcpPacket.options)) {
      const [code, format] = DhcpPacket.options[k]!;
      if (code === optionCode) return [k, format];
    }
    return [optionCode, ':'];
  }

  unpackOptions(optionsData: Buffer | PackValue): DhcpOption[] {
    const answer: DhcpOption[] = [];
    const opts = Buffer.isBuffer(optionsData)
      ? optionsData
      : Buffer.from(optionsData as Uint8Array);
    let i = 0;
    while (i < opts.length - 1) {
      const [name, format] = this.getOptionNameAndFormat(opts[i]!);
      const size = opts[i + 1]!;
      const value = this.unpack(format, opts.subarray(i + 2, i + 2 + size));
      answer.push([name, value]);
      i += 2 + size;
    }
    return answer;
  }

  unpackParameterRequestList(options: Buffer): (string | number)[] {
    const result: (string | number)[] = [];
    for (let i = 0; i < options.length; i++) {
      result.push(this.getOptionNameAndFormat(options[i]!)[0]);
    }
    return result;
  }

  isAskingForProxyAutodiscovery(): boolean {
    const opts = this.get('options') as DhcpOption[] | null;
    if (!opts) return false;
    for (const opt of opts) {
      if (opt[0] === 'parameter-request-list') {
        const optVal = opt[1];
        const buf = Buffer.isBuffer(optVal) ? optVal : Buffer.from(optVal as Uint8Array);
        for (let i = 0; i < buf.length; i++) {
          if (buf[i] === 252) return true;
        }
      }
    }
    return false;
  }

  getOptionValue(name: string): PackValue | null {
    const opts = this.get('options') as DhcpOption[] | null;
    if (!opts) return null;
    for (const opt of opts) {
      if (opt[0] === name) return opt[1];
    }
    return null;
  }
}
