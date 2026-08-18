/**
 * @impacket/pcap - TypeScript port of impacket/pcapfile.py and pcap_linktypes.py
 *
 * PCAP file format parser/writer and link-type constants.
 */

import { Buffer } from 'node:buffer';
import * as fs from 'node:fs';
import { Structure, type FieldDescriptor } from '@impacket/structure';

// ── Layer offsets ────────────────────────────────────────────────────────────

export const O_ETH = 0;
export const O_IP = 1;
export const O_ARP = 1;
export const O_UDP = 2;
export const O_TCP = 2;
export const O_ICMP = 2;
export const O_UDP_DATA = 3;
export const O_ICMP_DATA = 3;

// ── PCAP file magic ─────────────────────────────────────────────────────────

/** PCAP magic number (0xA1B2C3D4 little-endian) as a Structure quote-format string. */
export const MAGIC = '"\xD4\xC3\xB2\xA1';

// ── Structures ──────────────────────────────────────────────────────────────

export class PCapFileHeader extends Structure {
  static override structure: FieldDescriptor[] = [
    ['magic', MAGIC],
    ['versionMajor', '<H=2'],
    ['versionMinor', '<H=4'],
    ['GMT2localCorrection', '<l=0'],
    ['timeAccuracy', '<L=0'],
    ['maxLength', '<L=0xffff'],
    ['linkType', '<L=1'],
    ['packets', '*:=[]'],
  ];
}

export class PCapFilePacket extends Structure {
  static override structure: FieldDescriptor[] = [
    ['tsec', '<L=0'],
    ['tmsec', '<L=0'],
    ['savedLength', '<L-data'],
    ['realLength', '<L-data'],
    ['data', ':'],
  ];

  constructor(data?: Buffer | null, alignment?: number) {
    super(data, alignment);
    this.set('data', Buffer.alloc(0));
  }
}

// ── PcapFile ────────────────────────────────────────────────────────────────

export class PcapFile {
  private fd: number | null = null;
  private position = 0;
  private hdr: PCapFileHeader | null = null;
  private wroteHeader = false;

  constructor(fileName?: string | null, mode = 'rb') {
    if (fileName != null) {
      const flags = mode.includes('w') ? 'w+' : mode.includes('a') ? 'a+' : 'r';
      this.fd = fs.openSync(fileName, flags);
    }
  }

  reset(): void {
    this.hdr = null;
    this.position = 0;
  }

  close(): void {
    if (this.fd != null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
  }

  fileno(): number {
    if (this.fd == null) throw new Error('No file descriptor');
    return this.fd;
  }

  setFile(fd: number): void {
    this.fd = fd;
    this.position = 0;
  }

  setSnapLen(snapLen: number): void {
    this.createHeaderOnce();
    this.hdr!.set('maxLength', snapLen);
  }

  getSnapLen(): number {
    this.readHeaderOnce();
    return this.hdr!.get('maxLength') as number;
  }

  setLinkType(linkType: number): void {
    this.createHeaderOnce();
    this.hdr!.set('linkType', linkType);
  }

  getLinkType(): number {
    this.readHeaderOnce();
    return this.hdr!.get('linkType') as number;
  }

  readHeaderOnce(): void {
    if (this.hdr == null) {
      this.hdr = PCapFileHeader.fromFile(this.makeReader()) as PCapFileHeader;
    }
  }

  createHeaderOnce(): void {
    if (this.hdr == null) {
      this.hdr = new PCapFileHeader();
    }
  }

  writeHeaderOnce(): void {
    if (!this.wroteHeader) {
      this.wroteHeader = true;
      this.position = 0;
      this.createHeaderOnce();
      this.fileWrite(this.hdr!.getData());
    }
  }

  read(): PCapFilePacket | null {
    this.readHeaderOnce();
    try {
      const pkt = PCapFilePacket.fromFile(this.makeReader()) as PCapFilePacket;
      const savedLength = pkt.get('savedLength') as number;
      pkt.set('data', this.fileRead(savedLength));
      return pkt;
    } catch {
      return null;
    }
  }

  write(pkt: PCapFilePacket): void {
    this.writeHeaderOnce();
    this.fileWrite(pkt.getData());
  }

  *packets(): Generator<PCapFilePacket> {
    this.reset();
    while (true) {
      const answer = this.read();
      if (answer == null) break;
      yield answer;
    }
  }

  // ── Internal file I/O ─────────────────────────────────────────────────

  private makeReader(): (n: number) => Buffer {
    return (n: number): Buffer => this.fileRead(n);
  }

  private fileRead(n: number): Buffer {
    if (this.fd == null) throw new Error('No file descriptor');
    const buf = Buffer.alloc(n);
    const bytesRead = fs.readSync(this.fd, buf, 0, n, this.position);
    this.position += bytesRead;
    return buf.subarray(0, bytesRead);
  }

  private fileWrite(data: Buffer): void {
    if (this.fd == null) throw new Error('No file descriptor');
    fs.writeSync(this.fd, data, 0, data.length, this.position);
    this.position += data.length;
  }
}

// ── Link-type constants (pcap_linktypes.py) ──────────────────────────────────

export const LINKTYPE_NULL = 0;
export const DLT_NULL = LINKTYPE_NULL;
export const LINKTYPE_ETHERNET = 1;
export const DLT_EN10MB = LINKTYPE_ETHERNET;
export const LINKTYPE_AX25 = 3;
export const DLT_AX25 = LINKTYPE_AX25;
export const NKTYPE_IEEE802_5 = 6;
export const DLT_IEEE802 = NKTYPE_IEEE802_5;
export const LINKTYPE_ARCNET_BSD = 7;
export const DLT_ARCNET = LINKTYPE_ARCNET_BSD;
export const LINKTYPE_SLIP = 8;
export const DLT_SLIP = LINKTYPE_SLIP;
export const LINKTYPE_PPP = 9;
export const DLT_PPP = LINKTYPE_PPP;
export const LINKTYPE_FDDI = 10;
export const DLT_FDDI = LINKTYPE_FDDI;
export const LINKTYPE_PPP_HDLC = 50;
export const DLT_PPP_SERIAL = LINKTYPE_PPP_HDLC;
export const LINKTYPE_PPP_ETHER = 51;
export const DLT_PPP_ETHER = LINKTYPE_PPP_ETHER;
export const LINKTYPE_ATM_RFC1483 = 100;
export const DLT_ATM_RFC1483 = LINKTYPE_ATM_RFC1483;
export const LINKTYPE_RAW = 101;
export const DLT_RAW = LINKTYPE_RAW;
export const LINKTYPE_C_HDLC = 104;
export const DLT_C_HDLC = LINKTYPE_C_HDLC;
export const LINKTYPE_IEEE802_11 = 105;
export const DLT_IEEE802_11 = LINKTYPE_IEEE802_11;
export const LINKTYPE_FRELAY = 107;
export const DLT_FRELAY = LINKTYPE_FRELAY;
export const LINKTYPE_LOOP = 108;
export const DLT_LOOP = LINKTYPE_LOOP;
export const LINKTYPE_LINUX_SLL = 113;
export const DLT_LINUX_SLL = LINKTYPE_LINUX_SLL;
export const LINKTYPE_LTALK = 114;
export const DLT_LTALK = LINKTYPE_LTALK;
export const LINKTYPE_PFLOG = 117;
export const DLT_PFLOG = LINKTYPE_PFLOG;
export const LINKTYPE_IEEE802_11_PRISM = 119;
export const DLT_PRISM_HEADER = LINKTYPE_IEEE802_11_PRISM;
export const LINKTYPE_IP_OVER_FC = 122;
export const DLT_IP_OVER_FC = LINKTYPE_IP_OVER_FC;
export const LINKTYPE_SUNATM = 123;
export const DLT_SUNATM = LINKTYPE_SUNATM;
export const LINKTYPE_IEEE802_11_RADIOTAP = 127;
export const DLT_IEEE802_11_RADIO = LINKTYPE_IEEE802_11_RADIOTAP;
export const LINKTYPE_ARCNET_LINUX = 129;
export const DLT_ARCNET_LINUX = LINKTYPE_ARCNET_LINUX;
export const LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138;
export const DLT_APPLE_IP_OVER_IEEE1394 = LINKTYPE_APPLE_IP_OVER_IEEE1394;
export const LINKTYPE_MTP2_WITH_PHDR = 139;
export const DLT_MTP2_WITH_PHDR = LINKTYPE_MTP2_WITH_PHDR;
export const LINKTYPE_MTP2 = 140;
export const DLT_MTP2 = LINKTYPE_MTP2;
export const LINKTYPE_MTP3 = 141;
export const DLT_MTP3 = LINKTYPE_MTP3;
export const LINKTYPE_SCCP = 142;
export const DLT_SCCP = LINKTYPE_SCCP;
export const LINKTYPE_DOCSIS = 143;
export const DLT_DOCSIS = LINKTYPE_DOCSIS;
export const LINKTYPE_LINUX_IRDA = 144;
export const DLT_LINUX_IRDA = LINKTYPE_LINUX_IRDA;
export const LINKTYPE_IEEE802_11_AVS = 163;
export const DLT_IEEE802_11_RADIO_AVS = LINKTYPE_IEEE802_11_AVS;
export const LINKTYPE_BACNET_MS_TP = 165;
export const DLT_BACNET_MS_TP = LINKTYPE_BACNET_MS_TP;
export const LINKTYPE_PPP_PPPD = 166;
export const DLT_PPP_PPPD = LINKTYPE_PPP_PPPD;
export const LINKTYPE_GPRS_LLC = 169;
export const DLT_GPRS_LLC = LINKTYPE_GPRS_LLC;
export const LINKTYPE_LINUX_LAPD = 177;
export const DLT_LINUX_LAPD = LINKTYPE_LINUX_LAPD;
export const LINKTYPE_BLUETOOTH_HCI_H4 = 187;
export const DLT_BLUETOOTH_HCI_H4 = LINKTYPE_BLUETOOTH_HCI_H4;
export const LINKTYPE_USB_LINUX = 189;
export const DLT_USB_LINUX = LINKTYPE_USB_LINUX;
export const LINKTYPE_PPI = 192;
export const DLT_PPI = LINKTYPE_PPI;
export const LINKTYPE_IEEE802_15_4 = 195;
export const DLT_IEEE802_15_4 = LINKTYPE_IEEE802_15_4;
export const LINKTYPE_SITA = 196;
export const DLT_SITA = LINKTYPE_SITA;
export const LINKTYPE_ERF = 197;
export const DLT_ERF = LINKTYPE_ERF;
export const LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201;
export const DLT_BLUETOOTH_HCI_H4_WITH_PHDR = LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR;
export const LINKTYPE_AX25_KISS = 202;
export const DLT_AX25_KISS = LINKTYPE_AX25_KISS;
export const LINKTYPE_LAPD = 203;
export const DLT_LAPD = LINKTYPE_LAPD;
export const LINKTYPE_PPP_WITH_DIR = 204;
export const DLT_PPP_WITH_DIR = LINKTYPE_PPP_WITH_DIR;
export const LINKTYPE_C_HDLC_WITH_DIR = 205;
export const DLT_C_HDLC_WITH_DIR = LINKTYPE_C_HDLC_WITH_DIR;
export const LINKTYPE_FRELAY_WITH_DIR = 206;
export const DLT_FRELAY_WITH_DIR = LINKTYPE_FRELAY_WITH_DIR;
export const LINKTYPE_IPMB_LINUX = 209;
export const DLT_IPMB_LINUX = LINKTYPE_IPMB_LINUX;
export const LINKTYPE_IEEE802_15_4_NONASK_PHY = 215;
export const DLT_IEEE802_15_4_NONASK_PHY = LINKTYPE_IEEE802_15_4_NONASK_PHY;
export const LINKTYPE_USB_LINUX_MMAPPED = 220;
export const DLT_USB_LINUX_MMAPPED = LINKTYPE_USB_LINUX_MMAPPED;
export const LINKTYPE_FC_2 = 224;
export const DLT_FC_2 = LINKTYPE_FC_2;
export const LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225;
export const DLT_FC_2_WITH_FRAME_DELIMS = LINKTYPE_FC_2_WITH_FRAME_DELIMS;
export const LINKTYPE_IPNET = 226;
export const DLT_IPNET = LINKTYPE_IPNET;
export const LINKTYPE_CAN_SOCKETCAN = 227;
export const DLT_CAN_SOCKETCAN = LINKTYPE_CAN_SOCKETCAN;
export const LINKTYPE_IPV4 = 228;
export const DLT_IPV4 = LINKTYPE_IPV4;
export const LINKTYPE_IPV6 = 229;
export const DLT_IPV6 = LINKTYPE_IPV6;
export const LINKTYPE_IEEE802_15_4_NOFCS = 230;
export const DLT_IEEE802_15_4_NOFCS = LINKTYPE_IEEE802_15_4_NOFCS;
export const LINKTYPE_DBUS = 231;
export const DLT_DBUS = LINKTYPE_DBUS;
export const LINKTYPE_DVB_CI = 235;
export const DLT_DVB_CI = LINKTYPE_DVB_CI;
export const LINKTYPE_MUX27010 = 236;
export const DLT_MUX27010 = LINKTYPE_MUX27010;
export const LINKTYPE_STANAG_5066_D_PDU = 237;
export const DLT_STANAG_5066_D_PDU = LINKTYPE_STANAG_5066_D_PDU;
export const LINKTYPE_NFLOG = 239;
export const DLT_NFLOG = LINKTYPE_NFLOG;
export const LINKTYPE_NETANALYZER = 240;
export const DLT_NETANALYZER = LINKTYPE_NETANALYZER;
export const LINKTYPE_NETANALYZER_TRANSPARENT = 241;
export const DLT_NETANALYZER_TRANSPARENT = LINKTYPE_NETANALYZER_TRANSPARENT;
export const LINKTYPE_IPOIB = 242;
export const DLT_IPOIB = LINKTYPE_IPOIB;
export const LINKTYPE_MPEG_2_TS = 243;
export const DLT_MPEG_2_TS = LINKTYPE_MPEG_2_TS;
export const LINKTYPE_NG40 = 244;
export const DLT_NG40 = LINKTYPE_NG40;
export const LINKTYPE_NFC_LLCP = 245;
export const DLT_NFC_LLCP = LINKTYPE_NFC_LLCP;
export const LINKTYPE_INFINIBAND = 247;
export const DLT_INFINIBAND = LINKTYPE_INFINIBAND;
export const LINKTYPE_SCTP = 248;
export const DLT_SCTP = LINKTYPE_SCTP;
export const LINKTYPE_USBPCAP = 249;
export const DLT_USBPCAP = LINKTYPE_USBPCAP;
export const LINKTYPE_RTAC_SERIAL = 250;
export const DLT_RTAC_SERIAL = LINKTYPE_RTAC_SERIAL;
export const LINKTYPE_BLUETOOTH_LE_LL = 251;
export const DLT_BLUETOOTH_LE_LL = LINKTYPE_BLUETOOTH_LE_LL;
export const LINKTYPE_NETLINK = 253;
export const DLT_NETLINK = LINKTYPE_NETLINK;
export const LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254;
export const DLT_BLUETOOTH_LINUX_MONITOR = LINKTYPE_BLUETOOTH_LINUX_MONITOR;
export const LINKTYPE_BLUETOOTH_BREDR_BB = 255;
export const DLT_BLUETOOTH_BREDR_BB = LINKTYPE_BLUETOOTH_BREDR_BB;
export const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256;
export const DLT_BLUETOOTH_LE_LL_WITH_PHDR = LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR;
export const LINKTYPE_PROFIBUS_DL = 257;
export const DLT_PROFIBUS_DL = LINKTYPE_PROFIBUS_DL;
export const LINKTYPE_PKTAP = 258;
export const DLT_PKTAP = LINKTYPE_PKTAP;
export const LINKTYPE_EPON = 259;
export const DLT_EPON = LINKTYPE_EPON;
export const LINKTYPE_IPMI_HPM_2 = 260;
export const DLT_IPMI_HPM_2 = LINKTYPE_IPMI_HPM_2;
