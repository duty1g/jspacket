import { Buffer } from 'node:buffer';
import { Data, Header } from '@impacket/impact';
import { ICMP6 } from '@impacket/icmp6';
import { IP6_Address } from '@impacket/ip6';

export class NDP extends ICMP6 {
  static override ROUTER_SOLICITATION = 133;
  static override ROUTER_ADVERTISEMENT = 134;
  static override NEIGHBOR_SOLICITATION = 135;
  static override NEIGHBOR_ADVERTISEMENT = 136;
  static REDIRECT = 137;

  appendNdpOption(ndpOption: Header): void {
    const childBytes = Buffer.from((this.child() as Header).getBytes());
    const optBytes = ndpOption.getBytes();
    (this.child() as Header).setBytes(Buffer.concat([childBytes, optBytes]));
  }

  static RouterSolicitation(): NDP {
    return NDP._buildMessage(NDP.ROUTER_SOLICITATION, Buffer.alloc(4));
  }

  static RouterAdvertisement(
    currentHopLimit: number,
    managedFlag: boolean,
    otherFlag: boolean,
    routerLifetime: number,
    reachableTime: number,
    retransmissionTimer: number,
  ): NDP {
    let flagByte = 0x00;
    if (managedFlag) flagByte |= 0x80;
    if (otherFlag) flagByte |= 0x40;

    const buf = Buffer.alloc(12);
    buf.writeUInt8(currentHopLimit, 0);
    buf.writeUInt8(flagByte, 1);
    buf.writeUInt16BE(routerLifetime, 2);
    buf.writeUInt32BE(reachableTime, 4);
    buf.writeUInt32BE(retransmissionTimer, 8);
    return NDP._buildMessage(NDP.ROUTER_ADVERTISEMENT, buf);
  }

  static override NeighborSolicitation(targetAddress: string | IP6_Address): NDP {
    const addr = typeof targetAddress === 'string' ? new IP6_Address(targetAddress) : targetAddress;
    const messageData = Buffer.concat([Buffer.alloc(4), addr.asBytes()]);
    return NDP._buildMessage(NDP.NEIGHBOR_SOLICITATION, messageData);
  }

  static NdpNeighborAdvertisement(
    routerFlag: boolean,
    solicitedFlag: boolean,
    overrideFlag: boolean,
    targetAddress: IP6_Address,
  ): NDP {
    let flagByte = 0x00;
    if (routerFlag) flagByte |= 0x80;
    if (solicitedFlag) flagByte |= 0x40;
    if (overrideFlag) flagByte |= 0x20;

    const messageData = Buffer.concat([
      Buffer.from([flagByte, 0x00, 0x00, 0x00]),
      targetAddress.asBytes(),
    ]);
    return NDP._buildMessage(NDP.NEIGHBOR_ADVERTISEMENT, messageData);
  }

  static NdpRedirect(targetAddress: IP6_Address, destinationAddress: IP6_Address): NDP {
    const messageData = Buffer.concat([
      Buffer.alloc(4),
      targetAddress.asBytes(),
      destinationAddress.asBytes(),
    ]);
    return NDP._buildMessage(NDP.REDIRECT, messageData);
  }

  private static _buildMessage(type: number, messageData: Buffer): NDP {
    const ndpPacket = new NDP();
    ndpPacket.setType(type);
    ndpPacket.setCode(0);

    const ndpPayload = new Data(messageData);
    ndpPacket.contains(ndpPayload);
    return ndpPacket;
  }
}

export class NDP_Option {
  static SOURCE_LINK_LAYER_ADDRESS = 1;
  static TARGET_LINK_LAYER_ADDRESS = 2;
  static PREFIX_INFORMATION = 3;
  static REDIRECTED_HEADER = 4;
  static MTU_OPTION = 5;

  static SourceLinkLayerAddress(linkLayerAddress: Buffer): Data {
    return NDP_Option._linkLayerAddress(NDP_Option.SOURCE_LINK_LAYER_ADDRESS, linkLayerAddress);
  }

  static TargetLinkLayerAddress(linkLayerAddress: Buffer): Data {
    return NDP_Option._linkLayerAddress(NDP_Option.TARGET_LINK_LAYER_ADDRESS, linkLayerAddress);
  }

  private static _linkLayerAddress(optionType: number, linkLayerAddress: Buffer): Data {
    const optionLength = Math.floor(linkLayerAddress.length / 8) + 1;
    return NDP_Option._buildOption(optionType, optionLength, linkLayerAddress);
  }

  static PrefixInformation(
    prefixLength: number,
    onLinkFlag: boolean,
    autonomousFlag: boolean,
    validLifetime: number,
    preferredLifetime: number,
    prefix: Buffer,
  ): Data {
    let flagByte = 0x00;
    if (onLinkFlag) flagByte |= 0x80;
    if (autonomousFlag) flagByte |= 0x40;

    const optionData = Buffer.alloc(10 + 4 + prefix.length);
    optionData.writeUInt8(prefixLength, 0);
    optionData.writeUInt8(flagByte, 1);
    optionData.writeUInt32BE(validLifetime, 2);
    optionData.writeUInt32BE(preferredLifetime, 6);
    optionData.writeUInt32BE(0, 10); // Reserved
    prefix.copy(optionData, 14);

    return NDP_Option._buildOption(NDP_Option.PREFIX_INFORMATION, 4, optionData);
  }

  static RedirectedHeader(originalPacket: Buffer): Data {
    const reserved = Buffer.alloc(6);
    const optionData = Buffer.concat([reserved, originalPacket]);
    const optionLength = Math.floor((optionData.length + 4) / 8);
    return NDP_Option._buildOption(NDP_Option.REDIRECTED_HEADER, optionLength, optionData);
  }

  static MTU(mtu: number): Data {
    const optionData = Buffer.alloc(6);
    optionData.writeUInt32BE(mtu, 2);
    return NDP_Option._buildOption(NDP_Option.MTU_OPTION, 1, optionData);
  }

  private static _buildOption(type: number, length: number, optionData: Buffer): Data {
    const header = Buffer.alloc(2);
    header.writeUInt8(type, 0);
    header.writeUInt8(length, 1);

    const ndpOption = new Data(Buffer.concat([header, optionData]));
    return ndpOption;
  }
}
