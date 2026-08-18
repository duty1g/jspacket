import { Buffer } from 'node:buffer';
import { Header, Data } from '@impacket/impact';
import { IP6_Address } from '@impacket/ip6';

type IcmpMessageEntry = [number, string, Record<number, string> | null];

export class ICMP6 extends Header {
  static IP_PROTOCOL_NUMBER = 58;
  static protocol = 58;
  static HEADER_SIZE = 4;

  static DESTINATION_UNREACHABLE = 1;
  static PACKET_TOO_BIG = 2;
  static TIME_EXCEEDED = 3;
  static PARAMETER_PROBLEM = 4;
  static ECHO_REQUEST = 128;
  static ECHO_REPLY = 129;
  static ROUTER_SOLICITATION = 133;
  static ROUTER_ADVERTISEMENT = 134;
  static NEIGHBOR_SOLICITATION = 135;
  static NEIGHBOR_ADVERTISEMENT = 136;
  static REDIRECT_MESSAGE = 137;
  static NODE_INFORMATION_QUERY = 139;
  static NODE_INFORMATION_REPLY = 140;

  static NO_ROUTE_TO_DESTINATION = 0;
  static ADMINISTRATIVELY_PROHIBITED = 1;
  static BEYOND_SCOPE_OF_SOURCE_ADDRESS = 2;
  static ADDRESS_UNREACHABLE = 3;
  static PORT_UNREACHABLE = 4;
  static SOURCE_ADDRESS_FAILED_INGRESS_EGRESS_POLICY = 5;
  static REJECT_ROUTE_TO_DESTINATION = 6;

  static HOP_LIMIT_EXCEEDED_IN_TRANSIT = 0;
  static FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1;

  static ERRONEOUS_HEADER_FIELD_ENCOUNTERED = 0;
  static UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED = 1;
  static UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED = 2;

  static NODE_INFORMATION_QUERY_IPV6 = 0;
  static NODE_INFORMATION_QUERY_NAME_OR_EMPTY = 1;
  static NODE_INFORMATION_QUERY_IPV4 = 2;
  static NODE_INFORMATION_REPLY_SUCCESS = 0;
  static NODE_INFORMATION_REPLY_REFUSED = 1;
  static NODE_INFORMATION_REPLY_UNKNOWN_QTYPE = 2;

  static NODE_INFORMATION_QTYPE_NOOP = 0;
  static NODE_INFORMATION_QTYPE_UNUSED = 1;
  static NODE_INFORMATION_QTYPE_NODENAME = 2;
  static NODE_INFORMATION_QTYPE_NODEADDRS = 3;
  static NODE_INFORMATION_QTYPE_IPv4ADDRS = 4;

  static ERROR_MESSAGE = 0;
  static INFORMATIONAL_MESSAGE = 1;

  static MSG_TYPE_INDEX = 0;
  static DESCRIPTION_INDEX = 1;
  static CODES_INDEX = 2;

  static icmpMessages: Record<number, IcmpMessageEntry> = {
    [ICMP6.DESTINATION_UNREACHABLE]: [ICMP6.ERROR_MESSAGE, 'Destination unreachable', {
      [ICMP6.NO_ROUTE_TO_DESTINATION]: 'No route to destination',
      [ICMP6.ADMINISTRATIVELY_PROHIBITED]: 'Administratively prohibited',
      [ICMP6.BEYOND_SCOPE_OF_SOURCE_ADDRESS]: 'Beyond scope of source address',
      [ICMP6.ADDRESS_UNREACHABLE]: 'Address unreachable',
      [ICMP6.PORT_UNREACHABLE]: 'Port unreachable',
      [ICMP6.SOURCE_ADDRESS_FAILED_INGRESS_EGRESS_POLICY]: 'Source address failed ingress/egress policy',
      [ICMP6.REJECT_ROUTE_TO_DESTINATION]: 'Reject route to destination',
    }],
    [ICMP6.PACKET_TOO_BIG]: [ICMP6.ERROR_MESSAGE, 'Packet too big', null],
    [ICMP6.TIME_EXCEEDED]: [ICMP6.ERROR_MESSAGE, 'Time exceeded', {
      [ICMP6.HOP_LIMIT_EXCEEDED_IN_TRANSIT]: 'Hop limit exceeded in transit',
      [ICMP6.FRAGMENT_REASSEMBLY_TIME_EXCEEDED]: 'Fragment reassembly time exceeded',
    }],
    [ICMP6.PARAMETER_PROBLEM]: [ICMP6.ERROR_MESSAGE, 'Parameter problem', {
      [ICMP6.ERRONEOUS_HEADER_FIELD_ENCOUNTERED]: 'Erroneous header field encountered',
      [ICMP6.UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED]: 'Unrecognized Next Header type encountered',
      [ICMP6.UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED]: 'Unrecognized IPv6 Option Encountered',
    }],
    [ICMP6.ECHO_REQUEST]: [ICMP6.INFORMATIONAL_MESSAGE, 'Echo request', null],
    [ICMP6.ECHO_REPLY]: [ICMP6.INFORMATIONAL_MESSAGE, 'Echo reply', null],
    [ICMP6.ROUTER_SOLICITATION]: [ICMP6.INFORMATIONAL_MESSAGE, 'Router Solicitation', null],
    [ICMP6.ROUTER_ADVERTISEMENT]: [ICMP6.INFORMATIONAL_MESSAGE, 'Router Advertisement', null],
    [ICMP6.NEIGHBOR_SOLICITATION]: [ICMP6.INFORMATIONAL_MESSAGE, 'Neighbor Solicitation', null],
    [ICMP6.NEIGHBOR_ADVERTISEMENT]: [ICMP6.INFORMATIONAL_MESSAGE, 'Neighbor Advertisement', null],
    [ICMP6.REDIRECT_MESSAGE]: [ICMP6.INFORMATIONAL_MESSAGE, 'Redirect Message', null],
    [ICMP6.NODE_INFORMATION_QUERY]: [ICMP6.INFORMATIONAL_MESSAGE, 'Node Information Query', null],
    [ICMP6.NODE_INFORMATION_REPLY]: [ICMP6.INFORMATIONAL_MESSAGE, 'Node Information Reply', null],
  };

  constructor(buffer?: Buffer) {
    super(ICMP6.HEADER_SIZE);
    if (buffer) {
      this.loadHeader(buffer);
    }
  }

  private childHeader(): Header { return this.child() as Header; }

  override getHeaderSize(): number { return ICMP6.HEADER_SIZE; }
  getIpProtocolNumber(): number { return ICMP6.IP_PROTOCOL_NUMBER; }

  getType(): number { return this.getByte(0); }
  getCode(): number { return this.getByte(1); }
  getChecksum(): number { return this.getWord(2); }

  setType(type: number): void { this.setByte(0, type); }
  setCode(code: number): void { this.setByte(1, code); }
  setChecksum(checksum: number): void { this.setWord(2, checksum); }

  calculateChecksum(): void {
    this.setChecksum(0);
    const pseudoHeader = (this.parent() as unknown as { getPseudoHeader(): Buffer }).getPseudoHeader();
    const icmpHeader = this.getBytes();

    const parts: Buffer[] = [Buffer.from(pseudoHeader), Buffer.from(icmpHeader)];
    const ch = this.child() as Header | null;
    if (ch) {
      parts.push(Buffer.from(ch.getBytes()));
    }
    const checksumArray = Buffer.concat(parts);
    this.setChecksum(this.computeChecksum(checksumArray));
  }

  isInformationalMessage(): boolean {
    const entry = ICMP6.icmpMessages[this.getType()];
    return entry !== undefined && entry[ICMP6.MSG_TYPE_INDEX] === ICMP6.INFORMATIONAL_MESSAGE;
  }

  isErrorMessage(): boolean {
    const entry = ICMP6.icmpMessages[this.getType()];
    return entry !== undefined && entry[ICMP6.MSG_TYPE_INDEX] === ICMP6.ERROR_MESSAGE;
  }

  isWellFormed(): boolean {
    const entry = ICMP6.icmpMessages[this.getType()];
    if (!entry) return false;

    const codeDict = entry[2];
    if (codeDict === null) {
      return this.getCode() === 0;
    }
    return codeDict !== undefined && this.getCode() in codeDict;
  }

  // Echo methods
  static EchoRequest(id: number, sequenceNumber: number, arbitraryData?: Buffer): ICMP6 {
    return ICMP6._buildEchoMessage(ICMP6.ECHO_REQUEST, id, sequenceNumber, arbitraryData);
  }

  static EchoReply(id: number, sequenceNumber: number, arbitraryData?: Buffer): ICMP6 {
    return ICMP6._buildEchoMessage(ICMP6.ECHO_REPLY, id, sequenceNumber, arbitraryData);
  }

  private static _buildEchoMessage(type: number, id: number, sequenceNumber: number, arbitraryData?: Buffer): ICMP6 {
    const icmpPacket = new ICMP6();
    icmpPacket.setType(type);
    icmpPacket.setCode(0);

    const idBuf = Buffer.alloc(2);
    idBuf.writeUInt16BE(id);
    const seqBuf = Buffer.alloc(2);
    seqBuf.writeUInt16BE(sequenceNumber);

    const parts: Buffer[] = [idBuf, seqBuf];
    if (arbitraryData) {
      parts.push(arbitraryData);
    }

    const icmpPayload = new Data(Buffer.concat(parts));
    icmpPacket.contains(icmpPayload);
    return icmpPacket;
  }

  // Error message methods
  static DestinationUnreachable(code: number, originatingPacketData?: Buffer): ICMP6 {
    return ICMP6._buildErrorMessage(ICMP6.DESTINATION_UNREACHABLE, code, Buffer.alloc(4), originatingPacketData);
  }

  static PacketTooBig(mtu: number, originatingPacketData?: Buffer): ICMP6 {
    const mtuBuf = Buffer.alloc(4);
    mtuBuf.writeUInt32BE(mtu);
    return ICMP6._buildErrorMessage(ICMP6.PACKET_TOO_BIG, 0, mtuBuf, originatingPacketData);
  }

  static TimeExceeded(code: number, originatingPacketData?: Buffer): ICMP6 {
    return ICMP6._buildErrorMessage(ICMP6.TIME_EXCEEDED, code, Buffer.alloc(4), originatingPacketData);
  }

  static ParameterProblem(code: number, pointer: number, originatingPacketData?: Buffer): ICMP6 {
    const ptrBuf = Buffer.alloc(4);
    ptrBuf.writeUInt32BE(pointer);
    return ICMP6._buildErrorMessage(ICMP6.PARAMETER_PROBLEM, code, ptrBuf, originatingPacketData);
  }

  private static _buildErrorMessage(type: number, code: number, data: Buffer, originatingPacketData?: Buffer): ICMP6 {
    const icmpPacket = new ICMP6();
    icmpPacket.setType(type);
    icmpPacket.setCode(code);

    const parts: Buffer[] = [data];
    if (originatingPacketData) {
      parts.push(originatingPacketData);
    }

    const icmpPayload = new Data(Buffer.concat(parts));
    icmpPacket.contains(icmpPayload);
    return icmpPacket;
  }

  // Neighbor methods
  static NeighborSolicitation(targetAddress: string): ICMP6 {
    return ICMP6._buildNeighborMessage(ICMP6.NEIGHBOR_SOLICITATION, targetAddress);
  }

  static NeighborAdvertisement(targetAddress: string): ICMP6 {
    return ICMP6._buildNeighborMessage(ICMP6.NEIGHBOR_ADVERTISEMENT, targetAddress);
  }

  private static _buildNeighborMessage(msgType: number, targetAddress: string): ICMP6 {
    const icmpPacket = new ICMP6();
    icmpPacket.setType(msgType);
    icmpPacket.setCode(0);

    const flagsReserved = Buffer.alloc(4);
    const addrBytes = new IP6_Address(targetAddress).asBytes();

    const icmpPayload = new Data(Buffer.concat([flagsReserved, addrBytes]));
    icmpPacket.contains(icmpPayload);
    return icmpPacket;
  }

  getTargetAddress(): IP6_Address {
    return new IP6_Address(this.childHeader().getBytes().subarray(4, 20));
  }

  setTargetAddress(targetAddress: string): void {
    const address = new IP6_Address(targetAddress);
    const payloadBytes = Buffer.from(this.childHeader().getBytes());
    address.asBytes().copy(payloadBytes, 4);
    this.childHeader().setBytes(payloadBytes);
  }

  getNeighborAdvertisementFlags(): number {
    return this.childHeader().getByte(0);
  }

  setNeighborAdvertisementFlags(flags: number): void {
    this.childHeader().setByte(0, flags);
  }

  getRouterFlag(): boolean { return (this.getNeighborAdvertisementFlags() & 0x80) !== 0; }
  setRouterFlag(v: boolean): void {
    let f = this.getNeighborAdvertisementFlags();
    f = v ? (f | 0x80) : (f & ~0x80);
    this.setNeighborAdvertisementFlags(f);
  }

  getSolicitedFlag(): boolean { return (this.getNeighborAdvertisementFlags() & 0x40) !== 0; }
  setSolicitedFlag(v: boolean): void {
    let f = this.getNeighborAdvertisementFlags();
    f = v ? (f | 0x40) : (f & ~0x40);
    this.setNeighborAdvertisementFlags(f);
  }

  getOverrideFlag(): boolean { return (this.getNeighborAdvertisementFlags() & 0x20) !== 0; }
  setOverrideFlag(v: boolean): void {
    let f = this.getNeighborAdvertisementFlags();
    f = v ? (f | 0x20) : (f & ~0x20);
    this.setNeighborAdvertisementFlags(f);
  }

  // Node Information methods
  static NodeInformationQuery(code: number, payload?: Buffer): ICMP6 {
    return ICMP6._buildNodeInformationMessage(ICMP6.NODE_INFORMATION_QUERY, code, payload);
  }

  static NodeInformationReply(code: number, payload?: Buffer): ICMP6 {
    return ICMP6._buildNodeInformationMessage(ICMP6.NODE_INFORMATION_REPLY, code, payload);
  }

  private static _buildNodeInformationMessage(type: number, code: number, payload?: Buffer): ICMP6 {
    const icmpPacket = new ICMP6();
    icmpPacket.setType(type);
    icmpPacket.setCode(code);

    const qtypeBuf = Buffer.alloc(2);
    const flagsBuf = Buffer.alloc(2);
    const nonce = Buffer.alloc(8);

    const parts: Buffer[] = [qtypeBuf, flagsBuf, nonce];
    if (payload) {
      parts.push(payload);
    }

    const icmpPayload = new Data(Buffer.concat(parts));
    icmpPacket.contains(icmpPayload);
    return icmpPacket;
  }

  getQtype(): number { return this.childHeader().getWord(0); }
  setQtype(v: number): void { this.childHeader().setWord(0, v); }

  getNonce(): Buffer {
    return Buffer.from(this.childHeader().getBytes().subarray(4, 12));
  }

  setNonce(nonce: Buffer): void {
    const payloadBytes = Buffer.from(this.childHeader().getBytes());
    nonce.copy(payloadBytes, 4);
    this.childHeader().setBytes(payloadBytes);
  }

  getFlags(): number { return this.childHeader().getWord(2); }
  setFlags(flags: number): void { this.childHeader().setWord(2, flags); }

  getFlagT(): boolean { return (this.getFlags() & 0x0001) !== 0; }
  setFlagT(v: boolean): void { this.setFlags(v ? (this.getFlags() | 0x0001) : (this.getFlags() & ~0x0001)); }

  getFlagA(): boolean { return (this.getFlags() & 0x0002) !== 0; }
  setFlagA(v: boolean): void { this.setFlags(v ? (this.getFlags() | 0x0002) : (this.getFlags() & ~0x0002)); }

  getFlagC(): boolean { return (this.getFlags() & 0x0004) !== 0; }
  setFlagC(v: boolean): void { this.setFlags(v ? (this.getFlags() | 0x0004) : (this.getFlags() & ~0x0004)); }

  getFlagL(): boolean { return (this.getFlags() & 0x0008) !== 0; }
  setFlagL(v: boolean): void { this.setFlags(v ? (this.getFlags() | 0x0008) : (this.getFlags() & ~0x0008)); }

  getFlagS(): boolean { return (this.getFlags() & 0x0010) !== 0; }
  setFlagS(v: boolean): void { this.setFlags(v ? (this.getFlags() | 0x0010) : (this.getFlags() & ~0x0010)); }

  getFlagG(): boolean { return (this.getFlags() & 0x0020) !== 0; }
  setFlagG(v: boolean): void { this.setFlags(v ? (this.getFlags() | 0x0020) : (this.getFlags() & ~0x0020)); }

  setNodeInformationData(data: Buffer): void {
    const payloadBytes = Buffer.from(this.childHeader().getBytes());
    const newPayload = Buffer.concat([payloadBytes.subarray(0, 12), data]);
    this.childHeader().setBytes(newPayload);
  }

  getNodeInformationData(): Buffer {
    return Buffer.from(this.childHeader().getBytes().subarray(12));
  }

  // Echo accessors
  getEchoId(): number { return this.childHeader().getWord(0); }
  getEchoSequenceNumber(): number { return this.childHeader().getWord(2); }
  getEchoArbitraryData(): Buffer { return Buffer.from(this.childHeader().getBytes().subarray(4)); }

  getMtu(): number { return this.childHeader().getLong(0); }
  getParmProblemPointer(): number { return this.childHeader().getLong(0); }
  getOriginatingPacketData(): Buffer { return Buffer.from(this.childHeader().getBytes().subarray(4)); }
}
