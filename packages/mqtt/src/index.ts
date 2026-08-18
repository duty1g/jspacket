/**
 * @impacket/mqtt - TypeScript port of impacket/mqtt.py
 *
 * Minimalistic MQTT implementation, focused on connecting, subscribing
 * and publishing basic messages on topics.
 *
 * References:
 *   - https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
 */

import { Buffer } from 'node:buffer';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { Structure, type FieldDescriptor, type PackValue } from '@impacket/structure';

// ---------------------------------------------------------------------------
// Packet Types
// ---------------------------------------------------------------------------

export const PACKET_CONNECT       = 1 << 4;
export const PACKET_CONNACK       = 2 << 4;
export const PACKET_PUBLISH       = 3 << 4;
export const PACKET_PUBACK        = 4 << 4;
export const PACKET_PUBREC        = 5 << 4;
export const PACKET_PUBREL        = 6 << 4;
export const PACKET_PUBCOMP       = 7 << 4;
export const PACKET_SUBSCRIBE     = 8 << 4;
export const PACKET_SUBSCRIBEACK  = 9 << 4;
export const PACKET_UNSUBSCRIBE   = 10 << 4;
export const PACKET_UNSUBACK      = 11 << 4;
export const PACKET_PINGREQ       = 12 << 4;
export const PACKET_PINGRESP      = 13 << 4;
export const PACKET_DISCONNECT    = 14 << 4;

// ---------------------------------------------------------------------------
// CONNECT Flags
// ---------------------------------------------------------------------------

export const CONNECT_USERNAME      = 0x80;
export const CONNECT_PASSWORD      = 0x40;
export const CONNECT_CLEAN_SESSION = 0x2;

// ---------------------------------------------------------------------------
// CONNECT_ACK Return Errors
// ---------------------------------------------------------------------------

export const CONNECT_ACK_ERROR_MSGS: Record<number, string> = {
  0x00: 'Connection Accepted',
  0x01: 'Connection Refused, unacceptable protocol version',
  0x02: 'Connection Refused, identifier rejected',
  0x03: 'Connection Refused, Server unavailable',
  0x04: 'Connection Refused, bad user name or password',
  0x05: 'Connection Refused, not authorized',
};

// ---------------------------------------------------------------------------
// QoS Levels
// ---------------------------------------------------------------------------

export const QOS_FIRE_AND_FORGET   = 0;
export const QOS_ACK_DELIVERY      = 1;
export const QOS_ASSURED_DELIVERY  = 2;

// ---------------------------------------------------------------------------
// MQTT Structures
// ---------------------------------------------------------------------------

export class MQTT_Packet extends Structure {
  static override commonHdr: FieldDescriptor[] = [
    ['PacketType',    'B=0'],
    ['MessageLength', '<L=0'],
  ];

  static override structure: FieldDescriptor[] = [
    ['_VariablePart', '_-VariablePart', 'self["MessageLength"]'],
    ['VariablePart',  ':'],
  ];

  setQoS(qos: number): void {
    this.set('PacketType', ((this.get('PacketType') as number) | (qos << 1)));
  }

  override fromString(data: Buffer): this {
    if (data != null && data.length > 2) {
      // Decode MQTT variable-length encoding
      let index = 1;
      let multiplier = 1;
      let value = 0;
      let encodedByte = 128;
      const packetType = data[0]!;
      while ((encodedByte & 128) !== 0) {
        encodedByte = data[index]!;
        value += (encodedByte & 127) * multiplier;
        multiplier *= 128;
        index += 1;
        if (multiplier > 128 * 128 * 128) {
          throw new Error('Malformed Remaining Length');
        }
      }
      // Rebuild data with a fixed 4-byte little-endian length
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32LE(value, 0);
      data = Buffer.concat([
        Buffer.from([packetType]),
        lenBuf,
        data.subarray(index, value + index),
      ]);
      return Structure.prototype.fromString.call(this, data) as this;
    }
    throw new Error('Insufficient data for MQTT packet');
  }

  override getData(): Buffer {
    const packetType = this.get('PacketType') as number;

    // Temporarily remove commonHdr so we only get the structure part
    const savedCommonHdr = this.commonHdr;
    this.commonHdr = [];
    let packetLen = Structure.prototype.getData.call(this).length;

    // Encode the remaining length using MQTT variable-length encoding
    let output = Buffer.alloc(0);
    while (packetLen > 0) {
      let encodedByte = packetLen % 128;
      packetLen = Math.floor(packetLen / 128);
      if (packetLen > 0) {
        encodedByte |= 128;
      }
      output = Buffer.concat([output, Buffer.from([encodedByte])]);
    }

    // Restore commonHdr with variable-length MessageLength
    this.commonHdr = [
      ['PacketType', 'B=0'],
      ['MessageLength', ':'],
    ];
    this.set('PacketType', packetType);
    this.set('MessageLength', output.length > 0 ? output : Buffer.from([0]));

    return Structure.prototype.getData.call(this) as Buffer;
  }
}

export class MQTT_String extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Length', '>H-Name'],
    ['Name',   ':'],
  ];
}

export class MQTT_Connect extends MQTT_Packet {
  static override structure: FieldDescriptor[] = [
    ['ProtocolName', ':', MQTT_String],
    ['Version',      'B=3'],
    ['Flags',        'B=2'],
    ['KeepAlive',    '>H=60'],
    ['ClientID',     ':', MQTT_String],
    ['Payload',      ':=""'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
    if (data == null) {
      this.set('PacketType', PACKET_CONNECT);
    }
  }
}

export class MQTT_ConnectAck extends MQTT_Packet {
  static override structure: FieldDescriptor[] = [
    ['ReturnCode', '>H=0'],
  ];
}

export class MQTT_Publish extends MQTT_Packet {
  static override structure: FieldDescriptor[] = [
    ['Topic',   ':', MQTT_String],
    ['Message', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
    if (data == null) {
      this.set('PacketType', PACKET_PUBLISH);
    }
  }

  override getData(): Buffer {
    if (((this.get('PacketType') as number) & 6) > 0) {
      // QoS enabled: insert MessageID field
      this.structure = [
        ['Topic',     ':', MQTT_String],
        ['MessageID', '>H=0'],
        ['Message',   ':'],
      ];
    }
    return super.getData();
  }
}

export class MQTT_Disconnect extends MQTT_Packet {
  static override structure: FieldDescriptor[] = [];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
    if (data == null) {
      this.set('PacketType', PACKET_DISCONNECT);
    }
  }
}

export class MQTT_Subscribe extends MQTT_Packet {
  static override structure: FieldDescriptor[] = [
    ['MessageID', '>H=1'],
    ['Topic',     ':', MQTT_String],
    ['Flags',     'B=0'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
    if (data == null) {
      this.set('PacketType', PACKET_SUBSCRIBE);
    }
  }
}

export class MQTT_SubscribeACK extends MQTT_Packet {
  static override structure: FieldDescriptor[] = [
    ['MessageID',  '>H=0'],
    ['ReturnCode', 'B=0'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
    if (data == null) {
      this.set('PacketType', PACKET_SUBSCRIBEACK);
    }
  }
}

export class MQTT_UnSubscribe extends MQTT_Packet {
  static override structure: FieldDescriptor[] = [
    ['MessageID', '>H=1'],
    ['Topics',    ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data ?? null, alignment);
    if (data == null) {
      this.set('PacketType', PACKET_UNSUBSCRIBE);
    }
  }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class MQTTSessionError extends Error {
  error: number;
  packet: unknown;
  errorString: string;

  constructor(options: { error?: number; packet?: unknown; errorString?: string } = {}) {
    super(options.errorString ?? '');
    this.name = 'MQTTSessionError';
    this.error = options.error ?? 0;
    this.packet = options.packet ?? 0;
    this.errorString = options.errorString ?? '';
  }

  getErrorCode(): number { return this.error; }
  getErrorPacket(): unknown { return this.packet; }
  getErrorString(): string { return this.errorString; }

  override toString(): string { return this.errorString; }
}

// ---------------------------------------------------------------------------
// MQTT Connection
// ---------------------------------------------------------------------------

export class MQTTConnection {
  private _targetHost: string;
  private _targetPort: number;
  private _isSSL: boolean;
  private _socket: net.Socket | tls.TLSSocket | null = null;
  private _messageId = 1;

  constructor(host: string, port: number, isSSL = false) {
    this._targetHost = host;
    this._targetPort = port;
    this._isSSL = isSSL;
  }

  getSocket(): net.Socket | tls.TLSSocket | null {
    return this._socket;
  }

  connectSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this._isSSL) {
        const socket = tls.connect(
          {
            host: this._targetHost,
            port: this._targetPort,
            rejectUnauthorized: false,
          },
          () => {
            this._socket = socket;
            resolve();
          },
        );
        socket.on('error', reject);
      } else {
        const socket = new net.Socket();
        socket.connect(this._targetPort, this._targetHost, () => {
          this._socket = socket;
          resolve();
        });
        socket.on('error', reject);
      }
    });
  }

  send(request: MQTT_Packet | Structure): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this._socket) {
        reject(new Error('Socket not connected'));
        return;
      }
      this._socket.write(request.getData(), (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async sendReceive(request: MQTT_Packet | Structure): Promise<MQTT_Packet[]> {
    await this.send(request);
    return this.recv();
  }

  recv(): Promise<MQTT_Packet[]> {
    const REQUEST_SIZE = 8192;
    return new Promise((resolve, reject) => {
      if (!this._socket) {
        reject(new Error('Socket not connected'));
        return;
      }
      const chunks: Buffer[] = [];
      const onData = (chunk: Buffer) => {
        chunks.push(chunk);
        if (chunk.length < REQUEST_SIZE) {
          this._socket!.removeListener('data', onData);
          this._socket!.removeListener('error', onError);
          const data = Buffer.concat(chunks);
          const response: MQTT_Packet[] = [];
          let remaining = data;
          while (remaining.length > 0) {
            try {
              const message = new MQTT_Packet(remaining);
              const msgLen = message.getData().length;
              remaining = remaining.subarray(msgLen);
              response.push(message);
            } catch {
              // Need more data -- in the async case just break
              break;
            }
          }
          this._messageId += 1;
          resolve(response);
        }
      };
      const onError = (err: Error) => {
        this._socket!.removeListener('data', onData);
        reject(err);
      };
      this._socket.on('data', onData);
      this._socket.on('error', onError);
    });
  }

  async connect(
    clientId = ' ',
    username: string | null = null,
    password: string | null = null,
    protocolName = 'MQIsdp',
    version = 3,
    flags: number = CONNECT_CLEAN_SESSION,
    keepAlive = 60,
  ): Promise<boolean> {
    const connectPacket = new MQTT_Connect();
    connectPacket.set('Version', version);
    connectPacket.set('Flags', flags);
    connectPacket.set('KeepAlive', keepAlive);

    const protoNameStr = new MQTT_String();
    protoNameStr.set('Name', protocolName);
    connectPacket.set('ProtocolName', protoNameStr);

    const clientIdStr = new MQTT_String();
    clientIdStr.set('Name', clientId);
    connectPacket.set('ClientID', clientIdStr);

    if (username != null) {
      connectPacket.set('Flags', (connectPacket.get('Flags') as number) | CONNECT_USERNAME | CONNECT_PASSWORD);
    }

    const user = username ?? '';
    const pwd = password ?? '';

    const userStr = new MQTT_String();
    userStr.set('Name', user);
    const pwdStr = new MQTT_String();
    pwdStr.set('Name', pwd);
    connectPacket.set('Payload', Buffer.concat([userStr.getData(), pwdStr.getData()]));

    const responses = await this.sendReceive(connectPacket);
    const data = responses[0]!;
    const response = new MQTT_ConnectAck(data.getData());

    const returnCode = response.get('ReturnCode') as number;
    if (returnCode !== 0) {
      throw new MQTTSessionError({
        error: returnCode,
        errorString: CONNECT_ACK_ERROR_MSGS[returnCode] ?? 'Unknown error',
      });
    }

    return true;
  }

  async subscribe(
    topic: string,
    messageID = 1,
    flags = 0,
    qos = 1,
  ): Promise<boolean> {
    const subscribePacket = new MQTT_Subscribe();
    subscribePacket.set('MessageID', messageID);

    const topicStr = new MQTT_String();
    topicStr.set('Name', topic);
    subscribePacket.set('Topic', topicStr);
    subscribePacket.set('Flags', flags);
    subscribePacket.setQoS(qos);

    let responses: MQTT_Packet[];
    try {
      responses = await this.sendReceive(subscribePacket);
    } catch (e) {
      throw new MQTTSessionError({ errorString: String(e) });
    }

    const data = responses[0]!;
    const subAck = new MQTT_SubscribeACK(data.getData());

    if ((subAck.get('ReturnCode') as number) > 2) {
      throw new MQTTSessionError({ errorString: 'Failure to subscribe' });
    }

    return true;
  }

  async unSubscribe(
    topic: string,
    messageID = 1,
    qos = 0,
  ): Promise<MQTT_Packet[]> {
    const packet = new MQTT_UnSubscribe();
    packet.set('MessageID', messageID);

    const topicStr = new MQTT_String();
    topicStr.set('Name', topic);
    packet.set('Topics', topicStr);
    packet.setQoS(qos);

    return this.sendReceive(packet);
  }

  async publish(
    topic: string,
    message: string | Buffer,
    messageID = 1,
    qos = 0,
  ): Promise<MQTT_Packet[]> {
    const packet = new MQTT_Publish();

    const topicStr = new MQTT_String();
    topicStr.set('Name', topic);
    packet.set('Topic', topicStr);
    packet.set('Message', message);
    packet.set('MessageID', messageID);
    packet.setQoS(qos);

    return this.sendReceive(packet);
  }

  async disconnect(): Promise<void> {
    const pkt = new MQTT_Disconnect();
    await this.send(pkt);
  }
}
