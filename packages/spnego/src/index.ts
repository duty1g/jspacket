import { Buffer } from 'node:buffer';
import { rc4, rc4Init } from '@impacket/crypto';
import * as ntlm from '@impacket/ntlm';

export const GSS_API_SPNEGO_UUID = Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);

export const ASN1_SEQUENCE = 0x30;
export const ASN1_AID = 0x60;
export const ASN1_OID = 0x06;
export const ASN1_OCTET_STRING = 0x04;
export const ASN1_MECH_TYPE = 0xa0;
export const ASN1_MECH_TOKEN = 0xa2;
export const ASN1_SUPPORTED_MECH = 0xa1;
export const ASN1_RESPONSE_TOKEN = 0xa2;
export const ASN1_MECH_LIST_MIC = 0xa3;
export const ASN1_ENUMERATED = 0x0a;

export const MechTypes: Record<string, string> = {
  '2b06010401823702020a': 'NTLMSSP - Microsoft NTLM Security Support Provider',
  '2a864882f712010202': 'MS KRB5 - Microsoft Kerberos 5',
  '2a864886f712010202': 'KRB5 - Kerberos 5',
  '2a864886f71201020203': 'KRB5 - Kerberos 5 - User to User',
  '2b06010401823702021e': 'NEGOEX - SPNEGO Extended Negotiation Security Mechanism',
};

export const TypesMech: Record<string, Buffer> = {
  'NTLMSSP - Microsoft NTLM Security Support Provider': Buffer.from('2b06010401823702020a', 'hex'),
  'MS KRB5 - Microsoft Kerberos 5': Buffer.from('2a864882f712010202', 'hex'),
  'KRB5 - Kerberos 5': Buffer.from('2a864886f712010202', 'hex'),
  'KRB5 - Kerberos 5 - User to User': Buffer.from('2a864886f71201020203', 'hex'),
  'NEGOEX - SPNEGO Extended Negotiation Security Mechanism': Buffer.from(
    '2b06010401823702021e',
    'hex',
  ),
};

export function asn1encode(data: Buffer): Buffer {
  const len = data.length;
  if (len <= 0x7f) return Buffer.concat([Buffer.from([len]), data]);
  if (len <= 0xff) return Buffer.concat([Buffer.from([0x81, len]), data]);
  if (len <= 0xffff) {
    const hdr = Buffer.alloc(3);
    hdr[0] = 0x82;
    hdr.writeUInt16BE(len, 1);
    return Buffer.concat([hdr, data]);
  }
  if (len <= 0xffffff) {
    const hdr = Buffer.alloc(4);
    hdr[0] = 0x83;
    hdr.writeUInt8((len >> 16) & 0xff, 1);
    hdr.writeUInt16BE(len & 0xffff, 2);
    return Buffer.concat([hdr, data]);
  }
  if (len <= 0xffffffff) {
    const hdr = Buffer.alloc(5);
    hdr[0] = 0x84;
    hdr.writeUInt32BE(len, 1);
    return Buffer.concat([hdr, data]);
  }
  throw new Error('Error in asn1encode');
}

export function asn1decode(data: Buffer): [Buffer, number] {
  const len1 = data[0]!;
  let off = 1;
  let len: number;
  if (len1 === 0x81) {
    len = data[off]!;
    off += 1;
  } else if (len1 === 0x82) {
    len = data.readUInt16BE(off);
    off += 2;
  } else if (len1 === 0x83) {
    len = ((data[off]! << 16) | data.readUInt16BE(off + 1)) >>> 0;
    off += 3;
  } else if (len1 === 0x84) {
    len = data.readUInt32BE(off);
    off += 4;
  } else {
    len = len1;
  }
  const ans = data.subarray(off, off + len);
  return [Buffer.from(ans), off + len];
}

export class GSSAPI {
  fields: Record<string, Buffer> = {};

  constructor(data?: Buffer) {
    this.fields.UUID = GSS_API_SPNEGO_UUID;
    if (data) this.fromString(data);
  }

  fromString(data: Buffer): void {
    let nextByte = data[0]!;
    if (nextByte !== ASN1_AID) throw new Error(`Unknown AID=${nextByte.toString(16)}`);
    const payload = data.subarray(1);
    const [decodeData, _total1] = asn1decode(payload);
    nextByte = decodeData[0]!;
    if (nextByte !== ASN1_OID) throw new Error(`OID tag not found ${nextByte.toString(16)}`);
    const oidContent = decodeData.subarray(1);
    const [uuid, total2] = asn1decode(oidContent);
    this.fields.OID = uuid;
    this.fields.Payload = Buffer.from(decodeData.subarray(1 + total2));
  }

  getData(): Buffer {
    const inner = Buffer.concat([
      Buffer.from([ASN1_OID]),
      asn1encode(this.fields.UUID!),
      this.fields.Payload!,
    ]);
    return Buffer.concat([Buffer.from([ASN1_AID]), asn1encode(inner)]);
  }
}

export class SPNEGO_NegTokenInit extends GSSAPI {
  static SPNEGO_NEG_TOKEN_INIT = 0xa0;
  mechTypeOids: Buffer[] = [];

  constructor(data?: Buffer) {
    super();
    if (data) this.fromString(data);
  }

  fromString(data: Buffer): void {
    super.fromString(data);
    let payload = this.fields.Payload!;
    let nextByte = payload[0]!;
    if (nextByte !== SPNEGO_NegTokenInit.SPNEGO_NEG_TOKEN_INIT)
      throw new Error(`NegTokenInit not found ${nextByte.toString(16)}`);
    payload = payload.subarray(1);
    let [decodeData, _t1] = asn1decode(payload);
    nextByte = decodeData[0]!;
    if (nextByte !== ASN1_SEQUENCE)
      throw new Error(`SEQUENCE tag not found ${nextByte.toString(16)}`);
    decodeData = decodeData.subarray(1);
    let [decodeData2, _t2] = asn1decode(decodeData);
    nextByte = decodeData2[0]!;
    if (nextByte !== ASN1_MECH_TYPE)
      throw new Error(`MechType tag not found ${nextByte.toString(16)}`);
    decodeData2 = decodeData2.subarray(1);
    const remainingData = decodeData2;
    let [mechListData, t3] = asn1decode(decodeData2);
    nextByte = mechListData[0]!;
    if (nextByte !== ASN1_SEQUENCE)
      throw new Error(`SEQUENCE tag not found ${nextByte.toString(16)}`);
    mechListData = mechListData.subarray(1);
    let [mechData, _t4] = asn1decode(mechListData);

    this.mechTypeOids = [];
    while (mechData.length > 0) {
      nextByte = mechData[0]!;
      if (nextByte !== ASN1_OID) break;
      mechData = mechData.subarray(1);
      const [item, total] = asn1decode(mechData);
      this.mechTypeOids.push(item);
      mechData = mechData.subarray(total);
    }

    const afterMech = remainingData.subarray(t3);
    if (afterMech.length > 0) {
      nextByte = afterMech[0]!;
      if (nextByte === ASN1_MECH_TOKEN) {
        const tokenData = afterMech.subarray(1);
        let [tokenContent, _tt] = asn1decode(tokenData);
        nextByte = tokenContent[0]!;
        if (nextByte === ASN1_OCTET_STRING) {
          tokenContent = tokenContent.subarray(1);
          const [mechToken, _t5] = asn1decode(tokenContent);
          this.fields.MechToken = mechToken;
        }
      }
    }
  }

  getData(): Buffer {
    let mechTypesEncoded = Buffer.alloc(0);
    for (const oid of this.mechTypeOids) {
      mechTypesEncoded = Buffer.concat([
        mechTypesEncoded,
        Buffer.from([ASN1_OID]),
        asn1encode(oid),
      ]);
    }

    let mechToken = Buffer.alloc(0);
    if (this.fields.MechToken !== undefined) {
      mechToken = Buffer.concat([
        Buffer.from([ASN1_MECH_TOKEN]),
        asn1encode(
          Buffer.concat([Buffer.from([ASN1_OCTET_STRING]), asn1encode(this.fields.MechToken!)]),
        ),
      ]);
    }

    const ans = Buffer.concat([
      Buffer.from([SPNEGO_NegTokenInit.SPNEGO_NEG_TOKEN_INIT]),
      asn1encode(
        Buffer.concat([
          Buffer.from([ASN1_SEQUENCE]),
          asn1encode(
            Buffer.concat([
              Buffer.from([ASN1_MECH_TYPE]),
              asn1encode(
                Buffer.concat([Buffer.from([ASN1_SEQUENCE]), asn1encode(mechTypesEncoded)]),
              ),
              mechToken,
            ]),
          ),
        ]),
      ),
    ]);

    this.fields.Payload = ans;
    return super.getData();
  }
}

export class SPNEGO_NegTokenResp {
  static SPNEGO_NEG_TOKEN_RESP = 0xa1;
  static SPNEGO_NEG_TOKEN_TARG = 0xa0;
  fields: Record<string, Buffer> = {};

  constructor(data?: Buffer) {
    if (data) this.fromString(data);
  }

  fromString(data: Buffer): void {
    let payload = data;
    let nextByte = payload[0]!;
    if (nextByte !== SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP)
      throw new Error(`NegTokenResp not found ${nextByte.toString(16)}`);
    payload = payload.subarray(1);
    let [decodeData, _t1] = asn1decode(payload);
    nextByte = decodeData[0]!;
    if (nextByte !== ASN1_SEQUENCE)
      throw new Error(`SEQUENCE tag not found ${nextByte.toString(16)}`);
    decodeData = decodeData.subarray(1);
    let [innerData, _t2] = asn1decode(decodeData);
    nextByte = innerData[0]!;

    if (nextByte !== ASN1_MECH_TYPE) {
      if (nextByte !== ASN1_RESPONSE_TOKEN)
        throw new Error(`MechType/ResponseToken tag not found ${nextByte.toString(16)}`);
    } else {
      let decodeData2 = innerData.subarray(1);
      const [enumContent, t3] = asn1decode(decodeData2);
      nextByte = enumContent[0]!;
      if (nextByte !== ASN1_ENUMERATED)
        throw new Error(`Enumerated tag not found ${nextByte.toString(16)}`);
      const [item, _t4] = asn1decode(enumContent.subarray(1));
      this.fields.NegState = item;
      innerData = innerData.subarray(1 + t3);

      if (innerData.length === 0) return;

      nextByte = innerData[0]!;
      if (nextByte !== ASN1_SUPPORTED_MECH) {
        if (nextByte !== ASN1_RESPONSE_TOKEN)
          throw new Error(`Supported Mech/ResponseToken tag not found ${nextByte.toString(16)}`);
      } else {
        decodeData2 = innerData.subarray(1);
        let [mechContent, t5] = asn1decode(decodeData2);
        nextByte = mechContent[0]!;
        if (nextByte !== ASN1_OID) throw new Error(`OID tag not found ${nextByte.toString(16)}`);
        mechContent = mechContent.subarray(1);
        const [mechItem, _t6] = asn1decode(mechContent);
        this.fields.SupportedMech = mechItem;
        innerData = innerData.subarray(1 + t5);
        nextByte = innerData[0]!;
        if (nextByte !== ASN1_RESPONSE_TOKEN)
          throw new Error(`Response token tag not found ${nextByte.toString(16)}`);
      }
    }

    const tokenData = innerData.subarray(1);
    let [tokenContent, _t7] = asn1decode(tokenData);
    nextByte = tokenContent[0]!;
    if (nextByte !== ASN1_OCTET_STRING)
      throw new Error(`Octet string token tag not found ${nextByte.toString(16)}`);
    tokenContent = tokenContent.subarray(1);
    const [responseToken, _t8] = asn1decode(tokenContent);
    this.fields.ResponseToken = responseToken;
  }

  getData(): Buffer {
    let ans = Buffer.from([SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP]);

    const has = (k: string) => k in this.fields;

    if (has('NegState') && has('SupportedMech') && has('ResponseToken')) {
      ans = Buffer.concat([
        ans,
        asn1encode(
          Buffer.concat([
            Buffer.from([ASN1_SEQUENCE]),
            asn1encode(
              Buffer.concat([
                Buffer.from([SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_TARG]),
                asn1encode(
                  Buffer.concat([
                    Buffer.from([ASN1_ENUMERATED]),
                    asn1encode(this.fields.NegState!),
                  ]),
                ),
                Buffer.from([ASN1_SUPPORTED_MECH]),
                asn1encode(
                  Buffer.concat([Buffer.from([ASN1_OID]), asn1encode(this.fields.SupportedMech!)]),
                ),
                Buffer.from([ASN1_RESPONSE_TOKEN]),
                asn1encode(
                  Buffer.concat([
                    Buffer.from([ASN1_OCTET_STRING]),
                    asn1encode(this.fields.ResponseToken!),
                  ]),
                ),
              ]),
            ),
          ]),
        ),
      ]);
    } else if (has('NegState') && has('SupportedMech')) {
      ans = Buffer.concat([
        ans,
        asn1encode(
          Buffer.concat([
            Buffer.from([ASN1_SEQUENCE]),
            asn1encode(
              Buffer.concat([
                Buffer.from([SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_TARG]),
                asn1encode(
                  Buffer.concat([
                    Buffer.from([ASN1_ENUMERATED]),
                    asn1encode(this.fields.NegState!),
                  ]),
                ),
                Buffer.from([ASN1_SUPPORTED_MECH]),
                asn1encode(
                  Buffer.concat([Buffer.from([ASN1_OID]), asn1encode(this.fields.SupportedMech!)]),
                ),
              ]),
            ),
          ]),
        ),
      ]);
    } else if (has('NegState')) {
      ans = Buffer.concat([
        ans,
        asn1encode(
          Buffer.concat([
            Buffer.from([ASN1_SEQUENCE]),
            asn1encode(
              Buffer.concat([
                Buffer.from([SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_TARG]),
                asn1encode(
                  Buffer.concat([
                    Buffer.from([ASN1_ENUMERATED]),
                    asn1encode(this.fields.NegState!),
                  ]),
                ),
              ]),
            ),
          ]),
        ),
      ]);
    } else {
      if (has('mechListMIC')) {
        ans = Buffer.concat([
          ans,
          asn1encode(
            Buffer.concat([
              Buffer.from([ASN1_SEQUENCE]),
              asn1encode(
                Buffer.concat([
                  Buffer.from([ASN1_RESPONSE_TOKEN]),
                  asn1encode(
                    Buffer.concat([
                      Buffer.from([ASN1_OCTET_STRING]),
                      asn1encode(this.fields.ResponseToken!),
                    ]),
                  ),
                  Buffer.from([ASN1_MECH_LIST_MIC]),
                  asn1encode(
                    Buffer.concat([
                      Buffer.from([ASN1_OCTET_STRING]),
                      asn1encode(this.fields.mechListMIC!),
                    ]),
                  ),
                ]),
              ),
            ]),
          ),
        ]);
      } else {
        ans = Buffer.concat([
          ans,
          asn1encode(
            Buffer.concat([
              Buffer.from([ASN1_SEQUENCE]),
              asn1encode(
                Buffer.concat([
                  Buffer.from([ASN1_RESPONSE_TOKEN]),
                  asn1encode(
                    Buffer.concat([
                      Buffer.from([ASN1_OCTET_STRING]),
                      asn1encode(this.fields.ResponseToken!),
                    ]),
                  ),
                ]),
              ),
            ]),
          ),
        ]);
      }
    }
    return ans;
  }
}

export class SPNEGOCipher {
  private flags: number;
  private clientSigningKey: Buffer;
  private serverSigningKey: Buffer;
  private clientSealingKey: Buffer;
  private serverSealingKey: Buffer;
  private clientSealingHandle: (data: Buffer) => Buffer;
  private serverSealingHandle: (data: Buffer) => Buffer;
  private clientSealingCipher: ReturnType<typeof rc4Init> | null = null;
  private serverSealingCipher: ReturnType<typeof rc4Init> | null = null;
  private sequence = 0;

  constructor(flags: number, randomSessionKey: Buffer) {
    this.flags = flags;
    if (flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
      this.clientSigningKey = ntlm.signKey(flags, randomSessionKey) ?? randomSessionKey;
      this.serverSigningKey = ntlm.signKey(flags, randomSessionKey, 'Server') ?? randomSessionKey;
      this.clientSealingKey = ntlm.sealKey(flags, randomSessionKey);
      this.serverSealingKey = ntlm.sealKey(flags, randomSessionKey, 'Server');
    } else {
      this.clientSigningKey = randomSessionKey;
      this.serverSigningKey = randomSessionKey;
      this.clientSealingKey = randomSessionKey;
      this.serverSealingKey = randomSessionKey;
    }
    this.clientSealingCipher = rc4Init(this.clientSealingKey);
    this.clientSealingHandle = (data: Buffer) => this.clientSealingCipher!.update(data);
    this.serverSealingCipher = rc4Init(this.serverSealingKey);
    this.serverSealingHandle = (data: Buffer) => this.serverSealingCipher!.update(data);
  }

  encrypt(plainData: Buffer): [ntlm.NTLMMessageSignature, Buffer] {
    const [sealedMessage, signature] = ntlm.SEAL(
      this.flags,
      this.clientSigningKey,
      this.clientSealingKey,
      plainData,
      plainData,
      this.sequence,
      this.clientSealingHandle,
    );
    this.sequence += 1;
    return [signature, sealedMessage];
  }

  decrypt(answer: Buffer): [ntlm.NTLMMessageSignature, Buffer] {
    const [decrypted, signature] = ntlm.SEAL(
      this.flags,
      this.serverSigningKey,
      this.serverSealingKey,
      answer.subarray(0, 16),
      answer.subarray(16),
      this.sequence,
      this.serverSealingHandle,
    );
    return [signature, decrypted];
  }

  sign(data: Buffer, seqNum = 0, resetCipher = false): ntlm.NTLMMessageSignature {
    const signature = ntlm.MAC(
      this.flags,
      this.clientSealingHandle,
      this.clientSigningKey,
      seqNum,
      data,
    );
    if (resetCipher) {
      if (this.flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        this.clientSealingCipher = rc4Init(this.clientSealingKey);
        this.clientSealingHandle = (d: Buffer) => this.clientSealingCipher!.update(d);
        this.serverSealingCipher = rc4Init(this.serverSealingKey);
        this.serverSealingHandle = (d: Buffer) => this.serverSealingCipher!.update(d);
      } else {
        this.clientSealingCipher = rc4Init(this.clientSigningKey);
        this.clientSealingHandle = (d: Buffer) => this.clientSealingCipher!.update(d);
        this.serverSealingCipher = rc4Init(this.clientSigningKey);
        this.serverSealingHandle = (d: Buffer) => this.serverSealingCipher!.update(d);
      }
    }
    this.sequence += 1;
    return signature;
  }
}
