import { Buffer } from 'node:buffer';
import { describe, it, expect } from 'vitest';
import { TagClass, encodeTLV } from '@impacket/asn1';
import {
  type Filter,
  type LdapControl,
  ResultCode,
  Scope,
  DerefAliases,
  ProtocolOpTag,
  CONTROL_PAGEDRESULTS,
  CONTROL_SDFLAGS,
  encodeBindRequest,
  decodeBindResponse,
  encodeSearchRequest,
  encodeLDAPMessage,
  decodeLDAPMessage,
  encodeFilter,
  encodeControl,
  decodeControl,
  encodeControls,
  decodeControls,
  encodeModifyRequest,
  encodeAddRequest,
  encodeDelRequest,
  encodeModifyDNRequest,
  encodeCompareRequest,
  encodeAbandonRequest,
  encodeExtendedRequest,
  encodeUnbindRequest,
  createSimplePagedResultsControl,
  decodeSimplePagedResultsControlValue,
  createSDFlagsControl,
  decodeSDFlagsControlValue,
  encodeSimplePagedResultsControlValue,
} from '../src/ldapasn1.js';

describe('ldapasn1 — constants', () => {
  it('control OIDs match RFC/MS-ADTS values', () => {
    expect(CONTROL_PAGEDRESULTS).toBe('1.2.840.113556.1.4.319');
    expect(CONTROL_SDFLAGS).toBe('1.2.840.113556.1.4.801');
  });

  it('ResultCode enum values match RFC 4511', () => {
    expect(ResultCode.success).toBe(0);
    expect(ResultCode.operationsError).toBe(1);
    expect(ResultCode.compareFalse).toBe(5);
    expect(ResultCode.compareTrue).toBe(6);
    expect(ResultCode.referral).toBe(10);
    expect(ResultCode.noSuchObject).toBe(32);
    expect(ResultCode.invalidCredentials).toBe(49);
    expect(ResultCode.other).toBe(80);
  });

  it('Scope and DerefAliases enum values', () => {
    expect(Scope.baseObject).toBe(0);
    expect(Scope.singleLevel).toBe(1);
    expect(Scope.wholeSubtree).toBe(2);
    expect(DerefAliases.neverDerefAliases).toBe(0);
    expect(DerefAliases.derefAlways).toBe(3);
  });

  it('ProtocolOpTag values', () => {
    expect(ProtocolOpTag.bindRequest).toBe(0);
    expect(ProtocolOpTag.bindResponse).toBe(1);
    expect(ProtocolOpTag.searchRequest).toBe(3);
    expect(ProtocolOpTag.searchResEntry).toBe(4);
    expect(ProtocolOpTag.searchResDone).toBe(5);
    expect(ProtocolOpTag.searchResRef).toBe(19);
    expect(ProtocolOpTag.extendedReq).toBe(23);
    expect(ProtocolOpTag.extendedResp).toBe(24);
    expect(ProtocolOpTag.intermediateResponse).toBe(25);
  });
});

describe('ldapasn1 — BindRequest round-trip', () => {
  it('encodes a simple bind and decodes the response', () => {
    const bindReq = encodeBindRequest({
      version: 3,
      name: 'CN=User,DC=test,DC=com',
      authentication: { simple: Buffer.from('password', 'utf8') },
    });
    expect(bindReq[0]).toBe(0x60);
    const msg = encodeLDAPMessage(1, bindReq, null);
    const decoded = decodeLDAPMessage(msg);
    expect(decoded.messageID).toBe(1);
    expect(decoded.protocolOpTag).toBe(ProtocolOpTag.bindRequest);
  });

  it('encodes a SASL bind with GSS-SPNEGO', () => {
    const bindReq = encodeBindRequest({
      version: 3,
      name: '',
      authentication: {
        sasl: {
          mechanism: 'GSS-SPNEGO',
          credentials: Buffer.from([0x60, 0x06, 0x06, 0x04, 0x2b, 0x06, 0x01]),
        },
      },
    });
    expect(bindReq[0]).toBe(0x60);
    const msg = encodeLDAPMessage(2, bindReq, null);
    const decoded = decodeLDAPMessage(msg);
    expect(decoded.messageID).toBe(2);
    expect(decoded.protocolOpTag).toBe(ProtocolOpTag.bindRequest);
  });
});

describe('ldapasn1 — SearchRequest round-trip', () => {
  it('encodes a search request with a simple filter', () => {
    const filter: Filter = {
      equalityMatch: { attributeDesc: 'objectClass', assertionValue: 'user' },
    };
    const searchReq = encodeSearchRequest({
      baseObject: 'DC=test,DC=com',
      scope: Scope.wholeSubtree,
      derefAliases: DerefAliases.neverDerefAliases,
      sizeLimit: 0,
      timeLimit: 0,
      typesOnly: false,
      filter,
      attributes: ['cn', 'dn'],
    });
    expect(searchReq[0]).toBe(0x63);
    const msg = encodeLDAPMessage(3, searchReq, null);
    const decoded = decodeLDAPMessage(msg);
    expect(decoded.messageID).toBe(3);
    expect(decoded.protocolOpTag).toBe(ProtocolOpTag.searchRequest);
  });

  it('encodes a substring filter', () => {
    const filter: Filter = {
      substrings: {
        type: 'cn',
        substrings: [{ initial: 'test' }, { any: 'mid' }, { final: 'end' }],
      },
    };
    const encoded = encodeFilter(filter);
    expect(encoded[0]).toBe(0xa4);
  });

  it('encodes AND/OR/NOT composite filters', () => {
    const filter: Filter = {
      and: [
        { equalityMatch: { attributeDesc: 'objectClass', assertionValue: 'user' } },
        { not: [{ present: 'sn' }] },
        {
          or: [
            { greaterOrEqual: { attributeDesc: 'uidNumber', assertionValue: '1000' } },
            { lessOrEqual: { attributeDesc: 'uidNumber', assertionValue: '2000' } },
          ],
        },
      ],
    };
    const encoded = encodeFilter(filter);
    expect(encoded[0]).toBe(0xa0);
  });

  it('encodes present and approxMatch filters', () => {
    const present: Filter = { present: 'objectClass' };
    expect(encodeFilter(present)[0]).toBe(0x87);
    const approx: Filter = {
      approxMatch: { attributeDesc: 'cn', assertionValue: 'test' },
    };
    expect(encodeFilter(approx)[0]).toBe(0xa8);
  });

  it('encodes extensibleMatch filter', () => {
    const filter: Filter = {
      extensibleMatch: {
        matchingRule: '1.2.840.113556.1.4.1941',
        type: 'member',
        matchValue: 'CN=test',
        dnAttributes: true,
      },
    };
    const encoded = encodeFilter(filter);
    expect(encoded[0]).toBe(0xa9);
  });
});

describe('ldapasn1 — Controls', () => {
  it('encodes and decodes SimplePagedResults control', () => {
    const ctrl = createSimplePagedResultsControl(1000, Buffer.from([1, 2, 3]), true);
    expect(ctrl.controlType).toBe(CONTROL_PAGEDRESULTS);
    expect(ctrl.criticality).toBe(true);
    const decoded = decodeSimplePagedResultsControlValue(ctrl.controlValue!);
    expect(decoded.size).toBe(1000);
    expect(decoded.cookie).toEqual(Buffer.from([1, 2, 3]));
  });

  it('encodes and decodes SDFlags control', () => {
    const ctrl = createSDFlagsControl(0x7, true);
    expect(ctrl.controlType).toBe(CONTROL_SDFLAGS);
    const decoded = decodeSDFlagsControlValue(ctrl.controlValue!);
    expect(decoded.flags).toBe(7);
  });

  it('encodes and decodes a generic control', () => {
    const ctrl: LdapControl = {
      controlType: '1.2.3.4',
      criticality: true,
      controlValue: Buffer.from([0x01, 0x02]),
    };
    const encoded = encodeControl(ctrl);
    const decoded = decodeControl(encoded);
    expect(decoded.controlType).toBe('1.2.3.4');
    expect(decoded.criticality).toBe(true);
    expect(decoded.controlValue).toEqual(Buffer.from([0x01, 0x02]));
  });

  it('encodes and decodes controls list', () => {
    const ctrls: LdapControl[] = [
      createSimplePagedResultsControl(500, Buffer.alloc(0)),
      createSDFlagsControl(0x5),
    ];
    const encoded = encodeControls(ctrls);
    const decoded = decodeControls(encoded);
    expect(decoded.length).toBe(2);
    expect(decoded[0]!.controlType).toBe(CONTROL_PAGEDRESULTS);
    expect(decoded[1]!.controlType).toBe(CONTROL_SDFLAGS);
  });

  it('encodes LDAPMessage with controls', () => {
    const searchReq = encodeSearchRequest({
      baseObject: '',
      scope: Scope.baseObject,
      derefAliases: DerefAliases.neverDerefAliases,
      sizeLimit: 0,
      timeLimit: 0,
      typesOnly: false,
      filter: { present: 'objectClass' },
      attributes: [],
    });
    const ctrls = [createSimplePagedResultsControl(100, Buffer.alloc(0))];
    const msg = encodeLDAPMessage(5, searchReq, ctrls);
    const decoded = decodeLDAPMessage(msg);
    expect(decoded.messageID).toBe(5);
    expect(decoded.controls).not.toBeNull();
    expect(decoded.controls!.length).toBe(1);
    expect(decoded.controls![0]!.controlType).toBe(CONTROL_PAGEDRESULTS);
  });
});

describe('ldapasn1 — other operations', () => {
  it('encodes ModifyRequest', () => {
    const encoded = encodeModifyRequest({
      object: 'CN=test,DC=com',
      changes: [
        {
          operation: 2,
          modification: { type: 'description', vals: ['new value'] },
        },
      ],
    });
    expect(encoded[0]).toBe(0x66);
  });

  it('encodes AddRequest', () => {
    const encoded = encodeAddRequest({
      entry: 'CN=test,DC=com',
      attributes: [{ type: 'objectClass', vals: ['user'] }],
    });
    expect(encoded[0]).toBe(0x68);
  });

  it('encodes DelRequest', () => {
    const encoded = encodeDelRequest('CN=test,DC=com');
    expect(encoded[0]).toBe(0x4a);
  });

  it('encodes ModifyDNRequest', () => {
    const encoded = encodeModifyDNRequest({
      entry: 'CN=test,DC=com',
      newrdn: 'CN=new',
      deleteoldrdn: true,
    });
    expect(encoded[0]).toBe(0x6c);
  });

  it('encodes CompareRequest', () => {
    const encoded = encodeCompareRequest({
      entry: 'CN=test,DC=com',
      ava: { attributeDesc: 'sn', assertionValue: 'test' },
    });
    expect(encoded[0]).toBe(0x6e);
  });

  it('encodes AbandonRequest', () => {
    const encoded = encodeAbandonRequest(42);
    expect(encoded[0]).toBe(0x50);
  });

  it('encodes ExtendedRequest', () => {
    const encoded = encodeExtendedRequest({
      requestName: '1.3.6.1.4.1.4203.1.11.1',
      requestValue: null,
    });
    expect(encoded[0]).toBe(0x77);
  });

  it('encodes UnbindRequest', () => {
    const encoded = encodeUnbindRequest();
    expect(encoded[0]).toBe(0x42);
  });
});

describe('ldapasn1 — BindResponse decode', () => {
  it('decodes a success bind response', () => {
    const body = Buffer.concat([
      encodeTLV(TagClass.UNIVERSAL, false, 10, Buffer.from([0])),
      encodeTLV(TagClass.UNIVERSAL, false, 4, Buffer.alloc(0)),
      encodeTLV(TagClass.UNIVERSAL, false, 4, Buffer.alloc(0)),
    ]);
    const resp = encodeTLVApplication(1, body);
    const decoded = decodeBindResponse(resp);
    expect(decoded.resultCode).toBe(ResultCode.success);
    expect(decoded.matchedDN).toBe('');
    expect(decoded.diagnosticMessage).toBe('');
  });

  it('decodes a saslBindInProgress response with serverSaslCreds', () => {
    const creds = Buffer.from([0xa1, 0x03, 0x04, 0x01, 0xff]);
    const body = Buffer.concat([
      encodeTLV(TagClass.UNIVERSAL, false, 10, Buffer.from([14])),
      encodeTLV(TagClass.UNIVERSAL, false, 4, Buffer.alloc(0)),
      encodeTLV(TagClass.UNIVERSAL, false, 4, Buffer.alloc(0)),
      encodeTLV(TagClass.CONTEXT, false, 7, creds),
    ]);
    const resp = encodeTLVApplication(1, body);
    const decoded = decodeBindResponse(resp);
    expect(decoded.resultCode).toBe(ResultCode.saslBindInProgress);
    expect(decoded.serverSaslCreds).toEqual(creds);
  });
});

describe('ldapasn1 — SimplePagedResults value encode/decode', () => {
  it('round-trips size and cookie', () => {
    const encoded = encodeSimplePagedResultsControlValue({ size: 500, cookie: Buffer.from('abc') });
    const decoded = decodeSimplePagedResultsControlValue(encoded);
    expect(decoded.size).toBe(500);
    expect(decoded.cookie.toString()).toBe('abc');
  });
});

function encodeTLVApplication(tag: number, body: Buffer): Buffer {
  return encodeTLV(TagClass.APPLICATION, true, tag, body);
}
