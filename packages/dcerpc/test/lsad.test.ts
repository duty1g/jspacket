import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  LSAPR_HANDLE,
  LSAPR_OBJECT_ATTRIBUTES,
  LSAPR_POLICY_DNS_DOMAIN_INFO,
  LSAPR_TRUSTED_DOMAIN_INFORMATION_EX,
  LsarOpenPolicy2,
  LsarQueryInformationPolicy2,
  LsarClose,
  LsarEnumerateAccounts,
  LsarEnumerateTrustedDomainsEx,
  LsarCreateSecret,
  LsarEnumeratePrivileges,
  LsarLookupPrivilegeValue,
  LsarDeleteObject,
  MSRPC_UUID_LSAD,
  POLICY_VIEW_LOCAL_INFORMATION,
  LSAD_POLICY_LOOKUP_NAMES,
  POLICY_INFORMATION_CLASS,
  OPNUMS,
} from '../src/lsad';
import { NULL } from '../src/ndr';

describe('lsad', () => {
  it('MSRPC_UUID_LSAD is 20 bytes (UUID + version)', () => {
    expect(MSRPC_UUID_LSAD.length).toBe(20);
  });

  it('OPNUMS has 35 entries', () => {
    expect(Object.keys(OPNUMS).length).toBe(35);
  });

  it('LsarOpenPolicy2 produces non-empty data', () => {
    const req = new LsarOpenPolicy2();
    req.set('SystemName', NULL);
    req.set('DesiredAccess', POLICY_VIEW_LOCAL_INFORMATION | LSAD_POLICY_LOOKUP_NAMES);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarClose produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x41));
    const req = new LsarClose();
    req.set('ObjectHandle', handle);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarQueryInformationPolicy2 produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x42));
    const req = new LsarQueryInformationPolicy2();
    req.set('PolicyHandle', handle);
    req.set('InformationClass', POLICY_INFORMATION_CLASS.enumValues.PolicyDnsDomainInformation);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarEnumerateAccounts produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x43));
    const req = new LsarEnumerateAccounts();
    req.set('PolicyHandle', handle);
    req.set('EnumerationContext', 0);
    req.set('PreferedMaximumLength', 0xffffffff);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarEnumerateTrustedDomainsEx produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x44));
    const req = new LsarEnumerateTrustedDomainsEx();
    req.set('PolicyHandle', handle);
    req.set('EnumerationContext', 0);
    req.set('PreferedMaximumLength', 0xffffffff);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LSAPR_POLICY_DNS_DOMAIN_INFO produces non-empty data', () => {
    const info = new LSAPR_POLICY_DNS_DOMAIN_INFO();
    info.set('Name', 'TEST');
    info.set('DnsDomainName', 'test.local');
    info.set('DnsForestName', 'test.local');
    const data = info.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LSAPR_TRUSTED_DOMAIN_INFORMATION_EX produces non-empty data', () => {
    const info = new LSAPR_TRUSTED_DOMAIN_INFORMATION_EX();
    info.set('Name', 'trusted.local');
    info.set('FlatName', 'TRUSTED');
    info.set('TrustDirection', 2);
    info.set('TrustType', 2);
    info.set('TrustAttributes', 0);
    const data = info.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarCreateSecret produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x45));
    const req = new LsarCreateSecret();
    req.set('PolicyHandle', handle);
    req.set('SecretName', 'SecretName');
    req.set('DesiredAccess', 0x00000002);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarEnumeratePrivileges produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x46));
    const req = new LsarEnumeratePrivileges();
    req.set('PolicyHandle', handle);
    req.set('EnumerationContext', 0);
    req.set('PreferedMaximumLength', 0xffffffff);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarLookupPrivilegeValue produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x47));
    const req = new LsarLookupPrivilegeValue();
    req.set('PolicyHandle', handle);
    req.set('Name', 'SeDebugPrivilege');
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('LsarDeleteObject produces non-empty data', () => {
    const handle = new LSAPR_HANDLE();
    handle.set('Data', Buffer.alloc(20, 0x48));
    const req = new LsarDeleteObject();
    req.set('ObjectHandle', handle);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });
});
