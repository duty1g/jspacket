import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRUNION,
  NDRPOINTER,
  NDRENUM,
  NULL,
  type NDRField,
} from './ndr';
import { UINT, LPWSTR, GUID } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_DSSP = uuidtupToBin([
  '3919286A-B10C-11D0-9BA8-00C04FD92EF5',
  '0.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `DSSP SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

// 2.2.1 DSROLER_PRIMARY_DOMAIN_INFO_BASIC
export const DSROLE_PRIMARY_DS_RUNNING = 0x00000001;
export const DSROLE_PRIMARY_DS_MIXED_MODE = 0x00000002;
export const DSROLE_PRIMARY_DS_READONLY = 0x00000008;
export const DSROLE_PRIMARY_DOMAIN_GUID_PRESENT = 0x01000000;

// 2.2.5 DSROLE_UPGRADE_STATUS_INFO
export const DSROLE_UPGRADE_IN_PROGRESS = 0x00000004;

// 2.2.2 DSROLE_MACHINE_ROLE
export class DSROLE_MACHINE_ROLE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DsRole_RoleStandaloneWorkstation',
    1: 'DsRole_RoleMemberWorkstation',
    2: 'DsRole_RoleStandaloneServer',
    3: 'DsRole_RoleMemberServer',
    4: 'DsRole_RoleBackupDomainController',
    5: 'DsRole_RolePrimaryDomainController',
  };
  static enumValues: Record<string, number> = {
    DsRole_RoleStandaloneWorkstation: 0,
    DsRole_RoleMemberWorkstation: 1,
    DsRole_RoleStandaloneServer: 2,
    DsRole_RoleMemberServer: 3,
    DsRole_RoleBackupDomainController: 4,
    DsRole_RolePrimaryDomainController: 5,
  };
}

// 2.2.1 DSROLER_PRIMARY_DOMAIN_INFO_BASIC
export class DSROLER_PRIMARY_DOMAIN_INFO_BASIC extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['MachineRole', DSROLE_MACHINE_ROLE],
    ['Flags', UINT],
    ['DomainNameFlat', LPWSTR],
    ['DomainNameDns', LPWSTR],
    ['DomainForestName', LPWSTR],
    ['DomainGuid', GUID],
  ];
}

export class PDSROLER_PRIMARY_DOMAIN_INFO_BASIC extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', DSROLER_PRIMARY_DOMAIN_INFO_BASIC],
  ];
}

// 2.2.4 DSROLE_OPERATION_STATE
export class DSROLE_OPERATION_STATE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DsRoleOperationIdle',
    1: 'DsRoleOperationActive',
    2: 'DsRoleOperationNeedReboot',
  };
  static enumValues: Record<string, number> = {
    DsRoleOperationIdle: 0,
    DsRoleOperationActive: 1,
    DsRoleOperationNeedReboot: 2,
  };
}

// 2.2.3 DSROLE_OPERATION_STATE_INFO
export class DSROLE_OPERATION_STATE_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['OperationState', DSROLE_OPERATION_STATE],
  ];
}

export class PDSROLE_OPERATION_STATE_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DSROLE_OPERATION_STATE_INFO]];
}

// 2.2.6 DSROLE_SERVER_STATE
export class DSROLE_SERVER_STATE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'DsRoleServerUnknown',
    1: 'DsRoleServerPrimary',
    2: 'DsRoleServerBackup',
  };
  static enumValues: Record<string, number> = {
    DsRoleServerUnknown: 0,
    DsRoleServerPrimary: 1,
    DsRoleServerBackup: 2,
  };
}

export class PDSROLE_SERVER_STATE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DSROLE_SERVER_STATE]];
}

// 2.2.5 DSROLE_UPGRADE_STATUS_INFO
export class DSROLE_UPGRADE_STATUS_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['OperationState', UINT],
    ['PreviousServerState', DSROLE_SERVER_STATE],
  ];
}

export class PDSROLE_UPGRADE_STATUS_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DSROLE_UPGRADE_STATUS_INFO]];
}

// 2.2.7 DSROLE_PRIMARY_DOMAIN_INFO_LEVEL
export class DSROLE_PRIMARY_DOMAIN_INFO_LEVEL extends NDRENUM {
  static DsRolePrimaryDomainInfoBasic = 1;
  static DsRoleUpgradeStatus = 2;
  static DsRoleOperationState = 3;

  static enumItems: Record<number, string> = {
    1: 'DsRolePrimaryDomainInfoBasic',
    2: 'DsRoleUpgradeStatus',
    3: 'DsRoleOperationState',
  };
  static enumValues: Record<string, number> = {
    DsRolePrimaryDomainInfoBasic: 1,
    DsRoleUpgradeStatus: 2,
    DsRoleOperationState: 3,
  };
}

// 2.2.8 DSROLER_PRIMARY_DOMAIN_INFORMATION
export class DSROLER_PRIMARY_DOMAIN_INFORMATION extends NDRUNION {
  static commonHdr: NDRField[] = [
    ['tag', DSROLE_PRIMARY_DOMAIN_INFO_LEVEL],
  ];
  static union: Record<number, NDRField> = {
    1: ['DomainInfoBasic', DSROLER_PRIMARY_DOMAIN_INFO_BASIC],
    2: ['UpgradStatusInfo', DSROLE_UPGRADE_STATUS_INFO],
    3: ['OperationStateInfo', DSROLE_OPERATION_STATE_INFO],
  };
}

export class PDSROLER_PRIMARY_DOMAIN_INFORMATION extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', DSROLER_PRIMARY_DOMAIN_INFORMATION],
  ];
}

// 3.2.5.1 DsRolerGetPrimaryDomainInformation (Opnum 0)
export class DsRolerGetPrimaryDomainInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DomainInfo', PDSROLER_PRIMARY_DOMAIN_INFORMATION],
  ];
}

export class DsRolerGetPrimaryDomainInformation extends NDRCALL {
  static opnum = 0;
  static Response = DsRolerGetPrimaryDomainInformationResponse;
  static structure: NDRField[] = [
    ['InfoLevel', DSROLE_PRIMARY_DOMAIN_INFO_LEVEL],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [
    DsRolerGetPrimaryDomainInformation,
    DsRolerGetPrimaryDomainInformationResponse,
  ],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hDsRolerGetPrimaryDomainInformation(
  dce: DCERPC_v5,
  infoLevel: number,
): Promise<DsRolerGetPrimaryDomainInformationResponse> {
  const request = new DsRolerGetPrimaryDomainInformation();
  request.set('InfoLevel', infoLevel);
  return (dce as unknown as { request: DceRequestFn }).request<DsRolerGetPrimaryDomainInformationResponse>(
    request,
  );
}
