import { Buffer } from 'node:buffer';
import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDR,
  NDRSTRUCT,
  NDRPOINTER,
  NDRPOINTERNULL,
  NDRUniConformantArray,
  NDRUNION,
  NULL,
  type NDRField,
} from './ndr';
import {
  DWORD,
  LPWSTR,
  ULONG,
  BOOL,
  LPBYTE,
  ULONGLONG,
  PGUID,
  USHORT,
  LPDWORD,
  WSTR,
  GUID,
  PBOOL,
  WIDESTR,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_SCMR = uuidtupToBin(['367ABB81-9844-35F1-AD32-98F038001003', '2.0'])!;

export const SERVICE_ALL_ACCESS = 0x000f01ff;
export const SERVICE_CHANGE_CONFIG = 0x00000002;
export const SERVICE_ENUMERATE_DEPENDENTS = 0x00000008;
export const SERVICE_INTERROGATE = 0x00000080;
export const SERVICE_PAUSE_CONTINUE = 0x00000040;
export const SERVICE_QUERY_CONFIG = 0x00000001;
export const SERVICE_QUERY_STATUS = 0x00000004;
export const SERVICE_START = 0x00000010;
export const SERVICE_STOP = 0x00000020;
export const SERVICE_USER_DEFINED_CTRL = 0x00000100;
export const SERVICE_SET_STATUS = 0x00008000;

export const SC_MANAGER_LOCK = 0x00000008;
export const SC_MANAGER_CREATE_SERVICE = 0x00000002;
export const SC_MANAGER_ENUMERATE_SERVICE = 0x00000004;
export const SC_MANAGER_CONNECT = 0x00000001;
export const SC_MANAGER_QUERY_LOCK_STATUS = 0x00000010;
export const SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020;

export const SERVICE_KERNEL_DRIVER = 0x00000001;
export const SERVICE_FILE_SYSTEM_DRIVER = 0x00000002;
export const SERVICE_WIN32_OWN_PROCESS = 0x00000010;
export const SERVICE_WIN32_SHARE_PROCESS = 0x00000020;
export const SERVICE_INTERACTIVE_PROCESS = 0x00000100;
export const SERVICE_NO_CHANGE = 0xffffffff;

export const SERVICE_BOOT_START = 0x00000000;
export const SERVICE_SYSTEM_START = 0x00000001;
export const SERVICE_AUTO_START = 0x00000002;
export const SERVICE_DEMAND_START = 0x00000003;
export const SERVICE_DISABLED = 0x00000004;

export const SERVICE_ERROR_IGNORE = 0x00000000;
export const SERVICE_ERROR_NORMAL = 0x00000001;
export const SERVICE_ERROR_SEVERE = 0x00000002;
export const SERVICE_ERROR_CRITICAL = 0x00000003;

export const SERVICE_CONTROL_CONTINUE = 0x00000003;
export const SERVICE_CONTROL_INTERROGATE = 0x00000004;
export const SERVICE_CONTROL_PARAMCHANGE = 0x00000006;
export const SERVICE_CONTROL_PAUSE = 0x00000002;
export const SERVICE_CONTROL_STOP = 0x00000001;
export const SERVICE_CONTROL_NETBINDADD = 0x00000007;
export const SERVICE_CONTROL_NETBINDREMOVE = 0x00000008;
export const SERVICE_CONTROL_NETBINDENABLE = 0x00000009;
export const SERVICE_CONTROL_NETBINDDISABLE = 0x0000000a;

export const SERVICE_ACTIVE = 0x00000001;
export const SERVICE_INACTIVE = 0x00000002;
export const SERVICE_STATE_ALL = 0x00000003;

export const SERVICE_CONTINUE_PENDING = 0x00000005;
export const SERVICE_PAUSE_PENDING = 0x00000006;
export const SERVICE_PAUSED = 0x00000007;
export const SERVICE_RUNNING = 0x00000004;
export const SERVICE_START_PENDING = 0x00000002;
export const SERVICE_STOP_PENDING = 0x00000003;
export const SERVICE_STOPPED = 0x00000001;

export const SERVICE_ACCEPT_PARAMCHANGE = 0x00000008;
export const SERVICE_ACCEPT_PAUSE_CONTINUE = 0x00000002;
export const SERVICE_ACCEPT_SHUTDOWN = 0x00000004;
export const SERVICE_ACCEPT_STOP = 0x00000001;
export const SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020;
export const SERVICE_ACCEPT_POWEREVENT = 0x00000040;
export const SERVICE_ACCEPT_SESSIONCHANGE = 0x00000080;
export const SERVICE_ACCEPT_PRESHUTDOWN = 0x00000100;
export const SERVICE_ACCEPT_TIMECHANGE = 0x00000200;
export const ERVICE_ACCEPT_TRIGGEREVENT = 0x00000400;

export const SERVICE_CONFIG_DESCRIPTION = 0x00000001;
export const SERVICE_CONFIG_FAILURE_ACTIONS = 0x00000002;
export const SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 0x00000003;
export const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 0x00000004;
export const SERVICE_CONFIG_SERVICE_SID_INFO = 0x00000005;
export const SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 0x00000006;
export const SERVICE_CONFIG_PRESHUTDOWN_INFO = 0x00000007;
export const SERVICE_CONFIG_PREFERRED_NODE = 0x00000009;
export const SERVICE_CONFIG_RUNLEVEL_INFO = 0x0000000a;

export const SC_ACTION_NONE = 0;
export const SC_ACTION_RESTART = 1;
export const SC_ACTION_REBOOT = 2;
export const SC_ACTION_RUN_COMMAND = 3;

export const SERVICE_SID_TYPE_NONE = 0x00000000;
export const SERVICE_SID_TYPE_RESTRICTED = 0x00000003;
export const SERVICE_SID_TYPE_UNRESTRICTED = 0x00000001;

export const SC_STATUS_PROCESS_INFO = 0;

export const SERVICE_NOTIFY_CREATED = 0x00000080;
export const SERVICE_NOTIFY_CONTINUE_PENDING = 0x00000010;
export const SERVICE_NOTIFY_DELETE_PENDING = 0x00000200;
export const SERVICE_NOTIFY_DELETED = 0x00000100;
export const SERVICE_NOTIFY_PAUSE_PENDING = 0x00000020;
export const SERVICE_NOTIFY_PAUSED = 0x00000040;
export const SERVICE_NOTIFY_RUNNING = 0x00000008;
export const SERVICE_NOTIFY_START_PENDING = 0x00000002;
export const SERVICE_NOTIFY_STOP_PENDING = 0x00000004;
export const SERVICE_NOTIFY_STOPPED = 0x00000001;

export const SERVICE_STOP_CUSTOM = 0x20000000;
export const SERVICE_STOP_PLANNED = 0x40000000;
export const SERVICE_STOP_UNPLANNED = 0x10000000;

export const SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL = 1;
export const SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY = 2;
export const SERVICE_TRIGGER_TYPE_DOMAIN_JOIN = 3;
export const SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT = 4;
export const SERVICE_TRIGGER_TYPE_GROUP_POLICY = 5;
export const SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT = 6;
export const SERVICE_TRIGGER_TYPE_CUSTOM = 20;

export const SERVICE_TRIGGER_ACTION_SERVICE_START = 0x00000001;
export const SERVICE_TRIGGER_ACTION_SERVICE_STOP = 0x00000002;

export const DOMAIN_JOIN_GUID = '1ce20aba-9851-4421-9430-1ddeb766e809';
export const DOMAIN_LEAVE_GUID = 'ddaf516e-58c2-4866-9574-c3b615d42ea1';
export const FIREWALL_PORT_OPEN_GUID = 'b7569e07-8421-4ee0-ad10-86915afdad09';
export const FIREWALL_PORT_CLOSE_GUID = 'a144ed38-8e12-4de4-9d96-e64740b1a524';
export const MACHINE_POLICY_PRESENT_GUID = '659FCAE6-5BDB-4DA9-B1FF-CA2A178D46E0';
export const NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID = '4f27f2de-14e2-430b-a549-7cd48cbc8245';
export const NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID = 'cc4ba62a-162e-4648-847a-b6bdf993e335';
export const USER_POLICY_PRESENT_GUID = '54FB46C8-F089-464C-B1FD-59D1B62C3B50';

export const SERVICE_TRIGGER_DATA_TYPE_BINARY = 0x00000001;
export const SERVICE_TRIGGER_DATA_TYPE_STRING = 0x00000002;
export const SERVICE_TRIGGER_DATA_TYPE_LEVEL = 0x00000003;
export const SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY = 0x00000004;
export const SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL = 0x00000005;

export class ByteArray extends NDRUniConformantArray {
  static item = 'c';
}

export class ScRpcHandle extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=""']];
  getAlignment(): number {
    return 1;
  }
}

export const ScNotifyRpcHandle = ScRpcHandle;

export class ServiceStatus extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwServiceType', DWORD],
    ['dwCurrentState', DWORD],
    ['dwControlsAccepted', DWORD],
    ['dwWin32ExitCode', DWORD],
    ['dwServiceSpecificExitCode', DWORD],
    ['dwCheckPoint', DWORD],
    ['dwWaitHint', DWORD],
  ];
}

export class QueryServiceConfigW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwServiceType', DWORD],
    ['dwStartType', DWORD],
    ['dwErrorControl', DWORD],
    ['lpBinaryPathName', LPWSTR],
    ['lpLoadOrderGroup', LPWSTR],
    ['dwTagId', DWORD],
    ['lpDependencies', LPWSTR],
    ['lpServiceStartName', LPWSTR],
    ['lpDisplayName', LPWSTR],
  ];
}

export class ScRpcLock extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=""']];
  getAlignment(): number {
    return 1;
  }
}

export class LpServiceStatus extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceStatus]];
}

export const ScmrSecurityInformation = ULONG;
export const BoundedDword256K = DWORD;
export const BoundedDword8K = DWORD;
export const BoundedDword4K = DWORD;

export class LpBoundedDword256K extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BoundedDword256K]];
}

export const SvcctlHandleW = LPWSTR;

export class EnumServiceStatusW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['lpServiceName', LPWSTR],
    ['lpDisplayName', LPWSTR],
    ['ServiceStatus', ServiceStatus],
  ];
}

export class LpQueryServiceConfigW extends NDRPOINTER {
  static referent: NDRField[] = [['Data', QueryServiceConfigW]];
}

export class StringPtrsW extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', NDRUniConformantArray]];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(null, isNDR64);
    (this.fields['Data'] as NDRUniConformantArray).item = LPWSTR;
    if (data) {
      this.fromString(data);
    }
  }
}

export class UniqueStringPtrsW extends NDRPOINTER {
  static referent: NDRField[] = [['Data', StringPtrsW]];
}

export class QueryServiceLockStatusW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['fIsLocked', DWORD],
    ['lpLockOwner', LPWSTR],
    ['dwLockDuration', DWORD],
  ];
}

export class ServiceDescriptionWow64 extends NDRSTRUCT {
  static structure: NDRField[] = [['dwDescriptionOffset', DWORD]];
}

export class ServiceDescriptionW extends NDRSTRUCT {
  static structure: NDRField[] = [['lpDescription', LPWSTR]];
}

export class LpServiceDescriptionW extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceDescriptionW]];
}

export class ServiceFailureActionsWow64 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwResetPeriod', DWORD],
    ['dwRebootMsgOffset', DWORD],
    ['dwCommandOffset', DWORD],
    ['cActions', DWORD],
    ['dwsaActionsOffset', DWORD],
  ];
}

export class ScAction extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Type', DWORD],
    ['Delay', DWORD],
  ];
}

export class ScActionArray extends NDRUniConformantArray {
  static item = ScAction;
}

export class ScActions extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ScActionArray]];
}

export class ServiceFailureActionsW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwResetPeriod', DWORD],
    ['lpRebootMsg', LPWSTR],
    ['lpCommand', LPWSTR],
    ['cActions', DWORD],
    ['lpsaActions', ScActions],
  ];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(data, isNDR64);
    if (data == null) {
      this.set('lpsaActions', NULL);
    }
  }

  getData(soFar = 0): Buffer {
    const actions = this.get('lpsaActions');
    if (actions === 0 || actions == null) {
      this.set('cActions', 0);
    } else if (Array.isArray(actions)) {
      this.set('cActions', actions.length);
    }
    return NDR.prototype.getData.call(this, soFar);
  }
}

export class LpServiceFailureActionsW extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceFailureActionsW]];
}

export class ServiceFailureActionsFlag extends NDRSTRUCT {
  static structure: NDRField[] = [['fFailureActionsOnNonCrashFailures', BOOL]];
}

export class LpServiceFailureActionsFlag extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceFailureActionsFlag]];
}

export class ServiceDelayedAutoStartInfo extends NDRSTRUCT {
  static structure: NDRField[] = [['fDelayedAutostart', BOOL]];
}

export class LpServiceDelayedAutoStartInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceDelayedAutoStartInfo]];
}

export class ServiceSidInfo extends NDRSTRUCT {
  static structure: NDRField[] = [['dwServiceSidType', DWORD]];
}

export class LpServiceSidInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceSidInfo]];
}

export class ServiceRpcRequiredPrivilegesInfo extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cbRequiredPrivileges', DWORD],
    ['pRequiredPrivileges', LPBYTE],
  ];

  getData(soFar = 0): Buffer {
    const priv = this.get('pRequiredPrivileges');
    if (priv && typeof priv === 'object' && 'fields' in priv) {
      const lpbyte = priv as LPBYTE;
      const data = lpbyte.fields['Data'] as NDRUniConformantArray;
      const arr = data.fields['Data'] as unknown[];
      this.set('cbRequiredPrivileges', arr.length);
    }
    return NDR.prototype.getData.call(this, soFar);
  }
}

export class LpServiceRpcRequiredPrivilegesInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceRpcRequiredPrivilegesInfo]];
}

export class ServiceRequiredPrivilegesInfoWow64 extends NDRSTRUCT {
  static structure: NDRField[] = [['dwRequiredPrivilegesOffset', DWORD]];
}

export class ServicePreshutdownInfo extends NDRSTRUCT {
  static structure: NDRField[] = [['dwPreshutdownTimeout', DWORD]];
}

export class LpServicePreshutdownInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServicePreshutdownInfo]];
}

export class ServiceStatusProcess extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwServiceType', DWORD],
    ['dwCurrentState', DWORD],
    ['dwControlsAccepted', DWORD],
    ['dwWin32ExitCode', DWORD],
    ['dwServiceSpecificExitCode', DWORD],
    ['dwCheckPoint', DWORD],
    ['dwWaitHint', DWORD],
    ['dwProcessId', DWORD],
    ['dwServiceFlags', DWORD],
  ];
}

export class Uchar16 extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '16s=""']];
  getAlignment(): number {
    return 1;
  }
}

export class ServiceNotifyStatusChangeParams1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ullThreadId', ULONGLONG],
    ['dwNotifyMask', DWORD],
    ['CallbackAddressArray', Uchar16],
    ['CallbackParamAddressArray', Uchar16],
    ['ServiceStatus', ServiceStatusProcess],
    ['dwNotificationStatus', DWORD],
    ['dwSequence', DWORD],
  ];
}

export class ServiceNotifyStatusChangeParams2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ullThreadId', ULONGLONG],
    ['dwNotifyMask', DWORD],
    ['CallbackAddressArray', Uchar16],
    ['CallbackParamAddressArray', Uchar16],
    ['ServiceStatus', ServiceStatusProcess],
    ['dwNotificationStatus', DWORD],
    ['dwSequence', DWORD],
    ['dwNotificationTriggered', DWORD],
    ['pszServiceNames', LPWSTR],
  ];
}

export class PServiceNotifyStatusChangeParams1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceNotifyStatusChangeParams1]];
}

export class PServiceNotifyStatusChangeParams2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceNotifyStatusChangeParams2]];
}

export class ScRpcNotifyParams extends NDRUNION {
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['pStatusChangeParam1', PServiceNotifyStatusChangeParams1],
    2: ['pStatusChangeParams', PServiceNotifyStatusChangeParams2],
  };
}

export class ScRpcNotifyParamsArray extends NDRUniConformantArray {
  static item = ScRpcNotifyParams;
}

export class PScRpcNotifyParamsList extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cElements', BoundedDword4K],
    ['NotifyParamsArray', ScRpcNotifyParamsArray],
  ];
}

export class PPScRpcNotifyParamsList extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PScRpcNotifyParamsList]];
}

export class ServiceControlStatusReasonInParamsW extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwReason', DWORD],
    ['pszComment', LPWSTR],
  ];
}

export class ServiceTriggerSpecificDataItem extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwDataType', DWORD],
    ['cbData', DWORD],
    ['pData', LPBYTE],
  ];

  getData(soFar = 0): Buffer {
    const data = this.get('pData');
    if (data && typeof data === 'object' && 'fields' in data) {
      const lpbyte = data as LPBYTE;
      const arr = (lpbyte.fields['Data'] as NDRUniConformantArray).fields['Data'] as unknown[];
      this.set('cbData', arr.length);
    }
    return NDR.prototype.getData.call(this, soFar);
  }
}

export class ServiceTriggerSpecificDataItemArray extends NDRUniConformantArray {
  static item = ServiceTriggerSpecificDataItem;
}

export class PServiceTriggerSpecificDataItem extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceTriggerSpecificDataItemArray]];
}

export class ServiceTrigger extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwTriggerType', DWORD],
    ['dwAction', DWORD],
    ['pTriggerSubtype', PGUID],
    ['cDataItems', DWORD],
    ['pDataItems', PServiceTriggerSpecificDataItem],
  ];

  getData(soFar = 0): Buffer {
    const items = this.get('pDataItems');
    if (items && typeof items === 'object' && 'fields' in items) {
      const ptr = items as PServiceTriggerSpecificDataItem;
      const arr = (ptr.fields['Data'] as ServiceTriggerSpecificDataItemArray).fields['Data'] as unknown[];
      this.set('cDataItems', arr.length);
    }
    return NDR.prototype.getData.call(this, soFar);
  }
}

export class ServiceTriggerArray extends NDRUniConformantArray {
  static item = ServiceTrigger;
}

export class PServiceTrigger extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceTriggerArray]];
}

export class ServiceControlStatusReasonOutParams extends NDRSTRUCT {
  static structure: NDRField[] = [['ServiceStatus', ServiceStatusProcess]];
}

export class ServiceTriggerInfo extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cTriggers', DWORD],
    ['pTriggers', PServiceTrigger],
    ['pReserved', NDRPOINTERNULL],
  ];

  getData(soFar = 0): Buffer {
    const triggers = this.get('pTriggers');
    if (triggers && typeof triggers === 'object' && 'fields' in triggers) {
      const ptr = triggers as PServiceTrigger;
      const arr = (ptr.fields['Data'] as ServiceTriggerArray).fields['Data'] as unknown[];
      this.set('cTriggers', arr.length);
    }
    return NDR.prototype.getData.call(this, soFar);
  }
}

export class PServiceTriggerInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceTriggerInfo]];
}

export class ServicePreferredNodeInfo extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['usPreferredNode', USHORT],
    ['fDelete', BOOL],
  ];
}

export class LpServicePreferredNodeInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServicePreferredNodeInfo]];
}

export class ServiceRunlevelInfo extends NDRSTRUCT {
  static structure: NDRField[] = [['eLowestRunLevel', DWORD]];
}

export class PServiceRunlevelInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceRunlevelInfo]];
}

export class ServiceManagedAccountInfo extends NDRSTRUCT {
  static structure: NDRField[] = [['fIsManagedAccount', DWORD]];
}

export class PServiceManagedAccountInfo extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ServiceManagedAccountInfo]];
}

export class ScRpcConfigInfowUnion extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    1: ['psd', LpServiceDescriptionW],
    2: ['psfa', LpServiceFailureActionsW],
    3: ['psda', LpServiceDelayedAutoStartInfo],
    4: ['psfaf', LpServiceFailureActionsFlag],
    5: ['pssid', LpServiceSidInfo],
    6: ['psrp', LpServiceRpcRequiredPrivilegesInfo],
    7: ['psps', LpServicePreshutdownInfo],
    8: ['psti', PServiceTriggerInfo],
    9: ['pspn', LpServicePreferredNodeInfo],
    10: ['psri', PServiceRunlevelInfo],
    11: ['psma', PServiceManagedAccountInfo],
  };
}

export class ScRpcConfigInfow extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwInfoLevel', DWORD],
    ['Union', ScRpcConfigInfowUnion],
  ];
}

export class RCloseServiceHandleResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['hSCObject', ScRpcHandle],
    ['ErrorCode', DWORD],
  ];
}

export class RCloseServiceHandle extends NDRCALL {
  static opnum = 0;
  static structure: NDRField[] = [['hSCObject', ScRpcHandle]];
  static Response = RCloseServiceHandleResponse;
}

export class RControlServiceResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpServiceStatus', ServiceStatus],
    ['ErrorCode', DWORD],
  ];
}

export class RControlService extends NDRCALL {
  static opnum = 1;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwControl', DWORD],
  ];
  static Response = RControlServiceResponse;
}

export class RDeleteServiceResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', DWORD]];
}

export class RDeleteService extends NDRCALL {
  static opnum = 2;
  static structure: NDRField[] = [['hService', ScRpcHandle]];
  static Response = RDeleteServiceResponse;
}

export class RLockServiceDatabaseResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpLock', ScRpcLock],
    ['ErrorCode', DWORD],
  ];
}

export class RLockServiceDatabase extends NDRCALL {
  static opnum = 3;
  static structure: NDRField[] = [['hSCManager', ScRpcHandle]];
  static Response = RLockServiceDatabaseResponse;
}

export class RQueryServiceObjectSecurityResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpSecurityDescriptor', ByteArray],
    ['pcbBytesNeeded', BoundedDword256K],
    ['ErrorCode', DWORD],
  ];
}

export class RQueryServiceObjectSecurity extends NDRCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwSecurityInformation', ScmrSecurityInformation],
    ['cbBufSize', DWORD],
  ];
  static Response = RQueryServiceObjectSecurityResponse;
}

export class RSetServiceObjectSecurityResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', DWORD]];
}

export class RSetServiceObjectSecurity extends NDRCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwSecurityInformation', ScmrSecurityInformation],
    ['lpSecurityDescriptor', ByteArray],
    ['cbBufSize', DWORD],
  ];
  static Response = RSetServiceObjectSecurityResponse;
}

export class RQueryServiceStatusResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpServiceStatus', ServiceStatus],
    ['ErrorCode', DWORD],
  ];
}

export class RQueryServiceStatus extends NDRCALL {
  static opnum = 6;
  static structure: NDRField[] = [['hService', ScRpcHandle]];
  static Response = RQueryServiceStatusResponse;
}

export class RSetServiceStatusResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', DWORD]];
}

export class RSetServiceStatus extends NDRCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['hServiceStatus', ScRpcHandle],
    ['lpServiceStatus', ServiceStatus],
  ];
  static Response = RSetServiceStatusResponse;
}

export class RUnlockServiceDatabaseResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Lock', ScRpcLock],
    ['ErrorCode', DWORD],
  ];
}

export class RUnlockServiceDatabase extends NDRCALL {
  static opnum = 8;
  static structure: NDRField[] = [['Lock', ScRpcLock]];
  static Response = RUnlockServiceDatabaseResponse;
}

export class RNotifyBootConfigStatusResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', DWORD]];
}

export class RNotifyBootConfigStatus extends NDRCALL {
  static opnum = 9;
  static structure: NDRField[] = [
    ['lpMachineName', SvcctlHandleW],
    ['BootAcceptable', DWORD],
  ];
  static Response = RNotifyBootConfigStatusResponse;
}

export class RChangeServiceConfigWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpdwTagId', LPDWORD],
    ['ErrorCode', DWORD],
  ];
}

export class RChangeServiceConfigW extends NDRCALL {
  static opnum = 11;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwServiceType', DWORD],
    ['dwStartType', DWORD],
    ['dwErrorControl', DWORD],
    ['lpBinaryPathName', LPWSTR],
    ['lpLoadOrderGroup', LPWSTR],
    ['lpdwTagId', LPDWORD],
    ['lpDependencies', LPBYTE],
    ['dwDependSize', DWORD],
    ['lpServiceStartName', LPWSTR],
    ['lpPassword', LPBYTE],
    ['dwPwSize', DWORD],
    ['lpDisplayName', LPWSTR],
  ];
  static Response = RChangeServiceConfigWResponse;
}

export class RCreateServiceWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpdwTagId', LPWSTR],
    ['lpServiceHandle', ScRpcHandle],
    ['ErrorCode', DWORD],
  ];
}

export class RCreateServiceW extends NDRCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['lpServiceName', WSTR],
    ['lpDisplayName', LPWSTR],
    ['dwDesiredAccess', DWORD],
    ['dwServiceType', DWORD],
    ['dwStartType', DWORD],
    ['dwErrorControl', DWORD],
    ['lpBinaryPathName', WSTR],
    ['lpLoadOrderGroup', LPWSTR],
    ['lpdwTagId', LPDWORD],
    ['lpDependencies', LPBYTE],
    ['dwDependSize', DWORD],
    ['lpServiceStartName', LPWSTR],
    ['lpPassword', LPBYTE],
    ['dwPwSize', DWORD],
  ];
  static Response = RCreateServiceWResponse;
}

export class REnumDependentServicesWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpServices', NDRUniConformantArray],
    ['pcbBytesNeeded', BoundedDword256K],
    ['lpServicesReturned', BoundedDword256K],
    ['ErrorCode', DWORD],
  ];
}

export class REnumDependentServicesW extends NDRCALL {
  static opnum = 13;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwServiceState', DWORD],
    ['cbBufSize', DWORD],
  ];
  static Response = REnumDependentServicesWResponse;
}

export class REnumServicesStatusWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpBuffer', NDRUniConformantArray],
    ['pcbBytesNeeded', BoundedDword256K],
    ['lpServicesReturned', BoundedDword256K],
    ['lpResumeIndex', LpBoundedDword256K],
    ['ErrorCode', DWORD],
  ];
}

export class REnumServicesStatusW extends NDRCALL {
  static opnum = 14;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['dwServiceType', DWORD],
    ['dwServiceState', DWORD],
    ['cbBufSize', DWORD],
    ['lpResumeIndex', LpBoundedDword256K],
  ];
  static Response = REnumServicesStatusWResponse;
}

export class ROpenSCManagerWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpScHandle', ScRpcHandle],
    ['ErrorCode', DWORD],
  ];
}

export class ROpenSCManagerW extends NDRCALL {
  static opnum = 15;
  static structure: NDRField[] = [
    ['lpMachineName', SvcctlHandleW],
    ['lpDatabaseName', LPWSTR],
    ['dwDesiredAccess', DWORD],
  ];
  static Response = ROpenSCManagerWResponse;
}

export class ROpenServiceWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpServiceHandle', ScRpcHandle],
    ['ErrorCode', DWORD],
  ];
}

export class ROpenServiceW extends NDRCALL {
  static opnum = 16;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['lpServiceName', WSTR],
    ['dwDesiredAccess', DWORD],
  ];
  static Response = ROpenServiceWResponse;
}

export class RQueryServiceConfigWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpServiceConfig', QueryServiceConfigW],
    ['pcbBytesNeeded', BoundedDword8K],
    ['ErrorCode', DWORD],
  ];
}

export class RQueryServiceConfigW extends NDRCALL {
  static opnum = 17;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['cbBufSize', DWORD],
  ];
  static Response = RQueryServiceConfigWResponse;
}

export class RQueryServiceLockStatusWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpLockStatus', QueryServiceLockStatusW],
    ['pcbBytesNeeded', BoundedDword4K],
    ['ErrorCode', DWORD],
  ];
}

export class RQueryServiceLockStatusW extends NDRCALL {
  static opnum = 18;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['cbBufSize', DWORD],
  ];
  static Response = RQueryServiceLockStatusWResponse;
}

export class RStartServiceWResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', DWORD]];
}

export class RStartServiceW extends NDRCALL {
  static opnum = 19;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['argc', DWORD],
    ['argv', UniqueStringPtrsW],
  ];
  static Response = RStartServiceWResponse;
}

export class RGetServiceDisplayNameWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpDisplayName', WSTR],
    ['lpcchBuffer', DWORD],
    ['ErrorCode', DWORD],
  ];
}

export class RGetServiceDisplayNameW extends NDRCALL {
  static opnum = 20;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['lpServiceName', WSTR],
    ['lpcchBuffer', DWORD],
  ];
  static Response = RGetServiceDisplayNameWResponse;
}

export class RGetServiceKeyNameWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpDisplayName', WSTR],
    ['lpcchBuffer', DWORD],
    ['ErrorCode', DWORD],
  ];
}

export class RGetServiceKeyNameW extends NDRCALL {
  static opnum = 21;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['lpDisplayName', WSTR],
    ['lpcchBuffer', DWORD],
  ];
  static Response = RGetServiceKeyNameWResponse;
}

export class REnumServiceGroupWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpBuffer', LPBYTE],
    ['pcbBytesNeeded', BoundedDword256K],
    ['lpServicesReturned', BoundedDword256K],
    ['lpResumeIndex', BoundedDword256K],
    ['ErrorCode', DWORD],
  ];
}

export class REnumServiceGroupW extends NDRCALL {
  static opnum = 35;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['dwServiceType', DWORD],
    ['dwServiceState', DWORD],
    ['cbBufSize', DWORD],
    ['lpResumeIndex', LpBoundedDword256K],
    ['pszGroupName', LPWSTR],
  ];
  static Response = REnumServiceGroupWResponse;
}

export class RChangeServiceConfig2WResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', DWORD]];
}

export class RChangeServiceConfig2W extends NDRCALL {
  static opnum = 37;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['Info', ScRpcConfigInfow],
  ];
  static Response = RChangeServiceConfig2WResponse;
}

export class RQueryServiceConfig2WResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpBuffer', NDRUniConformantArray],
    ['pcbBytesNeeded', BoundedDword8K],
    ['ErrorCode', DWORD],
  ];
}

export class RQueryServiceConfig2W extends NDRCALL {
  static opnum = 39;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwInfoLevel', DWORD],
    ['cbBufSize', DWORD],
  ];
  static Response = RQueryServiceConfig2WResponse;
}

export class RQueryServiceStatusExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpBuffer', NDRUniConformantArray],
    ['pcbBytesNeeded', BoundedDword8K],
    ['ErrorCode', DWORD],
  ];
}

export class RQueryServiceStatusEx extends NDRCALL {
  static opnum = 40;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['InfoLevel', DWORD],
    ['cbBufSize', DWORD],
  ];
  static Response = RQueryServiceStatusExResponse;
}

export class REnumServicesStatusExWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpBuffer', NDRUniConformantArray],
    ['pcbBytesNeeded', BoundedDword256K],
    ['lpServicesReturned', BoundedDword256K],
    ['lpResumeIndex', LpBoundedDword256K],
    ['ErrorCode', DWORD],
  ];
}

export class REnumServicesStatusExW extends NDRCALL {
  static opnum = 42;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['InfoLevel', DWORD],
    ['dwServiceType', DWORD],
    ['dwServiceState', DWORD],
    ['cbBufSize', DWORD],
    ['lpResumeIndex', LpBoundedDword256K],
    ['pszGroupName', LPWSTR],
  ];
  static Response = REnumServicesStatusExWResponse;
}

export class RCreateServiceWOW64WResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpdwTagId', LPWSTR],
    ['lpServiceHandle', ScRpcHandle],
    ['ErrorCode', DWORD],
  ];
}

export class RCreateServiceWOW64W extends NDRCALL {
  static opnum = 45;
  static structure: NDRField[] = [
    ['hSCManager', ScRpcHandle],
    ['lpServiceName', WSTR],
    ['lpDisplayName', LPWSTR],
    ['dwDesiredAccess', DWORD],
    ['dwServiceType', DWORD],
    ['dwStartType', DWORD],
    ['dwErrorControl', DWORD],
    ['lpBinaryPathName', WSTR],
    ['lpLoadOrderGroup', LPWSTR],
    ['lpdwTagId', LPDWORD],
    ['lpDependencies', LPBYTE],
    ['dwDependSize', DWORD],
    ['lpServiceStartName', LPWSTR],
    ['lpPassword', LPBYTE],
    ['dwPwSize', DWORD],
  ];
  static Response = RCreateServiceWOW64WResponse;
}

export class RNotifyServiceStatusChangeResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pSCMProcessGuid', GUID],
    ['pfCreateRemoteQueue', PBOOL],
    ['phNotify', ScNotifyRpcHandle],
    ['ErrorCode', DWORD],
  ];
}

export class RNotifyServiceStatusChange extends NDRCALL {
  static opnum = 47;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['NotifyParams', ScRpcNotifyParams],
    ['pClientProcessGuid', GUID],
  ];
  static Response = RNotifyServiceStatusChangeResponse;
}

export class RGetNotifyResultsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppNotifyParams', PPScRpcNotifyParamsList],
    ['ErrorCode', DWORD],
  ];
}

export class RGetNotifyResults extends NDRCALL {
  static opnum = 48;
  static structure: NDRField[] = [['hNotify', ScNotifyRpcHandle]];
  static Response = RGetNotifyResultsResponse;
}

export class RCloseNotifyHandleResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phNotify', ScNotifyRpcHandle],
    ['pfApcFired', PBOOL],
    ['ErrorCode', DWORD],
  ];
}

export class RCloseNotifyHandle extends NDRCALL {
  static opnum = 49;
  static structure: NDRField[] = [['phNotify', ScNotifyRpcHandle]];
  static Response = RCloseNotifyHandleResponse;
}

export class RControlServiceExWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pControlOutParams', ServiceControlStatusReasonOutParams],
    ['ErrorCode', DWORD],
  ];
}

export class RControlServiceExW extends NDRCALL {
  static opnum = 51;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwControl', DWORD],
    ['dwInfoLevel', DWORD],
    ['pControlInParams', ServiceControlStatusReasonInParamsW],
  ];
  static Response = RControlServiceExWResponse;
}

export class RQueryServiceConfigExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pInfo', ScRpcConfigInfow],
    ['ErrorCode', DWORD],
  ];
}

export class RQueryServiceConfigEx extends NDRCALL {
  static opnum = 56;
  static structure: NDRField[] = [
    ['hService', ScRpcHandle],
    ['dwInfoLevel', DWORD],
  ];
  static Response = RQueryServiceConfigExResponse;
}

const OPNUMS = {
  0: [RCloseServiceHandle, RCloseServiceHandleResponse] as const,
  1: [RControlService, RControlServiceResponse] as const,
  2: [RDeleteService, RDeleteServiceResponse] as const,
  3: [RLockServiceDatabase, RLockServiceDatabaseResponse] as const,
  4: [RQueryServiceObjectSecurity, RQueryServiceObjectSecurityResponse] as const,
  5: [RSetServiceObjectSecurity, RSetServiceObjectSecurityResponse] as const,
  6: [RQueryServiceStatus, RQueryServiceStatusResponse] as const,
  7: [RSetServiceStatus, RSetServiceStatusResponse] as const,
  8: [RUnlockServiceDatabase, RUnlockServiceDatabaseResponse] as const,
  9: [RNotifyBootConfigStatus, RNotifyBootConfigStatusResponse] as const,
  11: [RChangeServiceConfigW, RChangeServiceConfigWResponse] as const,
  12: [RCreateServiceW, RCreateServiceWResponse] as const,
  13: [REnumDependentServicesW, REnumDependentServicesWResponse] as const,
  14: [REnumServicesStatusW, REnumServicesStatusWResponse] as const,
  15: [ROpenSCManagerW, ROpenSCManagerWResponse] as const,
  16: [ROpenServiceW, ROpenServiceWResponse] as const,
  17: [RQueryServiceConfigW, RQueryServiceConfigWResponse] as const,
  18: [RQueryServiceLockStatusW, RQueryServiceLockStatusWResponse] as const,
  19: [RStartServiceW, RStartServiceWResponse] as const,
  20: [RGetServiceDisplayNameW, RGetServiceDisplayNameWResponse] as const,
  21: [RGetServiceKeyNameW, RGetServiceKeyNameWResponse] as const,
  35: [REnumServiceGroupW, REnumServiceGroupWResponse] as const,
  37: [RChangeServiceConfig2W, RChangeServiceConfig2WResponse] as const,
  39: [RQueryServiceConfig2W, RQueryServiceConfig2WResponse] as const,
  40: [RQueryServiceStatusEx, RQueryServiceStatusExResponse] as const,
  42: [REnumServicesStatusExW, REnumServicesStatusExWResponse] as const,
  45: [RCreateServiceWOW64W, RCreateServiceWOW64WResponse] as const,
  47: [RNotifyServiceStatusChange, RNotifyServiceStatusChangeResponse] as const,
  48: [RGetNotifyResults, RGetNotifyResultsResponse] as const,
  49: [RCloseNotifyHandle, RCloseNotifyHandleResponse] as const,
  51: [RControlServiceExW, RControlServiceExWResponse] as const,
  56: [RQueryServiceConfigEx, RQueryServiceConfigExResponse] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

export function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export async function hRCloseServiceHandle(dce: DCERPC_v5, hSCObject: ScRpcHandle) {
  const request = new RCloseServiceHandle();
  request.set('hSCObject', hSCObject);
  return (dce as unknown as { request: DceRequestFn }).request<RCloseServiceHandleResponse>(request);
}

export async function hRControlService(dce: DCERPC_v5, hService: ScRpcHandle, dwControl: number) {
  const request = new RControlService();
  request.set('hService', hService);
  request.set('dwControl', dwControl);
  return (dce as unknown as { request: DceRequestFn }).request<RControlServiceResponse>(request);
}

export async function hRDeleteService(dce: DCERPC_v5, hService: ScRpcHandle) {
  const request = new RDeleteService();
  request.set('hService', hService);
  return (dce as unknown as { request: DceRequestFn }).request<RDeleteServiceResponse>(request);
}

export async function hRLockServiceDatabase(dce: DCERPC_v5, hSCManager: ScRpcHandle) {
  const request = new RLockServiceDatabase();
  request.set('hSCManager', hSCManager);
  return (dce as unknown as { request: DceRequestFn }).request<RLockServiceDatabaseResponse>(request);
}

export async function hRQueryServiceObjectSecurity(
  dce: DCERPC_v5,
  hService: ScRpcHandle,
  dwSecurityInformation: number,
  cbBufSize = 0,
) {
  const request = new RQueryServiceObjectSecurity();
  request.set('hService', hService);
  request.set('dwSecurityInformation', dwSecurityInformation);
  request.set('cbBufSize', cbBufSize);
  const dceReq = dce as unknown as { request: DceRequestFn };
  try {
    return await dceReq.request<RQueryServiceObjectSecurityResponse>(request);
  } catch (e) {
    if (e instanceof DCERPCException && e.error_code === 0x0000007a) {
      const packet = (e as unknown as { packet: RQueryServiceObjectSecurityResponse }).packet;
      request.set('cbBufSize', packet.get('pcbBytesNeeded') as number);
      return dceReq.request<RQueryServiceObjectSecurityResponse>(request);
    }
    throw e;
  }
}

export async function hRSetServiceObjectSecurity(
  dce: DCERPC_v5,
  hService: ScRpcHandle,
  dwSecurityInformation: number,
  lpSecurityDescriptor: ByteArray,
  cbBufSize: number,
) {
  const request = new RSetServiceObjectSecurity();
  request.set('hService', hService);
  request.set('dwSecurityInformation', dwSecurityInformation);
  request.set('lpSecurityDescriptor', lpSecurityDescriptor);
  request.set('cbBufSize', cbBufSize);
  return (dce as unknown as { request: DceRequestFn }).request<RSetServiceObjectSecurityResponse>(request);
}

export async function hRQueryServiceStatus(dce: DCERPC_v5, hService: ScRpcHandle) {
  const request = new RQueryServiceStatus();
  request.set('hService', hService);
  return (dce as unknown as { request: DceRequestFn }).request<RQueryServiceStatusResponse>(request);
}

export async function hRSetServiceStatus(
  dce: DCERPC_v5,
  hServiceStatus: ScRpcHandle,
  lpServiceStatus: ServiceStatus,
) {
  const request = new RSetServiceStatus();
  request.set('hServiceStatus', hServiceStatus);
  request.set('lpServiceStatus', lpServiceStatus);
  return (dce as unknown as { request: DceRequestFn }).request<RSetServiceStatusResponse>(request);
}

export async function hRUnlockServiceDatabase(dce: DCERPC_v5, lock: ScRpcLock) {
  const request = new RUnlockServiceDatabase();
  request.set('Lock', lock);
  return (dce as unknown as { request: DceRequestFn }).request<RUnlockServiceDatabaseResponse>(request);
}

export async function hRNotifyBootConfigStatus(
  dce: DCERPC_v5,
  lpMachineName: string,
  bootAcceptable: number,
) {
  const request = new RNotifyBootConfigStatus();
  request.set('lpMachineName', lpMachineName);
  request.set('BootAcceptable', bootAcceptable);
  return (dce as unknown as { request: DceRequestFn }).request<RNotifyBootConfigStatusResponse>(request);
}

export async function hRChangeServiceConfigW(
  dce: DCERPC_v5,
  hService: ScRpcHandle,
  dwServiceType = SERVICE_NO_CHANGE,
  dwStartType = SERVICE_NO_CHANGE,
  dwErrorControl = SERVICE_NO_CHANGE,
  lpBinaryPathName: string | typeof NULL = NULL,
  lpLoadOrderGroup: string | typeof NULL = NULL,
  lpdwTagId: LPDWORD | typeof NULL = NULL,
  lpDependencies: LPBYTE | typeof NULL = NULL,
  dwDependSize = 0,
  lpServiceStartName: string | typeof NULL = NULL,
  lpPassword: LPBYTE | typeof NULL = NULL,
  dwPwSize = 0,
  lpDisplayName: string | typeof NULL = NULL,
) {
  const request = new RChangeServiceConfigW();
  request.set('hService', hService);
  request.set('dwServiceType', dwServiceType);
  request.set('dwStartType', dwStartType);
  request.set('dwErrorControl', dwErrorControl);
  request.set('lpBinaryPathName', checkNullString(lpBinaryPathName));
  request.set('lpLoadOrderGroup', checkNullString(lpLoadOrderGroup));
  request.set('lpdwTagId', lpdwTagId);
  request.set('lpDependencies', lpDependencies);
  request.set('dwDependSize', dwDependSize);
  request.set('lpServiceStartName', checkNullString(lpServiceStartName));
  request.set('lpPassword', lpPassword);
  request.set('dwPwSize', dwPwSize);
  request.set('lpDisplayName', checkNullString(lpDisplayName));
  return (dce as unknown as { request: DceRequestFn }).request<RChangeServiceConfigWResponse>(request);
}

export async function hRCreateServiceW(
  dce: DCERPC_v5,
  hSCManager: ScRpcHandle,
  lpServiceName: string,
  lpDisplayName: string | typeof NULL,
  dwDesiredAccess = SERVICE_ALL_ACCESS,
  dwServiceType = SERVICE_WIN32_OWN_PROCESS,
  dwStartType = SERVICE_AUTO_START,
  dwErrorControl = SERVICE_ERROR_IGNORE,
  lpBinaryPathName: string | typeof NULL = NULL,
  lpLoadOrderGroup: string | typeof NULL = NULL,
  lpdwTagId: LPDWORD | typeof NULL = NULL,
  lpDependencies: LPBYTE | typeof NULL = NULL,
  dwDependSize = 0,
  lpServiceStartName: string | typeof NULL = NULL,
  lpPassword: LPBYTE | typeof NULL = NULL,
  dwPwSize = 0,
) {
  const request = new RCreateServiceW();
  request.set('hSCManager', hSCManager);
  request.set('lpServiceName', checkNullString(lpServiceName));
  request.set('lpDisplayName', checkNullString(lpDisplayName));
  request.set('dwDesiredAccess', dwDesiredAccess);
  request.set('dwServiceType', dwServiceType);
  request.set('dwStartType', dwStartType);
  request.set('dwErrorControl', dwErrorControl);
  request.set('lpBinaryPathName', checkNullString(lpBinaryPathName));
  request.set('lpLoadOrderGroup', checkNullString(lpLoadOrderGroup));
  request.set('lpdwTagId', lpdwTagId);
  request.set('lpDependencies', lpDependencies);
  request.set('dwDependSize', dwDependSize);
  request.set('lpServiceStartName', checkNullString(lpServiceStartName));
  request.set('lpPassword', lpPassword);
  request.set('dwPwSize', dwPwSize);
  return (dce as unknown as { request: DceRequestFn }).request<RCreateServiceWResponse>(request);
}

export async function hREnumDependentServicesW(
  dce: DCERPC_v5,
  hService: ScRpcHandle,
  dwServiceState: number,
  cbBufSize: number,
) {
  const request = new REnumDependentServicesW();
  request.set('hService', hService);
  request.set('dwServiceState', dwServiceState);
  request.set('cbBufSize', cbBufSize);
  return (dce as unknown as { request: DceRequestFn }).request<REnumDependentServicesWResponse>(request);
}

export async function hREnumServicesStatusW(
  dce: DCERPC_v5,
  hSCManager: ScRpcHandle,
  dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_WIN32_SHARE_PROCESS | SERVICE_INTERACTIVE_PROCESS,
  dwServiceState = SERVICE_STATE_ALL,
) {
  const request = new REnumServicesStatusW();
  request.set('hSCManager', hSCManager);
  request.set('dwServiceType', dwServiceType);
  request.set('dwServiceState', dwServiceState);
  request.set('cbBufSize', 0);
  request.set('lpResumeIndex', NULL);

  const dceReq = dce as unknown as { request: DceRequestFn };
  let resp: REnumServicesStatusWResponse;
  try {
    resp = await dceReq.request<REnumServicesStatusWResponse>(request);
  } catch (e) {
    if (e instanceof DCERPCException && (e.error_code === 0xea || e.error_code === 0x00000103)) {
      const packet = (e as unknown as { packet: REnumServicesStatusWResponse }).packet;
      request.set('cbBufSize', packet.get('pcbBytesNeeded') as number);
      resp = await dceReq.request<REnumServicesStatusWResponse>(request);
    } else {
      throw e;
    }
  }
  return resp;
}

export async function hROpenSCManagerW(
  dce: DCERPC_v5,
  lpMachineName = 'DUMMY\x00',
  lpDatabaseName = 'ServicesActive\x00',
  dwDesiredAccess = SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SC_MANAGER_ENUMERATE_SERVICE,
) {
  const request = new ROpenSCManagerW();
  request.set('lpMachineName', checkNullString(lpMachineName));
  request.set('lpDatabaseName', checkNullString(lpDatabaseName));
  request.set('dwDesiredAccess', dwDesiredAccess);
  return (dce as unknown as { request: DceRequestFn }).request<ROpenSCManagerWResponse>(request);
}

export async function hROpenServiceW(
  dce: DCERPC_v5,
  hSCManager: ScRpcHandle,
  lpServiceName: string,
  dwDesiredAccess = SERVICE_ALL_ACCESS,
) {
  const request = new ROpenServiceW();
  request.set('hSCManager', hSCManager);
  request.set('lpServiceName', checkNullString(lpServiceName));
  request.set('dwDesiredAccess', dwDesiredAccess);
  return (dce as unknown as { request: DceRequestFn }).request<ROpenServiceWResponse>(request);
}

export async function hRQueryServiceConfigW(dce: DCERPC_v5, hService: ScRpcHandle) {
  const request = new RQueryServiceConfigW();
  request.set('hService', hService);
  request.set('cbBufSize', 0);
  const dceReq = dce as unknown as { request: DceRequestFn };
  try {
    return await dceReq.request<RQueryServiceConfigWResponse>(request);
  } catch (e) {
    if (e instanceof DCERPCException && e.error_code === 0x0000007a) {
      const packet = (e as unknown as { packet: RQueryServiceConfigWResponse }).packet;
      request.set('cbBufSize', packet.get('pcbBytesNeeded') as number);
      return dceReq.request<RQueryServiceConfigWResponse>(request);
    }
    throw e;
  }
}

export async function hRQueryServiceLockStatusW(
  dce: DCERPC_v5,
  hSCManager: ScRpcHandle,
  cbBufSize: number,
) {
  const request = new RQueryServiceLockStatusW();
  request.set('hSCManager', hSCManager);
  request.set('cbBufSize', cbBufSize);
  return (dce as unknown as { request: DceRequestFn }).request<RQueryServiceLockStatusWResponse>(request);
}

export async function hRStartServiceW(
  dce: DCERPC_v5,
  hService: ScRpcHandle,
  argc = 0,
  argv: string[] | typeof NULL = NULL,
) {
  const request = new RStartServiceW();
  request.set('hService', hService);
  request.set('argc', argc);
  if (argc === 0) {
    request.set('argv', NULL);
  } else {
    const argvField = request.fields['argv'] as UniqueStringPtrsW;
    const dataArr = argvField.fields['Data'] as StringPtrsW;
    const arr = dataArr.fields['Data'] as NDRUniConformantArray;
    for (const item of argv as string[]) {
      const itemn = new LPWSTR();
      itemn.set('Data', checkNullString(item));
      (arr.fields['Data'] as unknown[]).push(itemn);
    }
  }
  return (dce as unknown as { request: DceRequestFn }).request<RStartServiceWResponse>(request);
}

export async function hRGetServiceDisplayNameW(
  dce: DCERPC_v5,
  hSCManager: ScRpcHandle,
  lpServiceName: string,
  lpcchBuffer: number,
) {
  const request = new RGetServiceDisplayNameW();
  request.set('hSCManager', hSCManager);
  request.set('lpServiceName', checkNullString(lpServiceName));
  request.set('lpcchBuffer', lpcchBuffer);
  return (dce as unknown as { request: DceRequestFn }).request<RGetServiceDisplayNameWResponse>(request);
}

export async function hRGetServiceKeyNameW(
  dce: DCERPC_v5,
  hSCManager: ScRpcHandle,
  lpDisplayName: string,
  lpcchBuffer: number,
) {
  const request = new RGetServiceKeyNameW();
  request.set('hSCManager', hSCManager);
  request.set('lpDisplayName', checkNullString(lpDisplayName));
  request.set('lpcchBuffer', lpcchBuffer);
  return (dce as unknown as { request: DceRequestFn }).request<RGetServiceKeyNameWResponse>(request);
}

export async function hREnumServiceGroupW(
  dce: DCERPC_v5,
  hSCManager: ScRpcHandle,
  dwServiceType: number,
  dwServiceState: number,
  cbBufSize: number,
  lpResumeIndex: LpBoundedDword256K | typeof NULL = NULL,
  pszGroupName: string | typeof NULL = NULL,
) {
  const request = new REnumServiceGroupW();
  request.set('hSCManager', hSCManager);
  request.set('dwServiceType', dwServiceType);
  request.set('dwServiceState', dwServiceState);
  request.set('cbBufSize', cbBufSize);
  request.set('lpResumeIndex', lpResumeIndex);
  request.set('pszGroupName', pszGroupName);
  return (dce as unknown as { request: DceRequestFn }).request<REnumServiceGroupWResponse>(request);
}
