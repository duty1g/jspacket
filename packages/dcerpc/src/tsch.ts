import { Buffer } from 'node:buffer';
import { uuidtupToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { DWORD, ULONG, LPWSTR, WSTR, GUID, SYSTEMTIME, PSYSTEMTIME } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_TSCHS = uuidtupToBin(['86D35949-83C9-4044-B424-DB363231FD0C', '1.0'])!;

class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const key = this.error_code;
    if (key != null) {
      return `TSCH SessionError: code: 0x${key.toString(16)}`;
    }
    return `TSCH SessionError: unknown error code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export const CNLEN = 15;
export const DNLEN = CNLEN;
export const UNLEN = 256;
export const MAX_BUFFER_SIZE = DNLEN + UNLEN + 1 + 1;

export const TASK_FLAG_INTERACTIVE = 0x1;
export const TASK_FLAG_DELETE_WHEN_DONE = 0x2;
export const TASK_FLAG_DISABLED = 0x4;
export const TASK_FLAG_START_ONLY_IF_IDLE = 0x10;
export const TASK_FLAG_KILL_ON_IDLE_END = 0x20;
export const TASK_FLAG_DONT_START_IF_ON_BATTERIES = 0x40;
export const TASK_FLAG_KILL_IF_GOING_ON_BATTERIES = 0x80;
export const TASK_FLAG_RUN_ONLY_IF_DOCKED = 0x100;
export const TASK_FLAG_HIDDEN = 0x200;
export const TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET = 0x400;
export const TASK_FLAG_RESTART_ON_IDLE_RESUME = 0x800;
export const TASK_FLAG_SYSTEM_REQUIRED = 0x1000;
export const TASK_FLAG_RUN_ONLY_IF_LOGGED_ON = 0x2000;

export const TASK_LOGON_NONE = 0;
export const TASK_LOGON_PASSWORD = 1;
export const TASK_LOGON_S4U = 2;
export const TASK_LOGON_INTERACTIVE_TOKEN = 3;
export const TASK_LOGON_GROUP = 4;
export const TASK_LOGON_SERVICE_ACCOUNT = 5;
export const TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6;

export const TASK_STATE_UNKNOWN = 0;
export const TASK_STATE_DISABLED = 1;
export const TASK_STATE_QUEUED = 2;
export const TASK_STATE_READY = 3;
export const TASK_STATE_RUNNING = 4;

export const SCHED_S_TASK_READY = 0x00041300;
export const SCHED_S_TASK_RUNNING = 0x00041301;
export const SCHED_S_TASK_NOT_SCHEDULED = 0x00041301;

export const TASK_TRIGGER_FLAG_HAS_END_DATE = 0;
export const TASK_TRIGGER_FLAG_KILL_AT_DURATION_END = 0;
export const TASK_TRIGGER_FLAG_DISABLED = 0;

export const ONCE = 0;
export const DAILY = 1;
export const WEEKLY = 2;
export const MONTHLYDATE = 3;
export const MONTHLYDOW = 4;
export const EVENT_ON_IDLE = 5;
export const EVENT_AT_SYSTEMSTART = 6;
export const EVENT_AT_LOGON = 7;

export const SUNDAY = 0;
export const MONDAY = 1;
export const TUESDAY = 2;
export const WEDNESDAY = 3;
export const THURSDAY = 4;
export const FRIDAY = 5;
export const SATURDAY = 6;

export const JANUARY = 1;
export const FEBRUARY = 2;
export const MARCH = 3;
export const APRIL = 4;
export const MAY = 5;
export const JUNE = 6;
export const JULY = 7;
export const AUGUST = 8;
export const SEPTEMBER = 9;
export const OCTOBER = 10;
export const NOVEMBER = 11;
export const DECEMBER = 12;

export const FIRST_WEEK = 1;
export const SECOND_WEEK = 2;
export const THIRD_WEEK = 3;
export const FOURTH_WEEK = 4;
export const LAST_WEEK = 5;

export const TASK_NAMES = LPWSTR;

export const TASK_VALIDATE_ONLY = 1 << (31 - 31);
export const TASK_CREATE = 1 << (31 - 30);
export const TASK_UPDATE = 1 << (31 - 29);
export const TASK_DISABLE = 1 << (31 - 28);
export const TASK_DON_ADD_PRINCIPAL_ACE = 1 << (31 - 27);
export const TASK_IGNORE_REGISTRATION_TRIGGERS = 1 << (31 - 26);

export const TASK_DONT_ADD_PRINCIPAL_ACE = 1 << (31 - 27);
export const SCH_FLAG_FOLDER = 1 << (31 - 2);
export const SCH_FLAG_TASK = 1 << (31 - 1);

export const TASK_ENUM_HIDDEN = 1;

export const TASK_RUN_AS_SELF = 1 << (31 - 31);
export const TASK_RUN_IGNORE_CONSTRAINTS = 1 << (31 - 30);
export const TASK_RUN_USE_SESSION_ID = 1 << (31 - 29);
export const TASK_RUN_USER_SID = 1 << (31 - 28);

export const SCH_FLAG_STATE = 1 << (31 - 3);

export class TASK_NAMES_ARRAY extends NDRUniConformantArray {
  static item = TASK_NAMES;
}

export class PTASK_NAMES_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TASK_NAMES_ARRAY]];
}

export class WSTR_ARRAY extends NDRUniConformantArray {
  static item = WSTR;
}

export class PWSTR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WSTR_ARRAY]];
}

export class GUID_ARRAY extends NDRUniConformantArray {
  static item = GUID;
}

export class PGUID_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', GUID_ARRAY]];
}

export class SYSTEMTIME_ARRAY extends NDRUniConformantArray {
  static item = SYSTEMTIME;
}

export class PSYSTEMTIME_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SYSTEMTIME_ARRAY]];
}

export class TASK_USER_CRED extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['userId', LPWSTR],
    ['password', LPWSTR],
    ['flags', DWORD],
  ];
}

export class TASK_USER_CRED_ARRAY extends NDRUniConformantArray {
  static item = TASK_USER_CRED;
}

export class LPTASK_USER_CRED_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TASK_USER_CRED_ARRAY]];
}

export class TASK_XML_ERROR_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['line', DWORD],
    ['column', DWORD],
    ['node', LPWSTR],
    ['value', LPWSTR],
  ];
}

export class PTASK_XML_ERROR_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TASK_XML_ERROR_INFO]];
}

export class FIXDLEN_DATA extends Structure {
  static structure: FieldDescriptor[] = [
    ['Product Version', '<H=0'],
    ['File Version', '<H=0'],
    ['Job uuid', '16s=""'],
    ['App Name Len Offset', '<H=0'],
    ['Trigger Offset', '<H=0'],
    ['Error Retry Count', '<H=0'],
    ['Error Retry Interval', '<H=0'],
    ['Idle Deadline', '<H=0'],
    ['Idle Wait', '<H=0'],
    ['Priority', '<L=0'],
    ['Maximum Run Time', '<L=0'],
    ['Exit Code', '<L=0'],
    ['Status', '<L=0'],
    ['Flags', '<L=0'],
  ];
}

export class TRIGGERS extends Structure {
  static structure: FieldDescriptor[] = [
    ['Trigger Size', '<H=0'],
    ['Reserved1', '<H=0'],
    ['Begin Year', '<H=0'],
    ['Begin Month', '<H=0'],
    ['Begin Day', '<H=0'],
    ['End Year', '<H=0'],
    ['End Month', '<H=0'],
    ['End Day', '<H=0'],
    ['Start Hour', '<H=0'],
    ['Start Minute', '<H=0'],
    ['Minutes Duration', '<L=0'],
    ['Minutes Interval', '<L=0'],
    ['Flags', '<L=0'],
    ['Trigger Type', '<L=0'],
    ['TriggerSpecific0', '<H=0'],
    ['TriggerSpecific1', '<H=0'],
    ['TriggerSpecific2', '<H=0'],
    ['Padding', '<H=0'],
    ['Reserved2', '<H=0'],
    ['Reserved3', '<H=0'],
  ];
}

export class WEEKLY_TRIGGER extends Structure {
  static structure: FieldDescriptor[] = [
    ['Trigger Type', '<L=0'],
    ['Weeks Interval', '<H=0'],
    ['DaysOfTheWeek', '<H=0'],
    ['Unused', '<H=0'],
    ['Padding', '<H=0'],
  ];
}

export class MONTHLYDATE_TRIGGER extends Structure {
  static structure: FieldDescriptor[] = [
    ['Trigger Type', '<L=0'],
    ['Days', '<L=0'],
    ['Months', '<H=0'],
    ['Padding', '<H=0'],
  ];
}

export class MONTHLYDOW_TRIGGER extends Structure {
  static structure: FieldDescriptor[] = [
    ['Trigger Type', '<L=0'],
    ['WhichWeek', '<H=0'],
    ['DaysOfTheWeek', '<H=0'],
    ['Months', '<H=0'],
    ['Padding', '<H=0'],
    ['Reserved2', '<H=0'],
    ['Reserved3', '<H=0'],
  ];
}

export class JOB_SIGNATURE extends Structure {
  static structure: FieldDescriptor[] = [
    ['SignatureVersion', '<HH0'],
    ['MinClientVersion', '<H=0'],
    ['Signature', '64s=""'],
  ];
}

export class SchRpcHighestVersionResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pVersion', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcHighestVersion extends NDRCALL {
  static opnum = 0;
  static Response = SchRpcHighestVersionResponse;
  static structure: NDRField[] = [];
}

export class SchRpcRegisterTaskResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pActualPath', LPWSTR],
    ['pErrorInfo', PTASK_XML_ERROR_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcRegisterTask extends NDRCALL {
  static opnum = 1;
  static Response = SchRpcRegisterTaskResponse;
  static structure: NDRField[] = [
    ['path', LPWSTR],
    ['xml', WSTR],
    ['flags', DWORD],
    ['sddl', LPWSTR],
    ['logonType', DWORD],
    ['cCreds', DWORD],
    ['pCreds', LPTASK_USER_CRED_ARRAY],
  ];
}

export class SchRpcRetrieveTaskResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pXml', LPWSTR],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcRetrieveTask extends NDRCALL {
  static opnum = 2;
  static Response = SchRpcRetrieveTaskResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['lpcwszLanguagesBuffer', WSTR],
    ['pulNumLanguages', DWORD],
  ];
}

export class SchRpcCreateFolderResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SchRpcCreateFolder extends NDRCALL {
  static opnum = 3;
  static Response = SchRpcCreateFolderResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['sddl', LPWSTR],
    ['flags', DWORD],
  ];
}

export class SchRpcSetSecurityResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SchRpcSetSecurity extends NDRCALL {
  static opnum = 4;
  static Response = SchRpcSetSecurityResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['sddl', WSTR],
    ['flags', DWORD],
  ];
}

export class SchRpcGetSecurityResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['sddl', LPWSTR],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcGetSecurity extends NDRCALL {
  static opnum = 5;
  static Response = SchRpcGetSecurityResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['securityInformation', DWORD],
  ];
}

export class SchRpcEnumFoldersResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['startIndex', DWORD],
    ['pcNames', DWORD],
    ['pNames', PTASK_NAMES_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcEnumFolders extends NDRCALL {
  static opnum = 6;
  static Response = SchRpcEnumFoldersResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['flags', DWORD],
    ['startIndex', DWORD],
    ['cRequested', DWORD],
  ];
}

export class SchRpcEnumTasksResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['startIndex', DWORD],
    ['pcNames', DWORD],
    ['pNames', PTASK_NAMES_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcEnumTasks extends NDRCALL {
  static opnum = 7;
  static Response = SchRpcEnumTasksResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['flags', DWORD],
    ['startIndex', DWORD],
    ['cRequested', DWORD],
  ];
}

export class SchRpcEnumInstancesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pcGuids', DWORD],
    ['pGuids', PGUID_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcEnumInstances extends NDRCALL {
  static opnum = 8;
  static Response = SchRpcEnumInstancesResponse;
  static structure: NDRField[] = [
    ['path', LPWSTR],
    ['flags', DWORD],
  ];
}

export class SchRpcGetInstanceInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pPath', LPWSTR],
    ['pState', DWORD],
    ['pCurrentAction', LPWSTR],
    ['pInfo', LPWSTR],
    ['pcGroupInstances', DWORD],
    ['pGroupInstances', PGUID_ARRAY],
    ['pEnginePID', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcGetInstanceInfo extends NDRCALL {
  static opnum = 9;
  static Response = SchRpcGetInstanceInfoResponse;
  static structure: NDRField[] = [['guid', GUID]];
}

export class SchRpcStopInstanceResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SchRpcStopInstance extends NDRCALL {
  static opnum = 10;
  static Response = SchRpcStopInstanceResponse;
  static structure: NDRField[] = [
    ['guid', GUID],
    ['flags', DWORD],
  ];
}

export class SchRpcStopResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SchRpcStop extends NDRCALL {
  static opnum = 11;
  static Response = SchRpcStopResponse;
  static structure: NDRField[] = [
    ['path', LPWSTR],
    ['flags', DWORD],
  ];
}

export class SchRpcRunResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pGuid', GUID],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcRun extends NDRCALL {
  static opnum = 12;
  static Response = SchRpcRunResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['cArgs', DWORD],
    ['pArgs', PWSTR_ARRAY],
    ['flags', DWORD],
    ['sessionId', DWORD],
    ['user', LPWSTR],
  ];
}

export class SchRpcDeleteResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SchRpcDelete extends NDRCALL {
  static opnum = 13;
  static Response = SchRpcDeleteResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['flags', DWORD],
  ];
}

export class SchRpcRenameResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SchRpcRename extends NDRCALL {
  static opnum = 14;
  static Response = SchRpcRenameResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['newName', WSTR],
    ['flags', DWORD],
  ];
}

export class SchRpcScheduledRuntimesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pcRuntimes', DWORD],
    ['pRuntimes', PSYSTEMTIME_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcScheduledRuntimes extends NDRCALL {
  static opnum = 15;
  static Response = SchRpcScheduledRuntimesResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['start', PSYSTEMTIME],
    ['end', PSYSTEMTIME],
    ['flags', DWORD],
    ['cRequested', DWORD],
  ];
}

export class SchRpcGetLastRunInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pLastRuntime', SYSTEMTIME],
    ['pLastReturnCode', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcGetLastRunInfo extends NDRCALL {
  static opnum = 16;
  static Response = SchRpcGetLastRunInfoResponse;
  static structure: NDRField[] = [['path', WSTR]];
}

export class SchRpcGetTaskInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pEnabled', DWORD],
    ['pState', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcGetTaskInfo extends NDRCALL {
  static opnum = 17;
  static Response = SchRpcGetTaskInfoResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['flags', DWORD],
  ];
}

export class SchRpcGetNumberOfMissedRunsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pNumberOfMissedRuns', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class SchRpcGetNumberOfMissedRuns extends NDRCALL {
  static opnum = 18;
  static Response = SchRpcGetNumberOfMissedRunsResponse;
  static structure: NDRField[] = [['path', WSTR]];
}

export class SchRpcEnableTaskResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SchRpcEnableTask extends NDRCALL {
  static opnum = 19;
  static Response = SchRpcEnableTaskResponse;
  static structure: NDRField[] = [
    ['path', WSTR],
    ['enabled', DWORD],
  ];
}

const OPNUMS = {
  0: [SchRpcHighestVersion, SchRpcHighestVersionResponse] as const,
  1: [SchRpcRegisterTask, SchRpcRegisterTaskResponse] as const,
  2: [SchRpcRetrieveTask, SchRpcRetrieveTaskResponse] as const,
  3: [SchRpcCreateFolder, SchRpcCreateFolderResponse] as const,
  4: [SchRpcSetSecurity, SchRpcSetSecurityResponse] as const,
  5: [SchRpcGetSecurity, SchRpcGetSecurityResponse] as const,
  6: [SchRpcEnumFolders, SchRpcEnumFoldersResponse] as const,
  7: [SchRpcEnumTasks, SchRpcEnumTasksResponse] as const,
  8: [SchRpcEnumInstances, SchRpcEnumInstancesResponse] as const,
  9: [SchRpcGetInstanceInfo, SchRpcGetInstanceInfoResponse] as const,
  10: [SchRpcStopInstance, SchRpcStopInstanceResponse] as const,
  11: [SchRpcStop, SchRpcStopResponse] as const,
  12: [SchRpcRun, SchRpcRunResponse] as const,
  13: [SchRpcDelete, SchRpcDeleteResponse] as const,
  14: [SchRpcRename, SchRpcRenameResponse] as const,
  15: [SchRpcScheduledRuntimes, SchRpcScheduledRuntimesResponse] as const,
  16: [SchRpcGetLastRunInfo, SchRpcGetLastRunInfoResponse] as const,
  17: [SchRpcGetTaskInfo, SchRpcGetTaskInfoResponse] as const,
  18: [SchRpcGetNumberOfMissedRuns, SchRpcGetNumberOfMissedRunsResponse] as const,
  19: [SchRpcEnableTask, SchRpcEnableTaskResponse] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export async function hSchRpcHighestVersion(dce: DCERPC_v5) {
  const request = new SchRpcHighestVersion();
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcHighestVersionResponse>(
    request,
  );
}

export async function hSchRpcRegisterTask(
  dce: DCERPC_v5,
  path: string,
  xml: string,
  flags: number,
  sddl: unknown,
  logonType: number,
  pCreds: TASK_USER_CRED[] = [],
) {
  const request = new SchRpcRegisterTask();
  request.set('path', checkNullString(path));
  request.set('xml', checkNullString(xml) as string);
  request.set('flags', flags);
  request.set('sddl', sddl);
  request.set('logonType', logonType);
  request.set('cCreds', pCreds.length);
  if (pCreds.length === 0) {
    request.set('pCreds', NULL);
  } else {
    const pCredsArr = request.fields['pCreds'] as LPTASK_USER_CRED_ARRAY;
    const credsArr = pCredsArr.fields['Data'] as TASK_USER_CRED_ARRAY;
    for (const cred of pCreds) {
      (credsArr.fields['Data'] as unknown[]).push(cred);
    }
  }
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcRegisterTaskResponse>(
    request,
  );
}

export async function hSchRpcRetrieveTask(
  dce: DCERPC_v5,
  path: string,
  lpcwszLanguagesBuffer: string = '\x00',
  pulNumLanguages = 0,
) {
  const request = new SchRpcRetrieveTask();
  request.set('path', checkNullString(path) as string);
  request.set('lpcwszLanguagesBuffer', lpcwszLanguagesBuffer);
  request.set('pulNumLanguages', pulNumLanguages);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcRetrieveTaskResponse>(
    request,
  );
}

export async function hSchRpcCreateFolder(
  dce: DCERPC_v5,
  path: string,
  sddl: unknown = NULL,
) {
  const request = new SchRpcCreateFolder();
  request.set('path', checkNullString(path) as string);
  request.set('sddl', sddl);
  request.set('flags', 0);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcCreateFolderResponse>(
    request,
  );
}

export async function hSchRpcSetSecurity(
  dce: DCERPC_v5,
  path: string,
  sddl: string,
  flags: number,
) {
  const request = new SchRpcSetSecurity();
  request.set('path', checkNullString(path) as string);
  request.set('sddl', checkNullString(sddl) as string);
  request.set('flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcSetSecurityResponse>(
    request,
  );
}

export async function hSchRpcGetSecurity(
  dce: DCERPC_v5,
  path: string,
  securityInformation = 0xffffffff,
) {
  const request = new SchRpcGetSecurity();
  request.set('path', checkNullString(path) as string);
  request.set('securityInformation', securityInformation);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcGetSecurityResponse>(
    request,
  );
}

export async function hSchRpcEnumFolders(
  dce: DCERPC_v5,
  path: string,
  flags = TASK_ENUM_HIDDEN,
  startIndex = 0,
  cRequested = 0xffffffff,
) {
  const request = new SchRpcEnumFolders();
  request.set('path', checkNullString(path) as string);
  request.set('flags', flags);
  request.set('startIndex', startIndex);
  request.set('cRequested', cRequested);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcEnumFoldersResponse>(
    request,
  );
}

export async function hSchRpcEnumTasks(
  dce: DCERPC_v5,
  path: string,
  flags = TASK_ENUM_HIDDEN,
  startIndex = 0,
  cRequested = 0xffffffff,
) {
  const request = new SchRpcEnumTasks();
  request.set('path', checkNullString(path) as string);
  request.set('flags', flags);
  request.set('startIndex', startIndex);
  request.set('cRequested', cRequested);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcEnumTasksResponse>(
    request,
  );
}

export async function hSchRpcEnumInstances(
  dce: DCERPC_v5,
  path: string,
  flags = TASK_ENUM_HIDDEN,
) {
  const request = new SchRpcEnumInstances();
  request.set('path', checkNullString(path));
  request.set('flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcEnumInstancesResponse>(
    request,
  );
}

export async function hSchRpcGetInstanceInfo(dce: DCERPC_v5, guid: GUID) {
  const request = new SchRpcGetInstanceInfo();
  request.set('guid', guid);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcGetInstanceInfoResponse>(
    request,
  );
}

export async function hSchRpcStopInstance(dce: DCERPC_v5, guid: GUID, flags = 0) {
  const request = new SchRpcStopInstance();
  request.set('guid', guid);
  request.set('flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcStopInstanceResponse>(
    request,
  );
}

export async function hSchRpcStop(dce: DCERPC_v5, path: string, flags = 0) {
  const request = new SchRpcStop();
  request.set('path', checkNullString(path));
  request.set('flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcStopResponse>(request);
}

export async function hSchRpcRun(
  dce: DCERPC_v5,
  path: string,
  pArgs: string[] = [],
  flags = 0,
  sessionId = 0,
  user: unknown = NULL,
) {
  const request = new SchRpcRun();
  request.set('path', checkNullString(path) as string);
  request.set('cArgs', pArgs.length);
  const pArgsField = request.fields['pArgs'] as PWSTR_ARRAY;
  const argsArr = pArgsField.fields['Data'] as WSTR_ARRAY;
  for (const arg of pArgs) {
    const argn = new LPWSTR();
    argn.set('Data', checkNullString(arg) as string);
    (argsArr.fields['Data'] as unknown[]).push(argn);
  }
  request.set('flags', flags);
  request.set('sessionId', sessionId);
  request.set('user', user);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcRunResponse>(request);
}

export async function hSchRpcDelete(dce: DCERPC_v5, path: string, flags = 0) {
  const request = new SchRpcDelete();
  request.set('path', checkNullString(path) as string);
  request.set('flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcDeleteResponse>(request);
}

export async function hSchRpcRename(
  dce: DCERPC_v5,
  path: string,
  newName: string,
  flags = 0,
) {
  const request = new SchRpcRename();
  request.set('path', checkNullString(path) as string);
  request.set('newName', checkNullString(newName) as string);
  request.set('flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcRenameResponse>(request);
}

export async function hSchRpcScheduledRuntimes(
  dce: DCERPC_v5,
  path: string,
  start: unknown = NULL,
  end: unknown = NULL,
  flags = 0,
  cRequested = 10,
) {
  const request = new SchRpcScheduledRuntimes();
  request.set('path', checkNullString(path) as string);
  request.set('start', start);
  request.set('end', end);
  request.set('flags', flags);
  request.set('cRequested', cRequested);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcScheduledRuntimesResponse>(
    request,
  );
}

export async function hSchRpcGetLastRunInfo(dce: DCERPC_v5, path: string) {
  const request = new SchRpcGetLastRunInfo();
  request.set('path', checkNullString(path) as string);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcGetLastRunInfoResponse>(
    request,
  );
}

export async function hSchRpcGetTaskInfo(dce: DCERPC_v5, path: string, flags = 0) {
  const request = new SchRpcGetTaskInfo();
  request.set('path', checkNullString(path) as string);
  request.set('flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcGetTaskInfoResponse>(
    request,
  );
}

export async function hSchRpcGetNumberOfMissedRuns(dce: DCERPC_v5, path: string) {
  const request = new SchRpcGetNumberOfMissedRuns();
  request.set('path', checkNullString(path) as string);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcGetNumberOfMissedRunsResponse>(
    request,
  );
}

export async function hSchRpcEnableTask(dce: DCERPC_v5, path: string, enabled = true) {
  const request = new SchRpcEnableTask();
  request.set('path', checkNullString(path) as string);
  request.set('enabled', enabled ? 1 : 0);
  return (dce as unknown as { request: DceRequestFn }).request<SchRpcEnableTaskResponse>(
    request,
  );
}
