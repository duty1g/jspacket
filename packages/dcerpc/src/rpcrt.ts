import { Buffer } from 'node:buffer';
import { Structure, type FieldDescriptor, structUnpack } from '@impacket/structure';
import { uuidtupToBin, generate, stringverToBin, binToUuidtup } from '@impacket/uuid';
import * as ntlm from '@impacket/ntlm';
// Lazy-loaded to avoid circular dependency (krb5 → pac → dcerpc)
let _krb5KerberosV5: typeof import('@impacket/krb5')['KerberosV5'] | null = null;
let _krb5GSSAPI: typeof import('@impacket/krb5')['GSSAPI'] | null = null;
async function getKrb5() {
  if (!_krb5KerberosV5) {
    const mod = await import('@impacket/krb5');
    _krb5KerberosV5 = mod.KerberosV5;
    _krb5GSSAPI = mod.GSSAPI;
  }
  return { KerberosV5: _krb5KerberosV5!, GSSAPI: _krb5GSSAPI! };
}
import { rc4Init } from '@impacket/crypto';
import { NDRSTRUCT, type NDRField } from './ndr';
import { UCHAR, ULONG, USHORT } from './dtypes';

export const MSRPC_REQUEST = 0x00;
export const MSRPC_PING = 0x01;
export const MSRPC_RESPONSE = 0x02;
export const MSRPC_FAULT = 0x03;
export const MSRPC_WORKING = 0x04;
export const MSRPC_NOCALL = 0x05;
export const MSRPC_REJECT = 0x06;
export const MSRPC_ACK = 0x07;
export const MSRPC_CL_CANCEL = 0x08;
export const MSRPC_FACK = 0x09;
export const MSRPC_CANCELACK = 0x0a;
export const MSRPC_BIND = 0x0b;
export const MSRPC_BINDACK = 0x0c;
export const MSRPC_BINDNAK = 0x0d;
export const MSRPC_ALTERCTX = 0x0e;
export const MSRPC_ALTERCTX_R = 0x0f;
export const MSRPC_AUTH3 = 0x10;
export const MSRPC_SHUTDOWN = 0x11;
export const MSRPC_CO_CANCEL = 0x12;
export const MSRPC_ORPHANED = 0x13;
export const MSRPC_RTS = 0x14;

export const PFC_FIRST_FRAG = 0x01;
export const PFC_LAST_FRAG = 0x02;
export const MSRPC_SUPPORT_SIGN = 0x04;
export const MSRPC_PENDING_CANCEL = 0x04;
export const PFC_RESERVED_1 = 0x08;
export const PFC_CONC_MPX = 0x10;
export const PFC_DID_NOT_EXECUTE = 0x20;
export const PFC_MAYBE = 0x40;
export const PFC_OBJECT_UUID = 0x80;

export const RPC_C_AUTHN_NONE = 0x00;
export const RPC_C_AUTHN_GSS_NEGOTIATE = 0x09;
export const RPC_C_AUTHN_WINNT = 0x0a;
export const RPC_C_AUTHN_GSS_SCHANNEL = 0x0e;
export const RPC_C_AUTHN_GSS_KERBEROS = 0x10;
export const RPC_C_AUTHN_NETLOGON = 0x44;
export const RPC_C_AUTHN_DEFAULT = 0xff;

export const RPC_C_AUTHN_LEVEL_NONE = 1;
export const RPC_C_AUTHN_LEVEL_CONNECT = 2;
export const RPC_C_AUTHN_LEVEL_CALL = 3;
export const RPC_C_AUTHN_LEVEL_PKT = 4;
export const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5;
export const RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;

export const rpc_provider_reason: Record<number, string> = {
  0: 'reason_not_specified',
  1: 'abstract_syntax_not_supported',
  2: 'proposed_transfer_syntaxes_not_supported',
  3: 'local_limit_exceeded',
  4: 'protocol_version_not_specified',
  8: 'authentication_type_not_recognized',
  9: 'invalid_checksum',
};

export const MSRPC_CONT_RESULT_ACCEPT = 0;
export const MSRPC_CONT_RESULT_USER_REJECT = 1;
export const MSRPC_CONT_RESULT_PROV_REJECT = 2;
export const MSRPC_CONT_RESULT_NEGOTIATE_ACK = 3;

export const rpc_cont_def_result: Record<number, string> = {
  0: 'acceptance',
  1: 'user_rejection',
  2: 'provider_rejection',
};

export const rpc_status_codes: Record<number, string> = {
  0x00000005: 'rpc_s_access_denied',
  0x00000008: 'Authentication type not recognized',
  0x000006d8: 'rpc_fault_cant_perform',
  0x000006c6: 'rpc_x_invalid_bound',
  0x000006e4: 'rpc_s_cannot_support: The requested operation is not supported.',
  0x000006f7: 'rpc_x_bad_stub_data',
  0x1c010001: 'nca_s_comm_failure',
  0x1c010002: 'nca_s_op_rng_error',
  0x1c010003: 'nca_s_unk_if',
  0x1c010006: 'nca_s_wrong_boot_time',
  0x1c010009: 'nca_s_you_crashed',
  0x1c01000b: 'nca_s_proto_error',
  0x1c010013: 'nca_s_out_args_too_big',
  0x1c010014: 'nca_s_server_too_busy',
  0x1c010015: 'nca_s_fault_string_too_long',
  0x1c010017: 'nca_s_unsupported_type',
  0x1c000001: 'nca_s_fault_int_div_by_zero',
  0x1c000002: 'nca_s_fault_addr_error',
  0x1c000003: 'nca_s_fault_fp_div_zero',
  0x1c000004: 'nca_s_fault_fp_underflow',
  0x1c000005: 'nca_s_fault_fp_overflow',
  0x1c000006: 'nca_s_fault_invalid_tag',
  0x1c000007: 'nca_s_fault_invalid_bound',
  0x1c000008: 'nca_s_rpc_version_mismatch',
  0x1c000009: 'nca_s_unspec_reject',
  0x1c00000a: 'nca_s_bad_actid',
  0x1c00000b: 'nca_s_who_are_you_failed',
  0x1c00000c: 'nca_s_manager_not_entered',
  0x1c00000d: 'nca_s_fault_cancel',
  0x1c00000e: 'nca_s_fault_ill_inst',
  0x1c00000f: 'nca_s_fault_fp_error',
  0x1c000010: 'nca_s_fault_int_overflow',
  0x1c000012: 'nca_s_fault_unspec',
  0x1c000013: 'nca_s_fault_remote_comm_failure',
  0x1c000014: 'nca_s_fault_pipe_empty',
  0x1c000015: 'nca_s_fault_pipe_closed',
  0x1c000016: 'nca_s_fault_pipe_order',
  0x1c000017: 'nca_s_fault_pipe_discipline',
  0x1c000018: 'nca_s_fault_pipe_comm_error',
  0x1c000019: 'nca_s_fault_pipe_memory',
  0x1c00001a: 'nca_s_fault_context_mismatch',
  0x1c00001b: 'nca_s_fault_remote_no_memory',
  0x1c00001c: 'nca_s_invalid_pres_context_id',
  0x1c00001d: 'nca_s_unsupported_authn_level',
  0x1c00001f: 'nca_s_invalid_checksum',
  0x1c000020: 'nca_s_invalid_crc',
  0x1c000021: 'nca_s_fault_user_defined',
  0x1c000022: 'nca_s_fault_tx_open_failed',
  0x1c000023: 'nca_s_fault_codeset_conv_error',
  0x1c000024: 'nca_s_fault_object_not_found',
  0x1c000025: 'nca_s_fault_no_client_stub',
  0x16c9a000: 'rpc_s_mod',
  0x16c9a001: 'rpc_s_op_rng_error',
  0x16c9a002: 'rpc_s_cant_create_socket',
  0x16c9a003: 'rpc_s_cant_bind_socket',
  0x16c9a004: 'rpc_s_not_in_call',
  0x16c9a005: 'rpc_s_no_port',
  0x16c9a006: 'rpc_s_wrong_boot_time',
  0x16c9a007: 'rpc_s_too_many_sockets',
  0x16c9a008: 'rpc_s_illegal_register',
  0x16c9a009: 'rpc_s_cant_recv',
  0x16c9a00a: 'rpc_s_bad_pkt',
  0x16c9a00b: 'rpc_s_unbound_handle',
  0x16c9a00c: 'rpc_s_addr_in_use',
  0x16c9a00d: 'rpc_s_in_args_too_big',
  0x16c9a00e: 'rpc_s_string_too_long',
  0x16c9a00f: 'rpc_s_too_many_objects',
  0x16c9a010: 'rpc_s_binding_has_no_auth',
  0x16c9a011: 'rpc_s_unknown_authn_service',
  0x16c9a012: 'rpc_s_no_memory',
  0x16c9a013: 'rpc_s_cant_nmalloc',
  0x16c9a014: 'rpc_s_call_faulted',
  0x16c9a015: 'rpc_s_call_failed',
  0x16c9a016: 'rpc_s_comm_failure',
  0x16c9a017: 'rpc_s_rpcd_comm_failure',
  0x16c9a018: 'rpc_s_illegal_family_rebind',
  0x16c9a019: 'rpc_s_invalid_handle',
  0x16c9a01a: 'rpc_s_coding_error',
  0x16c9a01b: 'rpc_s_object_not_found',
  0x16c9a01c: 'rpc_s_cthread_not_found',
  0x16c9a01d: 'rpc_s_cthread_in_use',
  0x16c9a01e: 'rpc_s_invalid_protect_level',
  0x16c9a01f: 'rpc_s_invalid_credentials',
  0x16c9a020: 'rpc_s_invalid_timeout',
  0x16c9a021: 'rpc_s_call_not_found',
  0x16c9a022: 'rpc_s_already_listening',
  0x16c9a023: 'rpc_s_no_more_bindings',
  0x16c9a024: 'rpc_s_group_not_found',
  0x16c9a025: 'rpc_s_invalid_group',
  0x16c9a026: 'rpc_s_invalid_if',
  0x16c9a027: 'rpc_s_invalid_object',
  0x16c9a028: 'rpc_s_no_interfaces_exported',
  0x16c9a029: 'rpc_s_unknown_if',
  0x16c9a02a: 'rpc_s_unknown_group',
  0x16c9a02b: 'rpc_s_invalid_kwargs',
  0x16c9a02c: 'rpc_s_no_ctx_elements',
  0x16c9a02d: 'rpc_s_ctx_full',
  0x16c9a02e: 'rpc_s_not_rpc_ep',
  0x16c9a02f: 'rpc_s_unknown_entry_type',
  0x16c9a030: 'rpc_s_no_more_elements',
  0x16c9a031: 'rpc_s_no_more_members',
  0x16c9a032: 'rpc_s_not_found',
  0x16c9a033: 'rpc_s_no_entry_name',
  0x16c9a034: 'rpc_s_no_entry',
  0x16c9a035: 'rpc_s_no_ctx',
  0x16c9a036: 'rpc_s_arity_mismatch',
  0x16c9a037: 'rpc_s_invalid_arg',
  0x16c9a038: 'rpc_s_uuid_not_found',
  0x16c9a039: 'rpc_s_no_more_stats',
  0x16c9a03a: 'rpc_s_cannot_delete',
  0x16c9a03b: 'rpc_s_CANNOT_OUTBOUND_CALL',
  0x16c9a03c: 'rpc_s_SERVER_NOT_AVAILABLE',
  0x16c9a03d: 'rpc_s_server_too_busy',
  0x16c9a03e: 'rpc_s_prot_seq_not_supported',
  0x16c9a03f: 'rpc_s_no_cached_interfaces',
  0x16c9a040: 'rpc_s_call_state_inconsistent',
  0x16c9a041: 'rpc_s_call_timeout',
  0x16c9a042: 'rpc_s_mgmt_op_disallowed',
  0x16c9a043: 'rpc_s_op_rng_invalid',
  0x16c9a044: 'rpc_s_unsupported_type',
  0x16c9a045: 'rpc_s_calls_not_supported',
  0x16c9a046: 'rpc_s_call_failed_during_exec',
  0x16c9a047: 'rpc_s_out_of_memory',
  0x16c9a048: 'rpc_s_interface_not_found',
  0x16c9a049: 'rpc_s_not_in_call',
  0x16c9a04a: 'rpc_s_endpoint_not_found',
  0x16c9a04b: 'rpc_s_entry_already_exists',
  0x16c9a04c: 'rpc_s_protocol_error',
  0x16c9a04d: 'rpc_s_out_of_resources',
  0x16c9a04e: 'rpc_s_cant_instantiate',
  0x16c9a04f: 'rpc_s_invalid_rpc_protseq',
  0x16c9a050: 'rpc_s_invalid_ns_handle',
  0x16c9a051: 'rpc_s_invalid_naf_id',
  0x16c9a052: 'rpc_s_invalid_call_handle',
  0x16c9a053: 'rpc_s_cant_comm',
  0x16c9a054: 'rpc_s_inconsistent_node',
  0x16c9a055: 'rpc_s_group_member_not_found',
  0x16c9a056: 'rpc_s_invalid_binding',
  0x16c9a057: 'rpc_s_login_disabled',
  0x16c9a058: 'rpc_s_unsupported_authn_level',
  0x16c9a059: 'rpc_s_busy_interface',
  0x16c9a05a: 'rpc_s_call_state_out_of_call',
  0x16c9a05b: 'rpc_s_no_more_calles',
  0x16c9a05c: 'rpc_s_cant_bind_socket',
  0x16c9a05d: 'rpc_s_group_not_found',
  0x16c9a05e: 'rpc_s_invalid_credentials_handle',
  0x16c9a05f: 'rpc_s_no_memory',
  0x16c9a060: 'rpc_s_invalid_call_handle',
  0x16c9a061: 'rpc_s_cant_comm',
  0x16c9a062: 'rpc_s_connect_failed',
  0x16c9a063: 'rpc_s_connection_closed',
  0x16c9a064: 'rpc_s_buffer_is_too_small',
  0x16c9a065: 'rpc_s_support_not_found',
  0x16c9a066: 'rpc_s_no_ctx_available',
  0x16c9a067: 'rpc_s_why_not_you_failed',
  0x16c9a068: 'rpc_s_license_disabled',
  0x16c9a069: 'rpc_s_internal_error',
  0x16c9a06a: 'rpc_s_principal_unknown',
  0x16c9a06b: 'rpc_s_logon_failed',
  0x16c9a06c: 'rpc_s_no_more_data',
  0x16c9a06d: 'rpc_s_no_more_entries',
  0x16c9a06e: 'rpc_s_comctx_not_found',
  0x16c9a06f: 'rpc_s_comhdr_invalid',
  0x16c9a070: 'rpc_s_protocol_error',
  0x16c9a071: 'rpc_s_unknown_if',
  0x16c9a072: 'rpc_s_unsupported_type',
  0x16c9a073: 'rpc_s_call_state_inconsistent',
  0x16c9a074: 'rpc_s_no_more_bindings',
  0x16c9a075: 'rpc_s_rpcd_not_running',
  0x16c9a076: 'rpc_s_rpcd_version_mismatch',
  0x16c9a077: 'rpc_s_rpcd_not_listening',
  0x16c9a078: 'rpc_rpc_ss_no_memory',
  0x16c9a079: 'rpc_rpc_ss_in_octet_error',
  0x16c9a07a: 'rpc_rpc_ss_string_too_long',
  0x16c9a07b: 'rpc_rpc_ss_context_mismatch',
  0x16c9a07c: 'rpc_rpc_ss_context_damaged',
  0x16c9a07d: 'rpc_rpc_ss_no_ctx',
  0x16c9a07e: 'rpc_x_invalid_binding',
  0x16c9a07f: 'rpc_x_invalid_rpc_protseq',
  0x16c9a080: 'rpc_x_invalid_if',
  0x16c9a081: 'rpc_x_invalid_object',
  0x16c9a082: 'rpc_x_no_more_bindings',
  0x16c9a083: 'rpc_x_already_listening',
  0x16c9a084: 'rpc_x_no_interfaces_exported',
  0x16c9a085: 'rpc_x_unknown_if',
  0x16c9a086: 'rpc_x_op_rng_invalid',
  0x16c9a087: 'rpc_x_prot_seq_not_supported',
  0x16c9a088: 'rpc_x_no_more_interfaces',
  0x16c9a089: 'rpc_x_call_timeout',
  0x16c9a08a: 'rpc_x_no_more_calls',
  0x16c9a08b: 'rpc_x_call_state_inconsistent',
  0x16c9a08c: 'rpc_x_connect_failed',
  0x16c9a08d: 'rpc_x_connection_closed',
  0x16c9a08e: 'rpc_x_ss_in_null_context',
  0x16c9a090: 'rpc_x_ss_in_buffer_too_small',
  0x16c9a091: 'rpc_x_ss_in_context_mismatch',
  0x16c9a092: 'rpc_x_ss_in_context_damaged',
  0x16c9a093: 'rpc_x_ss_in_invalid_context',
  0x16c9a094: 'rpc_x_ss_in_invalid_call_handle',
  0x16c9a095: 'rpc_x_ss_in_out_of_memory',
  0x16c9a096: 'rpc_x_ss_in_out_of_resources',
  0x16c9a097: 'rpc_x_ss_in_invalid_credentials',
  0x16c9a098: 'rpc_x_ss_in_invalid_auth_identity',
  0x16c9a099: 'rpc_x_ss_in_invalid_authn_level',
  0x16c9a09a: 'rpc_x_ss_in_invalid_authn_svc',
  0x16c9a09b: 'rpc_x_ss_in_no_more_entries',
  0x16c9a09c: 'rpc_x_ss_in_no_memory',
  0x16c9a09d: 'rpc_x_ss_in_no_more_ctx',
  0x16c9a09e: 'rpc_x_ss_in_no_more_ifs',
  0x16c9a09f: 'rpc_x_ss_in_no_more_bindings',
  0x16c9a0a0: 'rpc_x_ss_in_no_more_call_handles',
  0x16c9a0a1: 'rpc_x_ss_in_no_more_resources',
  0x16c9a0a2: 'rpc_x_ss_in_no_more_stats',
  0x16c9a0a3: 'rpc_x_ss_in_no_more_members',
  0x16c9a0a4: 'rpc_x_ss_in_no_more_elements',
  0x16c9a0a5: 'rpc_x_ss_in_no_more_data',
  0x16c9a0a6: 'rpc_x_ss_in_no_more_uuids',
  0x16c9a0a7: 'rpc_x_ss_in_no_more_arities',
  0x16c9a0a8: 'rpc_x_ss_in_no_more_arg',
  0x16c9a0a9: 'rpc_x_ss_in_no_more_call',
  0x16c9a0aa: 'rpc_x_ss_in_no_more_object',
  0x16c9a0ab: 'rpc_x_ss_in_no_more_if_id',
  0x16c9a0ac: 'rpc_x_ss_in_no_more_if_ops',
  0x16c9a0ad: 'rpc_x_ss_in_no_more_if_op',
  0x16c9a0ae: 'rpc_x_ss_in_no_more_if_op_arg',
  0x16c9a0af: 'rpc_x_ss_in_no_more_if_op_args',
  0x16c9a0b0: 'rpc_x_ss_in_no_more_if_op_arg_type',
  0x16c9a0b1: 'rpc_x_ss_in_no_more_if_op_arg_value',
  0x16c9a0b2: 'rpc_x_ss_in_no_more_if_op_arg_type_value',
  0x16c9a0b3: 'rpc_x_ss_in_no_more_if_op_arg_value_type',
  0x16c9a0b4: 'rpc_x_ss_in_no_more_if_op_arg_value_type_value',
  0x16c9a0b5: 'rpc_x_ss_in_no_more_if_op_arg_value_type_value_type',
  0x16c9a0b6: 'rpc_x_ss_in_no_more_if_op_arg_value_type_value_type_value',
  0x16c9a0b7: 'rpc_x_ss_in_no_more_if_op_arg_value_type_value_type_value_type',
  0x16c9a0b8: 'rpc_x_ss_in_no_more_if_op_arg_value_type_value_type_value_type_value',
  0x16c9a0b9: 'rpc_x_ss_in_no_more_if_op_arg_value_type_value_type_value_type_value_type',
  0x16c9a0c0: 'rpc_s_ss_in_null_context',
  0x16c9a0c1: 'rpc_s_ss_in_context_mismatch',
  0x16c9a0c2: 'rpc_s_ss_in_context_damaged',
  0x16c9a0c3: 'rpc_s_ss_in_invalid_context',
  0x16c9a0c4: 'rpc_s_ss_in_invalid_call_handle',
  0x16c9a0c5: 'rpc_s_ss_in_out_of_memory',
  0x16c9a0c6: 'rpc_s_ss_in_out_of_resources',
  0x16c9a0c7: 'rpc_s_ss_in_invalid_credentials',
  0x16c9a0c8: 'rpc_s_ss_in_invalid_auth_identity',
  0x16c9a0c9: 'rpc_s_ss_in_invalid_authn_level',
  0x16c9a0ca: 'rpc_s_ss_in_invalid_authn_svc',
  0x16c9a0cb: 'rpc_s_ss_in_no_more_entries',
  0x16c9a0cc: 'rpc_s_ss_in_no_memory',
  0x16c9a0cd: 'rpc_s_ss_in_no_more_ctx',
  0x16c9a0ce: 'rpc_s_ss_in_no_more_ifs',
  0x16c9a0cf: 'rpc_s_ss_in_no_more_bindings',
  0x16c9a0d0: 'ept_s_cant_create',
  0x16c9a0d1: 'ept_s_cant_access',
  0x16c9a0d2: 'ept_s_database_already_open',
  0x16c9a0d3: 'ept_s_invalid_entry',
  0x16c9a0d4: 'ept_s_update_failed',
  0x16c9a0d5: 'ept_s_invalid_context',
  0x16c9a0d6: 'ept_s_not_registered',
  0x16c9a0d7: 'ept_s_server_unavailable',
  0x16c9a0d8: 'rpc_s_underspecified_name',
  0x16c9a0d9: 'rpc_s_invalid_ns_handle',
  0x16c9a0da: 'rpc_s_unknown_error',
  0x16c9a0db: 'rpc_s_ss_char_trans_open_fail',
  0x16c9a0dc: 'rpc_s_ss_char_trans_short_file',
  0x16c9a0dd: 'rpc_s_ss_context_damaged',
  0x16c9a0de: 'rpc_s_ss_in_null_context',
  0x16c9a0df: 'rpc_s_socket_failure',
};

export const MSRPC_STANDARD_NDR_SYNTAX = ['8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0'] as const;

export class DCERPCException extends Error {
  packet: unknown = null;
  error_code: number | null = null;

  constructor(
    error_string?: string | null,
    error_code?: number | null,
    packet?: unknown,
  ) {
    super();
    this.packet = packet;
    if (packet != null) {
      try {
        this.error_code = (packet as { get: (k: string) => unknown }).get('ErrorCode') as number;
      } catch {
        this.error_code = error_code ?? null;
      }
    } else {
      this.error_code = error_code ?? null;
    }
    if (error_string) {
      this.message = error_string;
    } else if (this.error_code != null && this.error_code in rpc_status_codes) {
      this.message = `DCERPC Runtime Error: code: 0x${this.error_code.toString(16)} - ${rpc_status_codes[this.error_code]}`;
    } else if (this.error_code != null) {
      this.message = `DCERPC Runtime Error: unknown error code: 0x${this.error_code.toString(16)}`;
    }
  }

  getErrorCode(): number | null {
    return this.error_code;
  }

  getPacket(): unknown {
    return this.packet;
  }
}

export class CtxItem extends Structure {
  static structure: FieldDescriptor[] = [
    ['ContextID', '<H=0'],
    ['TransItems', 'B=0'],
    ['Pad', 'B=0'],
    ['AbstractSyntax', '20s=""'],
    ['TransferSyntax', '20s=""'],
  ];
}

export class CtxItemResult extends Structure {
  static structure: FieldDescriptor[] = [
    ['Result', '<H=0'],
    ['Reason', '<H=0'],
    ['TransferSyntax', '20s=""'],
  ];
}

export class SEC_TRAILER extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['auth_type', 'B=10'],
    ['auth_level', 'B=0'],
    ['auth_pad_len', 'B=0'],
    ['auth_rsvrd', 'B=0'],
    ['auth_ctx_id', '<L=747920'],
  ];
}

export class MSRPCHeader extends Structure {
  static _SIZE = 16;
  static commonHdr: FieldDescriptor[] = [
    ['ver_major', 'B=5'],
    ['ver_minor', 'B=0'],
    ['type', 'B=0'],
    ['flags', 'B=0'],
    ['representation', '<L=0x10'],
    ['frag_len', '<H=self._SIZE+len(auth_data)+(16 if (self["flags"] & 0x80) > 0 else 0)+len(pduData)+len(pad)+len(sec_trailer)'],
    ['auth_len', '<H=len(auth_data)'],
    ['call_id', '<L=1'],
  ];

  static structure: FieldDescriptor[] = [
    ['dataLen', '_-pduData', 'self["frag_len"]-self["auth_len"]-self._SIZE-(8 if self["auth_len"] > 0 else 0)'],
    ['pduData', ':'],
    ['_pad', '_-pad', '(4 - ((self._SIZE + (16 if (self["flags"] & 0x80) > 0 else 0) + len(self["pduData"])) & 3) & 3)'],
    ['pad', ':'],
    ['_sec_trailer', '_-sec_trailer', '8 if self["auth_len"] > 0 else 0'],
    ['sec_trailer', ':'],
    ['auth_dataLen', '_-auth_data', 'self["auth_len"]'],
    ['auth_data', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data == null) {
      this.set('ver_major', 5);
      this.set('ver_minor', 0);
      this.set('flags', PFC_FIRST_FRAG | PFC_LAST_FRAG);
      this.set('type', MSRPC_REQUEST);
      this.set('auth_len', 0);
      this.set('pduData', Buffer.alloc(0));
      this.set('auth_data', Buffer.alloc(0));
      this.set('sec_trailer', Buffer.alloc(0));
      this.set('pad', Buffer.alloc(0));
    }
  }

  getHeaderSize(): number {
    const flags = this.get('flags') as number;
    return (this.constructor as typeof MSRPCHeader)._SIZE + (flags & PFC_OBJECT_UUID ? 16 : 0);
  }

  getPacket(): Buffer {
    const authData = this.get('auth_data') as Buffer;
    if (authData && authData.length > 0) {
      this.set('auth_len', authData.length);
    }
    return this.getData();
  }
}

export class MSRPCRequestHeader extends MSRPCHeader {
  static _SIZE = 24;
  static commonHdr: FieldDescriptor[] = [
    ...MSRPCHeader.commonHdr,
    ['alloc_hint', '<L=0'],
    ['ctx_id', '<H=0'],
    ['op_num', '<H=0'],
    ['_uuid', '_-uuid', '16 if self["flags"] & 0x80 > 0 else 0'],
    ['uuid', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data == null) {
      this.set('type', MSRPC_REQUEST);
      this.set('ctx_id', 0);
      this.set('uuid', Buffer.alloc(0));
    }
  }
}

export class MSRPCRespHeader extends MSRPCHeader {
  static _SIZE = 24;
  static commonHdr: FieldDescriptor[] = [
    ...MSRPCHeader.commonHdr,
    ['alloc_hint', '<L=0'],
    ['ctx_id', '<H=0'],
    ['cancel_count', '<B=0'],
    ['padding', '<B=0'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data == null) {
      this.set('type', MSRPC_RESPONSE);
      this.set('ctx_id', 0);
    }
  }
}

export class MSRPCBind extends Structure {
  static _CTX_ITEM_LEN = new CtxItem().getData().length;
  static structure: FieldDescriptor[] = [
    ['max_tfrag', '<H=4280'],
    ['max_rfrag', '<H=4280'],
    ['assoc_group', '<L=0'],
    ['ctx_num', 'B=0'],
    ['Reserved', 'B=0'],
    ['Reserved2', '<H=0'],
    ['_ctx_items', '_-ctx_items', 'self["ctx_num"]*self._CTX_ITEM_LEN'],
    ['ctx_items', ':'],
  ];

  private ctxItems: CtxItem[] = [];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data == null) {
      this.set('max_tfrag', 4280);
      this.set('max_rfrag', 4280);
      this.set('assoc_group', 0);
      this.set('ctx_num', 1);
      this.set('ctx_items', Buffer.alloc(0));
    }
  }

  addCtxItem(item: CtxItem): void {
    this.ctxItems.push(item);
  }

  getCtxItems(): CtxItem[] {
    return this.ctxItems;
  }

  getCtxItem(index: number): CtxItem {
    return this.ctxItems[index - 1]!;
  }

  getData(): Buffer {
    this.set('ctx_num', this.ctxItems.length);
    let ctxData = Buffer.alloc(0);
    for (const item of this.ctxItems) {
      ctxData = Buffer.concat([ctxData, item.getData()]);
    }
    this.set('ctx_items', ctxData);
    return super.getData();
  }
}

export class MSRPCBindAck extends MSRPCHeader {
  static _SIZE = 26;
  static _CTX_ITEM_LEN = new CtxItemResult().getData().length;
  static structure: FieldDescriptor[] = [
    ['max_tfrag', '<H=0'],
    ['max_rfrag', '<H=0'],
    ['assoc_group', '<L=0'],
    ['SecondaryAddrLen', '<H&SecondaryAddr'],
    ['SecondaryAddr', 'z'],
    ['PadLen', '_-Pad', '(4-((self["SecondaryAddrLen"]+self._SIZE) % 4))%4'],
    ['Pad', ':'],
    ['ctx_num', 'B=0'],
    ['Reserved', 'B=0'],
    ['Reserved2', '<H=0'],
    ['_ctx_items', '_-ctx_items', 'self["ctx_num"]*self._CTX_ITEM_LEN'],
    ['ctx_items', ':'],
    ['_sec_trailer', '_-sec_trailer', '8 if self["auth_len"] > 0 else 0'],
    ['sec_trailer', ':'],
    ['auth_dataLen', '_-auth_data', 'self["auth_len"]'],
    ['auth_data', ':'],
  ];

  private ctxItems: CtxItemResult[] = [];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data == null) {
      this.set('Pad', Buffer.alloc(0));
      this.set('ctx_items', Buffer.alloc(0));
      this.set('sec_trailer', Buffer.alloc(0));
      this.set('auth_data', Buffer.alloc(0));
    } else {
      let ctxData = this.get('ctx_items') as Buffer;
      const ctxNum = this.get('ctx_num') as number;
      for (let i = 0; i < ctxNum; i++) {
        const item = new CtxItemResult(ctxData);
        this.ctxItems.push(item);
        ctxData = ctxData.subarray(item.getData().length);
      }
    }
  }

  getCtxItems(): CtxItemResult[] {
    return this.ctxItems;
  }

  getCtxItem(index: number): CtxItemResult {
    return this.ctxItems[index - 1]!;
  }
}

export class MSRPCBindNak extends Structure {
  static structure: FieldDescriptor[] = [
    ['RejectedReason', '<H=0'],
    ['SupportedVersions', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data == null) {
      this.set('SupportedVersions', Buffer.alloc(0));
    }
  }
}

export interface IDCERPCTransport {
  connect(): Promise<void> | void;
  disconnect(): Promise<void> | void;
  send(data: Buffer, forceWriteAndx?: number, forceRecv?: number): Promise<void> | void;
  recv(forceRecv?: number, count?: number): Promise<Buffer> | Buffer;
  getRemoteName(): string;
  doesSupportNTLMv2(): boolean;
  getCredentials(): [string | null, string | null, string, Buffer | string, Buffer | string, string, unknown, unknown];
  setCredentials(
    username: string,
    password: string,
    domain?: string,
    lmhash?: string,
    nthash?: string,
    aesKey?: string | null,
    TGT?: unknown,
    TGS?: unknown,
  ): void;
  getKdcHost(): string | null;
}

export class DCERPC {
  static NDRSyntax = uuidtupToBin(['8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'])!;
  static NDR64Syntax = uuidtupToBin(['71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'])!;
  transferSyntax: Buffer = DCERPC.NDRSyntax;
  protected _transport: IDCERPCTransport;

  protected _ctx = 0;
  protected _maxUserFrag = 0;

  constructor(transport: IDCERPCTransport) {
    this._transport = transport;
    this._ctx = 0;
    this._maxUserFrag = 0;
  }

  getRpcTransport(): IDCERPCTransport {
    return this._transport;
  }

  setCtxId(ctxId: number): void {
    this._ctx = ctxId;
  }

  connect(): Promise<void> | void {
    return this._transport.connect();
  }

  disconnect(): Promise<void> | void {
    return this._transport.disconnect();
  }

  setMaxFragmentSize(fragmentSize: number): void {
    if (fragmentSize === -1) {
      this._maxUserFrag = 0;
    } else {
      this._maxUserFrag = fragmentSize;
    }
  }

  setCredentials(
    _username: string,
    _password: string,
    _domain?: string,
    _lmhash?: string,
    _nthash?: string,
    _aesKey?: string,
    _TGT?: unknown,
    _TGS?: unknown,
  ): void {}

  setAuthLevel(_authLevel: number): void {}
  setAuthType(_authType: number, _callback?: unknown): void {}

  async call(functionNum: number, body: { getData(): Buffer } | Buffer, uuid?: Buffer | null): Promise<void> {
    if (typeof body === 'object' && body !== null && 'getData' in body) {
      const reqBytes = body.getData();
      await this.send(new DCERPC_RawCall(functionNum, reqBytes, uuid));
    } else {
      await this.send(new DCERPC_RawCall(functionNum, body as Buffer, uuid));
    }
  }

  send(_data: unknown): Promise<void> {
    throw new Error('virtual method. Not implemented in subclass');
  }

  recv(): Promise<Buffer> {
    throw new Error('virtual method. Not implemented in subclass');
  }

  alterCtx(_newUID: Buffer, _bogusBinds?: number): Promise<DCERPC> {
    throw new Error('virtual method. Not implemented in subclass');
  }
}

export class DCERPC_v5 extends DCERPC {
  private authLevel = RPC_C_AUTHN_LEVEL_NONE;
  private authType = RPC_C_AUTHN_WINNT;
  private authFlags = 0;
  private username: string | null = null;
  private password: string | null = null;
  private domain = '';
  private lmhash: Buffer | string = '';
  private nthash: Buffer | string = '';
  private aesKey = '';
  private TGT: unknown = null;
  private TGS: unknown = null;
  private aesNegotiated = false;
  private clientSigningKey: Buffer;
  private serverSigningKey: Buffer;
  private clientSealingKey: Buffer;
  private serverSealingKey: Buffer;
  private clientSealingHandle: ((data: Buffer) => Buffer) | null = null;
  private serverSealingHandle: ((data: Buffer) => Buffer) | null = null;
  private sequence = 0;
  private callid = 1;
  private sessionKey: Buffer | null = null;
  private maxXmitSize = 0;
  private flags = 0;
  private cipher: unknown = null;
  private confounder = Buffer.alloc(0);
  private gss: unknown = null;
  private krbSessionKey: unknown = null;

  constructor(transport: IDCERPCTransport) {
    super(transport);
    this.transferSyntax = uuidtupToBin(['8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'])!;
    this.clientSigningKey = Buffer.alloc(0);
    this.serverSigningKey = Buffer.alloc(0);
    this.clientSealingKey = Buffer.alloc(0);
    this.serverSealingKey = Buffer.alloc(0);
    this.lmhash = '';
    this.nthash = '';
  }

  setAes(isAes: boolean): void {
    this.aesNegotiated = isAes;
  }

  setSessionKey(sessionKey: Buffer): void {
    this.sessionKey = sessionKey;
  }

  getSessionKey(): Buffer | null {
    return this.sessionKey;
  }

  setAuthLevel(authLevel: number): void {
    this.authLevel = authLevel;
  }

  setAuthType(authType: number): void {
    this.authType = authType;
  }

  getAuthType(): number {
    return this.authType;
  }

  setMaxTfrag(size: number): void {
    this.maxXmitSize = size;
  }

  getCredentials(): [string | null, string | null, string, Buffer | string, Buffer | string, string, unknown, unknown] {
    return [this.username, this.password, this.domain, this.lmhash, this.nthash, this.aesKey, this.TGT, this.TGS];
  }

  setCredentials(
    username: string,
    password: string,
    domain = '',
    lmhash = '',
    nthash = '',
    aesKey = '',
    TGT: unknown = null,
    TGS: unknown = null,
  ): void {
    this.setAuthLevel(RPC_C_AUTHN_LEVEL_CONNECT);
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.aesKey = aesKey;
    this.TGT = TGT;
    this.TGS = TGS;
    this.lmhash = '';
    this.nthash = '';
    if (lmhash || nthash) {
      if (lmhash.length % 2) lmhash = `0${lmhash}`;
      if (nthash.length % 2) nthash = `0${nthash}`;
      try {
        this.lmhash = Buffer.from(lmhash, 'hex');
        this.nthash = Buffer.from(nthash, 'hex');
      } catch {
        this.lmhash = Buffer.from(lmhash);
        this.nthash = Buffer.from(nthash);
      }
    }
    this._transport.setCredentials(username, password, domain, lmhash, nthash, aesKey || null, TGT, TGS);
  }

  async bind(
    ifaceUuid: Buffer,
    alter = 0,
    bogusBinds = 0,
    transferSyntax: [string, string] = ['8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'],
  ): Promise<MSRPCHeader> {
    const bind = new MSRPCBind();
    let ctx = this._ctx;

    for (let i = 0; i < bogusBinds; i++) {
      const item = new CtxItem();
      item.set('ContextID', ctx);
      item.set('TransItems', 1);
      item.set('AbstractSyntax', Buffer.concat([generate(), stringverToBin('2.0')]));
      item.set('TransferSyntax', uuidtupToBin(transferSyntax));
      bind.addCtxItem(item);
      this._ctx++;
      ctx++;
    }

    const item = new CtxItem();
    item.set('AbstractSyntax', ifaceUuid);
    item.set('TransferSyntax', uuidtupToBin(transferSyntax));
    item.set('ContextID', ctx);
    item.set('TransItems', 1);
    bind.addCtxItem(item);

    const packet = new MSRPCHeader();
    packet.set('type', MSRPC_BIND);
    packet.set('pduData', bind.getData());
    packet.set('call_id', this.callid);

    if (alter) {
      packet.set('type', MSRPC_ALTERCTX);
    }

    let auth: ntlm.NTLMAuthNegotiate | null = null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let krbType1: any = null;
    if (this.authLevel !== RPC_C_AUTHN_LEVEL_NONE) {
      if (this.username == null || this.password == null) {
        [this.username, this.password, this.domain, this.lmhash, this.nthash, this.aesKey, this.TGT, this.TGS] =
          this._transport.getCredentials();
      }

      if (this.authType === RPC_C_AUTHN_WINNT) {
        auth = ntlm.getNTLMSSPType1('', '', true, this._transport.doesSupportNTLMv2());
      } else if (this.authType === RPC_C_AUTHN_GSS_NEGOTIATE) {
        const { KerberosV5 } = await getKrb5();
        krbType1 = await KerberosV5.getKerberosType1(
          this.username!, this.password!, this.domain,
          this.lmhash, this.nthash, this.aesKey,
          this._transport.getRemoteName(),
          this._transport.getKdcHost(),
          true, this.TGT as any, this.TGS as any,
        );
      } else {
        throw new DCERPCException(`Unsupported auth_type 0x${this.authType.toString(16)}`);
      }

      const secTrailer = new SEC_TRAILER();
      secTrailer.set('auth_type', this.authType);
      secTrailer.set('auth_level', this.authLevel);
      secTrailer.set('auth_ctx_id', this._ctx + 79231);

      const pad = (4 - (packet.getPacket().length % 4)) % 4;
      if (pad !== 0) {
        packet.set('pduData', Buffer.concat([packet.get('pduData') as Buffer, Buffer.alloc(pad, 0xff)]));
        secTrailer.set('auth_pad_len', pad);
      }

      packet.set('sec_trailer', secTrailer.getData());
      packet.set('auth_data', auth ? auth.getData() : krbType1.data);
    }

    await this._transport.send(packet.getPacket());
    const s = await this._transport.recv();

    if (s.length === 0) {
      return packet;
    }

    const resp = new MSRPCHeader(s);

    if (resp.get('type') === MSRPC_BINDACK || resp.get('type') === MSRPC_ALTERCTX_R) {
      const bindResp = new MSRPCBindAck(resp.getData());
      for (let ctx2 = bogusBinds + 1; ctx2 <= (bindResp.get('ctx_num') as number); ctx2++) {
        const ctxItems = bindResp.getCtxItem(ctx2);
        const result = ctxItems.get('Result') as number;
        if (result !== 0) {
          let msg = `Bind context ${ctx2} rejected: `;
          msg += rpc_cont_def_result[result] ?? `Unknown DCE RPC context result code: ${result.toString(16)}`;
          msg += '; ';
          const reason = ctxItems.get('Reason') as number;
          msg += rpc_provider_reason[reason] ?? `Unknown reason code: ${reason.toString(16)}`;
          if (result === 2 && reason === 1) {
            msg += " (this usually means the interface isn't listening on the given endpoint)";
          }
          throw new DCERPCException(msg);
        }
        this.transferSyntax = ctxItems.get('TransferSyntax') as Buffer;
      }
      this.maxXmitSize = bindResp.get('max_rfrag') as number;

      if (this.authLevel !== RPC_C_AUTHN_LEVEL_NONE) {
        let response: ntlm.NTLMAuthChallengeResponse | null = null;
        let krbType3Data: Buffer | null = null;
        if (this.authType === RPC_C_AUTHN_WINNT) {
          const [resp3, sessionKey] = ntlm.getNTLMSSPType3(
            auth!,
            bindResp.get('auth_data') as Buffer,
            this.username!,
            this.password!,
            this.domain,
            this.lmhash,
            this.nthash,
            this._transport.doesSupportNTLMv2(),
          );
          response = resp3;
          this.flags = response.get('flags') as number;
          this.sessionKey = sessionKey;
        } else if (this.authType === RPC_C_AUTHN_GSS_NEGOTIATE) {
          const { KerberosV5, GSSAPI: GSSAPIModule } = await getKrb5();
          const type3Result = KerberosV5.getKerberosType3(
            krbType1.cipher,
            krbType1.sessionKey,
            bindResp.get('auth_data') as Buffer,
          );
          krbType3Data = type3Result.data;
          this.sessionKey = type3Result.sessionKey.contents.subarray(0, 16);
          this.krbSessionKey = type3Result.sessionKey;
          this.gss = GSSAPIModule.GSSAPI(type3Result.cipher);
        }

        this.sequence = 0;

        if (
          this.authLevel === RPC_C_AUTHN_LEVEL_CONNECT ||
          this.authLevel === RPC_C_AUTHN_LEVEL_PKT_INTEGRITY ||
          this.authLevel === RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        ) {
          if (this.authType === RPC_C_AUTHN_WINNT) {
            if (this.flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
              this.clientSigningKey = ntlm.signKey(this.flags, this.sessionKey!)!;
              this.serverSigningKey = ntlm.signKey(this.flags, this.sessionKey!, 'Server')!;
              this.clientSealingKey = ntlm.sealKey(this.flags, this.sessionKey!);
              this.serverSealingKey = ntlm.sealKey(this.flags, this.sessionKey!, 'Server');
              const cipher3 = rc4Init(this.clientSealingKey);
              this.clientSealingHandle = (data: Buffer) => cipher3.update(data);
              const cipher4 = rc4Init(this.serverSealingKey);
              this.serverSealingHandle = (data: Buffer) => cipher4.update(data);
            } else {
              this.clientSigningKey = this.sessionKey!;
              this.serverSigningKey = this.sessionKey!;
              this.clientSealingKey = this.sessionKey!;
              this.serverSealingKey = this.sessionKey!;
              const cipher = rc4Init(this.clientSigningKey);
              this.clientSealingHandle = (data: Buffer) => cipher.update(data);
              const cipher2 = rc4Init(this.serverSigningKey);
              this.serverSealingHandle = (data: Buffer) => cipher2.update(data);
            }
          }
        }

        const secTrailer2 = new SEC_TRAILER();
        secTrailer2.set('auth_type', this.authType);
        secTrailer2.set('auth_level', this.authLevel);
        secTrailer2.set('auth_ctx_id', this._ctx + 79231);

        const auth3 = new MSRPCHeader();
        auth3.set('type', MSRPC_AUTH3);
        auth3.set('pduData', Buffer.from('    '));
        auth3.set('sec_trailer', secTrailer2.getData());
        if (response) {
          auth3.set('auth_data', response.getData());
        } else if (krbType3Data) {
          auth3.set('auth_data', krbType3Data);
        } else {
          auth3.set('auth_data', Buffer.alloc(0));
        }
        this.callid = resp.get('call_id') as number;
        auth3.set('call_id', this.callid);
        await this._transport.send(auth3.getPacket(), 1);
      }

      this.callid++;
      return resp;
    }

    if (resp.get('type') === MSRPC_BINDNAK || resp.get('type') === MSRPC_FAULT) {
      let statusCode: number;
      if (resp.get('type') === MSRPC_FAULT) {
        const faultResp = new MSRPCRespHeader(resp.getData());
        statusCode = structUnpack('<L', (faultResp.get('pduData') as Buffer).subarray(0, 4)) as number;
      } else {
        const nak = new MSRPCBindNak(resp.get('pduData') as Buffer);
        statusCode = nak.get('RejectedReason') as number;
      }
      if (statusCode in rpc_status_codes) {
        throw new DCERPCException(rpc_status_codes[statusCode]);
      } else if (statusCode in rpc_provider_reason) {
        throw new DCERPCException(`Bind context rejected: ${rpc_provider_reason[statusCode]}`);
      } else {
        throw new DCERPCException(`Unknown DCE RPC fault status code: ${statusCode.toString(16)}`);
      }
    }

    throw new DCERPCException(`Unknown DCE RPC packet type received: ${resp.get('type')}`);
  }

  private async transportSend(rpcPacket: MSRPCRequestHeader, forceWriteAndx = 0, forceRecv = 0): Promise<void> {
    rpcPacket.set('ctx_id', this._ctx);
    rpcPacket.set('sec_trailer', Buffer.alloc(0));
    rpcPacket.set('auth_data', Buffer.alloc(0));

    if (this.authLevel === RPC_C_AUTHN_LEVEL_PKT_INTEGRITY || this.authLevel === RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
      const secTrailer = new SEC_TRAILER();
      secTrailer.set('auth_type', this.authType);
      secTrailer.set('auth_level', this.authLevel);
      secTrailer.set('auth_pad_len', 0);
      secTrailer.set('auth_ctx_id', this._ctx + 79231);

      const pad = (4 - (rpcPacket.getPacket().length % 4)) % 4;
      if (pad !== 0) {
        rpcPacket.set('pduData', Buffer.concat([rpcPacket.get('pduData') as Buffer, Buffer.alloc(pad, 0xbb)]));
        secTrailer.set('auth_pad_len', pad);
      }

      rpcPacket.set('sec_trailer', secTrailer.getData());
      rpcPacket.set('auth_data', Buffer.alloc(16, 0x20));

      const plainData = rpcPacket.get('pduData') as Buffer;

      if (this.authLevel === RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
        if (this.authType === RPC_C_AUTHN_WINNT) {
          let sealedMessage: Buffer;
          let signature: ntlm.NTLMMessageSignature;
          if (this.flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
            [sealedMessage, signature] = ntlm.SEAL(
              this.flags,
              this.clientSigningKey,
              this.clientSealingKey,
              rpcPacket.getPacket().subarray(0, -16),
              plainData,
              this.sequence,
              this.clientSealingHandle!,
            );
          } else {
            [sealedMessage, signature] = ntlm.SEAL(
              this.flags,
              this.clientSigningKey,
              this.clientSealingKey,
              plainData,
              plainData,
              this.sequence,
              this.clientSealingHandle!,
            );
          }
          rpcPacket.set('pduData', sealedMessage);
          rpcPacket.set('auth_data', signature.getData());
        } else if (this.authType === RPC_C_AUTHN_GSS_NEGOTIATE) {
          const gss = this.gss as any;
          const [sealed, token] = gss.GSS_Wrap(
            this.krbSessionKey,
            plainData,
            this.sequence,
          );
          rpcPacket.set('pduData', sealed);
          rpcPacket.set('auth_data', token);
        }
      } else if (this.authLevel === RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) {
        if (this.authType === RPC_C_AUTHN_WINNT) {
          let signature: ntlm.NTLMMessageSignature;
          if (this.flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
            signature = ntlm.SIGN(
              this.flags,
              this.clientSigningKey,
              rpcPacket.getPacket().subarray(0, -16),
              this.sequence,
              this.clientSealingHandle!,
            );
          } else {
            signature = ntlm.SIGN(
              this.flags,
              this.clientSigningKey,
              plainData,
              this.sequence,
              this.clientSealingHandle!,
            );
          }
          rpcPacket.set('auth_data', signature.getData());
        } else if (this.authType === RPC_C_AUTHN_GSS_NEGOTIATE) {
          const gss = this.gss as any;
          const mic = gss.GSS_GetMIC(
            this.krbSessionKey,
            plainData,
            this.sequence,
          );
          rpcPacket.set('auth_data', mic);
        }
      }

      rpcPacket.set('sec_trailer', secTrailer.getData());
      this.sequence++;
    }

    await this._transport.send(rpcPacket.getPacket(), forceWriteAndx, forceRecv);
  }

  async send(data: unknown): Promise<void> {
    let rpcPacket: MSRPCRequestHeader;
    if (data instanceof MSRPCHeader) {
      rpcPacket = data as MSRPCRequestHeader;
    } else {
      const raw = data as { OP_NUM: number; getPacket(): Buffer };
      rpcPacket = new DCERPC_RawCall(raw.OP_NUM, raw.getPacket());
    }

    try {
      const uuid = rpcPacket.get('uuid') as Buffer;
      if (uuid && uuid.length > 0) {
        rpcPacket.set('flags', (rpcPacket.get('flags') as number) | PFC_OBJECT_UUID);
      }
    } catch {
      // Structure doesn't have uuid
    }

    rpcPacket.set('ctx_id', this._ctx);
    rpcPacket.set('call_id', this.callid);
    rpcPacket.set('alloc_hint', (rpcPacket.get('pduData') as Buffer).length);

    let fragmentSize: number;
    if (this._maxUserFrag > 0) {
      fragmentSize = Math.min(this._maxUserFrag, this.maxXmitSize);
    } else {
      fragmentSize = this.maxXmitSize;
    }

    if (this.authLevel === RPC_C_AUTHN_LEVEL_PKT_INTEGRITY || this.authLevel === RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
      if (fragmentSize <= 8) {
        fragmentSize = 8;
      }
    }

    const pduData = rpcPacket.get('pduData') as Buffer;
    const shouldFragment = pduData.length + 128 > fragmentSize;
    if (shouldFragment && fragmentSize + 128 > this.maxXmitSize) {
      fragmentSize = this.maxXmitSize - 128;
    }

    if (shouldFragment && fragmentSize > 0) {
      const packet = pduData;
      let offset = 0;
      while (true) {
        const toSend = packet.subarray(offset, offset + fragmentSize);
        if (toSend.length === 0) break;
        if (offset === 0) {
          rpcPacket.set('flags', (rpcPacket.get('flags') as number) | PFC_FIRST_FRAG);
        } else {
          rpcPacket.set('flags', (rpcPacket.get('flags') as number) & ~PFC_FIRST_FRAG);
        }
        offset += toSend.length;
        if (offset >= packet.length) {
          rpcPacket.set('flags', (rpcPacket.get('flags') as number) | PFC_LAST_FRAG);
        } else {
          rpcPacket.set('flags', (rpcPacket.get('flags') as number) & ~PFC_LAST_FRAG);
        }
        rpcPacket.set('pduData', toSend);
        await this.transportSend(rpcPacket, 1, (rpcPacket.get('flags') as number) & PFC_LAST_FRAG);
      }
    } else {
      await this.transportSend(rpcPacket);
    }
    this.callid++;
  }

  async recv(): Promise<Buffer> {
    let finished = false;
    let forceRecv = 0;
    let retAnswer = Buffer.alloc(0);

    while (!finished) {
      let responseData = await this._transport.recv(forceRecv, MSRPCRespHeader._SIZE);
      const responseHeader = new MSRPCRespHeader(responseData);
      while (responseData.length < (responseHeader.get('frag_len') as number)) {
        responseData = Buffer.concat([
          responseData,
          await this._transport.recv(forceRecv, (responseHeader.get('frag_len') as number) - responseData.length),
        ]);
      }

      const off = responseHeader.getHeaderSize();

      if (responseHeader.get('type') === MSRPC_FAULT && (responseHeader.get('frag_len') as number) >= off + 4) {
        const statusCode = structUnpack('<L', responseData.subarray(off, off + 4)) as number;
        if (statusCode in rpc_status_codes) {
          throw new DCERPCException(rpc_status_codes[statusCode]);
        } else if ((statusCode & 0xffff) in rpc_status_codes) {
          throw new DCERPCException(rpc_status_codes[statusCode & 0xffff]!);
        } else {
          throw new DCERPCException(`Unknown DCE RPC fault status code: ${statusCode.toString(16)}`);
        }
      }

      if ((responseHeader.get('flags') as number) & PFC_LAST_FRAG) {
        finished = true;
      } else {
        forceRecv = 1;
      }

      let answer = responseData.subarray(off);
      const authLen = responseHeader.get('auth_len') as number;
      if (authLen) {
        const totalAuthLen = authLen + 8;
        const authData = answer.subarray(answer.length - totalAuthLen);
        const secTrailer = new SEC_TRAILER(authData);
        answer = answer.subarray(0, answer.length - totalAuthLen);

        const secAuthLevel = secTrailer.get('auth_level') as number;
        if (secAuthLevel === RPC_C_AUTHN_LEVEL_PKT_PRIVACY) {
          if (this.authType === RPC_C_AUTHN_WINNT) {
            const [decrypted] = ntlm.SEAL(
              this.flags,
              this.serverSigningKey,
              this.serverSealingKey,
              answer,
              answer,
              this.sequence,
              this.serverSealingHandle!,
            );
            answer = decrypted;
            if (!(this.flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
              this.sequence++;
            }
          } else if (this.authType === RPC_C_AUTHN_GSS_NEGOTIATE) {
            const gss = this.gss as any;
            const gssAuthBlob = authData.subarray(8);
            const [decrypted] = gss.GSS_Unwrap(
              this.krbSessionKey,
              answer,
              this.sequence,
              'accept',
              true,
              gssAuthBlob,
            );
            answer = decrypted;
          }
        } else if (secAuthLevel === RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) {
          if (this.authType === RPC_C_AUTHN_WINNT) {
            if (!(this.flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
              this.sequence++;
            }
          }
        }

        const authPadLen = secTrailer.get('auth_pad_len') as number;
        if (authPadLen) {
          answer = answer.subarray(0, answer.length - authPadLen);
        }
      }

      retAnswer = Buffer.concat([retAnswer, answer]);
    }
    return retAnswer;
  }

  async alterCtx(newUID: Buffer, bogusBinds = 0): Promise<DCERPC_v5> {
    const answer = new DCERPC_v5(this._transport);
    answer.setCredentials(
      this.username!, this.password!, this.domain,
      this.lmhash as string, this.nthash as string,
      this.aesKey, this.TGT, this.TGS,
    );
    answer.setAuthType(this.authType);
    answer.setAuthLevel(this.authLevel);
    answer.setCtxId(this._ctx + 1);
    (answer as unknown as { callid: number }).callid = this.callid;
    await answer.bind(newUID, 1, bogusBinds, binToUuidtup(this.transferSyntax) as [string, string]);
    return answer;
  }

  async request<T extends { fromString(data: Buffer, isNDR64?: boolean): void }>(
    request: { opnum: number; getData(): Buffer; constructor: { Response?: new (data: Buffer, isNDR64?: boolean) => T } },
    uuid?: Buffer | null,
    checkError = true,
  ): Promise<T> {
    const isNDR64 = this.transferSyntax.equals(DCERPC.NDR64Syntax);
    if (isNDR64 && 'changeTransferSyntax' in request) {
      (request as { changeTransferSyntax(s: Buffer): void }).changeTransferSyntax(DCERPC.NDR64Syntax);
    }

    const opnum = (request.constructor as { opnum?: number }).opnum;
    if (opnum == null) throw new DCERPCException('No opnum defined for request');
    await this.call(opnum, { getData: () => request.getData() } as unknown as { getData(): Buffer }, uuid);
    const answer = await this.recv();

    const respClass = request.constructor.Response;
    if (!respClass) {
      throw new DCERPCException('No Response class defined for request');
    }

    if (answer.subarray(-4).equals(Buffer.alloc(4)) === false && checkError) {
      const errorCode = structUnpack('<L', answer.subarray(-4)) as number;
      if (errorCode in rpc_status_codes) {
        throw new DCERPCException(rpc_status_codes[errorCode]);
      }
      try {
        const response = new respClass(answer, isNDR64);
        throw new DCERPCException(`Session error: 0x${errorCode.toString(16)}`, errorCode, response);
      } catch (e) {
        if (e instanceof DCERPCException) throw e;
        throw new DCERPCException(`Error code: 0x${errorCode.toString(16)}`, errorCode);
      }
    }

    return new respClass(answer, isNDR64);
  }
}

export class DCERPC_RawCall extends MSRPCRequestHeader {
  OP_NUM: number;

  constructor(opNum: number, data: Buffer = Buffer.alloc(0), uuid?: Buffer | null) {
    super();
    this.OP_NUM = opNum;
    this.set('op_num', opNum);
    this.set('pduData', data);
    if (uuid) {
      this.set('flags', (this.get('flags') as number) | PFC_OBJECT_UUID);
      this.set('uuid', uuid);
    }
  }

  setData(data: Buffer): void {
    this.set('pduData', data);
  }
}

export class CommonHeader extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Version', UCHAR],
    ['Endianness', UCHAR],
    ['CommonHeaderLength', USHORT],
    ['Filler', ULONG],
  ];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(data, isNDR64);
    if (data == null) {
      this.set('Version', 1);
      this.set('Endianness', 0x10);
      this.set('CommonHeaderLength', 8);
      this.set('Filler', 0xcccccccc);
    }
  }
}

export class PrivateHeader extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ObjectBufferLength', ULONG],
    ['Filler', ULONG],
  ];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(data, isNDR64);
    if (data == null) {
      this.set('Filler', 0xcccccccc);
    }
  }
}

export class TypeSerialization1 extends NDRSTRUCT {
  static commonHdr: NDRField[] = [
    ['CommonHeader', CommonHeader],
    ['PrivateHeader', PrivateHeader],
  ];

  getData(soFar = 0): Buffer {
    const commonHeader = this.fields['CommonHeader'] as CommonHeader;
    const privateHeader = this.fields['PrivateHeader'] as PrivateHeader;
    const structData = super.getData(soFar);
    const referentsData = this.getDataReferents(soFar);
    privateHeader.set(
      'ObjectBufferLength',
      structData.length + referentsData.length - commonHeader.getData().length - privateHeader.getData().length,
    );
    return super.getData(soFar);
  }
}
