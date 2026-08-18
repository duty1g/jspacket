#!/usr/bin/env node
/**
 * rpcmap - Scan for listening MSRPC interfaces.
 *
 * This binds to the MGMT interface and gets a list of interface UUIDs.
 * If the MGMT interface is not available, it takes a list of interface UUIDs
 * seen in the wild and tries to bind to each interface.
 *
 * If -brute-opnums is specified, the script tries to call each of the first N
 * operation numbers for each UUID in turn and reports the outcome of each call.
 * This can generate a burst of connections to the given endpoint!
 *
 * Original impacket authors:
 *   Catalin Patulea <cat@vv.carleton.ca>
 *   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies
 * TypeScript port for jspacket.
 */

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import {
  init as initLogger,
  initProxy,
  info,
  error as logError,
  critical,
  debug,
  normalizeArgs,
  parseCredentials,
  BANNER,
} from '@impacket/examples';
import {
  DCERPCTransportFactory,
  DCERPCStringBinding,
  SMBTransport,
  MSRPC_UUID_MGMT,
  hinqIfIds,
  KNOWN_UUIDS,
  KNOWN_PROTOCOLS,
  DCERPCException,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  RPC_PROXY_CONN_A1_401_ERR,
  RPC_PROXY_INVALID_RPC_PORT_ERR,
  RPC_PROXY_HTTP_IN_DATA_401_ERR,
  RPC_PROXY_CONN_A1_0X6BA_ERR,
  RPC_PROXY_CONN_A1_404_ERR,
  RPC_PROXY_RPC_OUT_DATA_404_ERR,
} from '@impacket/dcerpc';
import { AUTH_BASIC } from '@impacket/http';
import {
  uuidtupToBin,
  binToUuidtup,
  stringToUuidtup,
} from '@impacket/uuid';


// ---------------------------------------------------------------------------
// UUID database to bruteforce (ported from impacket examples/rpcdatabase.py)
// ---------------------------------------------------------------------------

const UUID_DATABASE: [string, string][] = [
  ['00000001-0000-0000-c000-000000000046', '0.0'],
  ['00000131-0000-0000-c000-000000000046', '0.0'],
  ['00000132-0000-0000-c000-000000000046', '0.0'],
  ['00000134-0000-0000-c000-000000000046', '0.0'],
  ['00000136-0000-0000-c000-000000000046', '0.0'],
  ['00000141-0000-0000-c000-000000000046', '0.0'],
  ['00000143-0000-0000-c000-000000000046', '0.0'],
  ['000001a0-0000-0000-c000-000000000046', '0.0'],
  ['027947e1-d731-11ce-a357-000000000001', '0.0'],
  ['04fcb220-fcfd-11cd-bec8-00aa0047ae4e', '1.0'],
  ['06bba54a-be05-49f9-b0a0-30f790261023', '1.0'],
  ['0767a036-0d22-48aa-ba69-b619480f38cb', '1.0'],
  ['0a5a5830-58e0-11ce-a3cc-00aa00607271', '1.0'],
  ['0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53', '1.0'],
  ['0b0a6584-9e0f-11cf-a3cf-00805f68cb1b', '1.0'],
  ['0b0a6584-9e0f-11cf-a3cf-00805f68cb1b', '1.1'],
  ['0b6edbfa-4a24-4fc6-8a23-942b1eca65d1', '1.0'],
  ['0c821d64-a3fc-11d1-bb7a-0080c75e4ec1', '1.0'],
  ['0d72a7d4-6148-11d1-b4aa-00c04fb66ea0', '1.0'],
  ['0da5a86c-12c2-4943-30ab-7f74a813d853', '1.0'],
  ['0e4a0156-dd5d-11d2-8c2f-00c04fb6bcde', '1.0'],
  ['1088a980-eae5-11d0-8d9b-00a02453c337', '1.0'],
  ['10f24e8e-0fa6-11d2-a910-00c04f990f3b', '1.0'],
  ['11220835-5b26-4d94-ae86-c3e475a809de', '1.0'],
  ['12345678-1234-abcd-ef00-0123456789ab', '1.0'],
  ['12345678-1234-abcd-ef00-01234567cffb', '1.0'],
  ['12345778-1234-abcd-ef00-0123456789ab', '0.0'],
  ['12345778-1234-abcd-ef00-0123456789ac', '1.0'],
  ['12b81e99-f207-4a4c-85d3-77b42f76fd14', '1.0'],
  ['12d4b7c8-77d5-11d1-8c24-00c04fa3080d', '1.0'],
  ['12e65dd8-887f-41ef-91bf-8d816c42c2e7', '1.0'],
  ['130ceefb-e466-11d1-b78b-00c04fa32883', '2.0'],
  ['1453c42c-0fa6-11d2-a910-00c04f990f3b', '1.0'],
  ['1544f5e0-613c-11d1-93df-00c04fd7bd09', '1.0'],
  ['16e0cf3a-a604-11d0-96b1-00a0c91ece30', '1.0'],
  ['16e0cf3a-a604-11d0-96b1-00a0c91ece30', '2.0'],
  ['17fdd703-1827-4e34-79d4-24a55c53bb37', '1.0'],
  ['18f70770-8e64-11cf-9af1-0020af6e72f4', '0.0'],
  ['1a9134dd-7b39-45ba-ad88-44d01ca47f28', '1.0'],
  ['1bddb2a6-c0c3-41be-8703-ddbdf4f0e80a', '1.0'],
  ['1be617c0-31a5-11cf-a7d8-00805f48a135', '3.0'],
  ['1c1c45ee-4395-11d2-b60b-00104b703efd', '0.0'],
  ['1cbcad78-df0b-4934-b558-87839ea501c9', '0.0'],
  ['1d55b526-c137-46c5-ab79-638f2a68e869', '1.0'],
  ['1ff70682-0a51-30e8-076d-740be8cee98b', '1.0'],
  ['201ef99a-7fa0-444c-9399-19ba84f12a1a', '1.0'],
  ['20610036-fa22-11cf-9823-00a0c911e5df', '1.0'],
  ['209bb240-b919-11d1-bbb6-0080c75e4ec1', '1.0'],
  ['21cd80a2-b305-4f37-9d4c-4534a8d9b568', '0.0'],
  ['2465e9e0-a873-11d0-930b-00a0c90ab17c', '3.0'],
  ['25952c5d-7976-4aa1-a3cb-c35f7ae79d1b', '1.0'],
  ['266f33b4-c7c1-4bd1-8f52-ddb8f2214ea9', '1.0'],
  ['28607ff1-15a0-8e03-d670-b89eec8eb047', '1.0'],
  ['2acb9d68-b434-4b3e-b966-e06b4b3a84cb', '1.0'],
  ['2eb08e3e-639f-4fba-97b1-14f878961076', '1.0'],
  ['2f59a331-bf7d-48cb-9e5c-7c090d76e8b8', '1.0'],
  ['2f5f3220-c126-1076-b549-074d078619da', '1.2'],
  ['2f5f6520-ca46-1067-b319-00dd010662da', '1.0'],
  ['2f5f6521-ca47-1068-b319-00dd010662db', '1.0'],
  ['2f5f6521-cb55-1059-b446-00df0bce31db', '1.0'],
  ['2fb92682-6599-42dc-ae13-bd2ca89bd11c', '1.0'],
  ['300f3532-38cc-11d0-a3f0-0020af6b0add', '1.2'],
  ['326731e3-c1c0-4a69-ae20-7d9044a4ea5c', '1.0'],
  ['333a2276-0000-0000-0d00-00809c000000', '3.0'],
  ['338cd001-2244-31f1-aaaa-900038001003', '1.0'],
  ['342cfd40-3c6c-11ce-a893-08002b2e9c6d', '0.0'],
  ['3473dd4d-2e88-4006-9cba-22570909dd10', '5.0'],
  ['3473dd4d-2e88-4006-9cba-22570909dd10', '5.1'],
  ['359e47c9-682e-11d0-adec-00c04fc2a078', '1.0'],
  ['367abb81-9844-35f1-ad32-98f038001003', '2.0'],
  ['369ce4f0-0fdc-11d3-bde8-00c04f8eee78', '1.0'],
  ['378e52b0-c0a9-11cf-822d-00aa0051e40f', '1.0'],
  ['386ffca4-22f5-4464-b660-be08692d7296', '1.0'],
  ['38a94e72-a9bc-11d2-8faf-00c04fa378ff', '1.0'],
  ['3919286a-b10c-11d0-9ba8-00c04fd92ef5', '0.0'],
  ['3ba0ffc0-93fc-11d0-a4ec-00a0c9062910', '1.0'],
  ['3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5', '1.0'],
  ['3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6', '1.0'],
  ['3dde7c30-165d-11d1-ab8f-00805f14db40', '1.0'],
  ['3f31c91e-2545-4b7b-9311-9529e8bffef6', '1.0'],
  ['3f77b086-3a17-11d3-9166-00c04f688e28', '1.0'],
  ['3f99b900-4d87-101b-99b7-aa0004007f07', '1.0'],
  ['3faf4738-3a21-4307-b46c-fdda9bb8c0d5', '1.0'],
  ['3faf4738-3a21-4307-b46c-fdda9bb8c0d5', '1.1'],
  ['41208ee0-e970-11d1-9b9e-00e02c064c39', '1.0'],
  ['412f241e-c12a-11ce-abff-0020af6e7a17', '0.2'],
  ['423ec01e-2e35-11d2-b604-00104b703efd', '0.0'],
  ['45776b01-5956-4485-9f80-f428f7d60129', '2.0'],
  ['45f52c28-7f9f-101a-b52b-08002b2efabe', '1.0'],
  ['469d6ec0-0d87-11ce-b13f-00aa003bac6c', '16.0'],
  ['4825ea41-51e3-4c2a-8406-8f2d2698395f', '1.0'],
  ['4a452661-8290-4b36-8fbe-7f4093a94978', '1.0'],
  ['4b112204-0e19-11d3-b42b-0000f81feb9f', '1.0'],
  ['4b324fc8-1670-01d3-1278-5a47bf6ee188', '0.0'],
  ['4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0'],
  ['4d9f4ab8-7d1c-11cf-861e-0020af6e7c57', '0.0'],
  ['4da1c422-943d-11d1-acae-00c04fc2aa3f', '1.0'],
  ['4f82f460-0e21-11cf-909e-00805f48a135', '4.0'],
  ['4fc742e0-4a10-11cf-8273-00aa004ae673', '3.0'],
  ['50abc2a4-574d-40b3-9d66-ee4fd5fba076', '5.0'],
  ['53e75790-d96b-11cd-ba18-08002b2dfead', '2.0'],
  ['56c8504c-4408-40fd-93fc-afd30f10c90d', '1.0'],
  ['57674cd0-5200-11ce-a897-08002b2e9c6d', '0.0'],
  ['57674cd0-5200-11ce-a897-08002b2e9c6d', '1.0'],
  ['5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc', '1.0'],
  ['5b5b3580-b0e0-11d1-b92d-0060081e87f0', '1.0'],
  ['5b821720-f63b-11d0-aad2-00c04fc324db', '1.0'],
  ['5c89f409-09cc-101a-89f3-02608c4d2361', '1.1'],
  ['5ca4a760-ebb1-11cf-8611-00a0245420ed', '1.0'],
  ['5cbe92cb-f4be-45c9-9fc9-33e73e557b20', '1.0'],
  ['5f54ce7d-5b79-4175-8584-cb65313a0e98', '1.0'],
  ['6099fc12-3eff-11d0-abd0-00c04fd91a4e', '3.0'],
  ['621dff68-3c39-4c6c-aae3-e68e2c6503ad', '1.0'],
  ['629b9f66-556c-11d1-8dd2-00aa004abd5e', '2.0'],
  ['629b9f66-556c-11d1-8dd2-00aa004abd5e', '3.0'],
  ['63fbe424-2029-11d1-8db8-00aa004abd5e', '1.0'],
  ['654976df-1498-4056-a15e-cb4e87584bd8', '1.0'],
  ['65a93890-fab9-43a3-b2a5-1e330ac28f11', '2.0'],
  ['68dcd486-669e-11d1-ab0c-00c04fc2dcd2', '1.0'],
  ['68dcd486-669e-11d1-ab0c-00c04fc2dcd2', '2.0'],
  ['69510fa1-2f99-4eeb-a4ff-af259f0f9749', '1.0'],
  ['6bffd098-0206-0936-4859-199201201157', '1.0'],
  ['6bffd098-a112-3610-9833-012892020162', '0.0'],
  ['6bffd098-a112-3610-9833-46c3f874532d', '1.0'],
  ['6bffd098-a112-3610-9833-46c3f87e345a', '1.0'],
  ['6e17aaa0-1a47-11d1-98bd-0000f875292e', '2.0'],
  ['708cca10-9569-11d1-b2a5-0060977d8118', '1.0'],
  ['70b51430-b6ca-11d0-b9b9-00a0c922e750', '0.0'],
  ['76d12b80-3467-11d3-91ff-0090272f9ea3', '1.0'],
  ['76f226c3-ec14-4325-8a99-6a46348418ae', '1.0'],
  ['76f226c3-ec14-4325-8a99-6a46348418af', '1.0'],
  ['77df7a80-f298-11d0-8358-00a024c480a8', '1.0'],
  ['7af5bbd0-6063-11d1-ae2a-0080c75e4ec1', '0.2'],
  ['7c44d7d4-31d5-424c-bd5e-2b3e1f323d22', '1.0'],
  ['7c857801-7381-11cf-884d-00aa004b2e24', '0.0'],
  ['7e048d38-ac08-4ff1-8e6b-f35dbab88d4a', '1.0'],
  ['7ea70bcf-48af-4f6a-8968-6a440754d5fa', '1.0'],
  ['7f9d11bf-7fb9-436b-a812-b2d50c5d4c03', '1.0'],
  ['811109bf-a4e1-11d1-ab54-00a0c91e9b45', '1.0'],
  ['8174bb16-571b-4c38-8386-1102b449044a', '1.0'],
  ['82273fdc-e32a-18c3-3f78-827929dc23ea', '0.0'],
  ['82980780-4b64-11cf-8809-00a004ff3128', '3.0'],
  ['82ad4280-036b-11cf-972c-00aa006887b0', '2.0'],
  ['83d72bf0-0d89-11ce-b13f-00aa003bac6c', '6.0'],
  ['83da7c00-e84f-11d2-9807-00c04f8ec850', '2.0'],
  ['86d35949-83c9-4044-b424-db363231fd0c', '1.0'],
  ['894de0c0-0d55-11d3-a322-00c04fa321a1', '1.0'],
  ['89742ace-a9ed-11cf-9c0c-08002be7ae86', '2.0'],
  ['8c7a6de0-788d-11d0-9edf-444553540000', '2.0'],
  ['8c7daf44-b6dc-11d1-9a4c-0020af6e7c57', '1.0'],
  ['8cfb5d70-31a4-11cf-a7d8-00805f48a135', '3.0'],
  ['8d09b37c-9f3a-4ebb-b0a2-4dee7d6ceae9', '1.0'],
  ['8d0ffe72-d252-11d0-bf8f-00c04fd9126b', '1.0'],
  ['8d9f4e40-a03d-11ce-8f69-08003e30051b', '0.0'],
  ['8d9f4e40-a03d-11ce-8f69-08003e30051b', '1.0'],
  ['8f09f000-b7ed-11ce-bbd2-00001a181cad', '0.0'],
  ['8fb6d884-2388-11d0-8c35-00c04fda2795', '4.1'],
  ['906b0ce0-c70b-1067-b317-00dd010662da', '1.0'],
  ['91ae6020-9e3c-11cf-8d7c-00aa00c091be', '0.0'],
  ['92bdb7e4-f28b-46a0-b551-45a52bdd5125', '0.0'],
  ['93149ca2-973b-11d1-8c39-00c04fb984f9', '0.0'],
  ['93f5ac6f-1a94-4bc5-8d1b-fd44fc255089', '1.0'],
  ['9556dc99-828c-11cf-a37e-00aa003240c7', '0.0'],
  ['95958c94-a424-4055-b62b-b7f4d5c47770', '1.0'],
  ['975201b0-59ca-11d0-a8d5-00a0c90d8051', '1.0'],
  ['98fe2c90-a542-11d0-a4ef-00a0c9062910', '1.0'],
  ['99e64010-b032-11d0-97a4-00c04fd6551d', '3.0'],
  ['99fcfec4-5260-101b-bbcb-00aa0021347a', '0.0'],
  ['9b3195fe-d603-43d1-a0d5-9072d7cde122', '1.0'],
  ['9b8699ae-0e44-47b1-8e7f-86a461d7ecdc', '0.0'],
  ['9e8ee830-4459-11ce-979b-00aa005ffebe', '2.0'],
  ['a002b3a0-c9b7-11d1-ae88-0080c75e4ec1', '1.0'],
  ['a00c021c-2be2-11d2-b678-0000f87a8f8e', '1.0'],
  ['a0bc4698-b8d7-4330-a28f-7709e18b6108', '4.0'],
  ['a2d47257-12f7-4beb-8981-0ebfa935c407', '1.0'],
  ['a398e520-d59a-4bdd-aa7a-3c1e0303a511', '1.0'],
  ['a3b749b1-e3d0-4967-a521-124055d1c37d', '1.0'],
  ['a4c2fd60-5210-11d1-8fc2-00a024cb6019', '1.0'],
  ['a4f1db00-ca47-1067-b31e-00dd010662da', '1.0'],
  ['a4f1db00-ca47-1067-b31f-00dd010662da', '0.0'],
  ['a4f1db00-ca47-1067-b31f-00dd010662da', '0.81'],
  ['aa177641-fc9b-41bd-80ff-f964a701596f', '1.0'],
  ['aa411582-9bdf-48fb-b42b-faa1eee33949', '1.0'],
  ['aae9ac90-ce13-11cf-919e-08002be23c64', '1.0'],
  ['ae33069b-a2a8-46ee-a235-ddfd339be281', '1.0'],
  ['afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0'],
  ['b196b284-bab4-101a-b69c-00aa00341d07', '0.0'],
  ['b196b286-bab4-101a-b69c-00aa00341d07', '0.0'],
  ['b58aa02e-2884-4e97-8176-4ee06d794184', '1.0'],
  ['b7b31df9-d515-11d3-a11c-00105a1f515a', '0.0'],
  ['b97db8b2-4c63-11cf-bff6-08002be23f2f', '2.0'],
  ['b9e79e60-3d52-11ce-aaa1-00006901293f', '0.2'],
  ['bfa951d1-2f0e-11d3-bfd1-00c04fa3490a', '1.0'],
  ['c13d3372-cc20-4449-9b23-8cc8271b3885', '1.0'],
  ['c33b9f46-2088-4dbc-97e3-6125f127661c', '1.0'],
  ['c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'],
  ['c6f3ee72-ce7e-11d1-b71e-00c04fc3111a', '1.0'],
  ['c8cb7687-e6d3-11d2-a958-00c04f682e16', '1.0'],
  ['c9378ff1-16f7-11d0-a0b2-00aa0061426a', '1.0'],
  ['c9ac6db5-82b7-4e55-ae8a-e464ed7b4277', '1.0'],
  ['ce1334a5-41dd-40ea-881d-64326b23effe', '0.2'],
  ['d049b186-814f-11d1-9a3c-00c04fc9b232', '1.1'],
  ['d2d79dfa-3400-11d0-b40b-00aa005ff586', '1.0'],
  ['d335b8f6-cb31-11d0-b0f9-006097ba4e54', '1.5'],
  ['d3fbb514-0e3b-11cb-8fad-08002b1d29c3', '1.0'],
  ['d4781cd6-e5d3-44df-ad94-930efe48a887', '0.0'],
  ['d6d70ef0-0e3b-11cb-acc3-08002b1d29c3', '1.0'],
  ['d6d70ef0-0e3b-11cb-acc3-08002b1d29c4', '1.0'],
  ['d7f9e1c0-2247-11d1-ba89-00c04fd91268', '5.0'],
  ['d95afe70-a6d5-4259-822e-2c84da1ddb0d', '1.0'],
  ['dd490425-5325-4565-b774-7e27d6c09c24', '1.0'],
  ['e1af8308-5d1f-11c9-91a4-08002b14a0fa', '3.0'],
  ['e248d0b8-bf15-11cf-8c5e-08002bb49649', '2.0'],
  ['e33c0cc4-0482-101a-bc0c-02608c6ba218', '1.0'],
  ['e3514235-4b06-11d1-ab04-00c04fc2dcd2', '4.0'],
  ['e60c73e6-88f9-11cf-9af1-0020af6e72f4', '2.0'],
  ['e67ab081-9844-3521-9d32-834f038001c0', '1.0'],
  ['e76ea56d-453f-11cf-bfec-08002be23f2f', '2.0'],
  ['ea0a3165-4834-11d2-a6f8-00c04fa346cc', '4.0'],
  ['eb658b8a-7a64-4ddc-9b8d-a92610db0206', '0.0'],
  ['ec02cae0-b9e0-11d2-be62-0020afeddf63', '1.0'],
  ['ecec0d70-a603-11d0-96b1-00a0c91ece30', '1.0'],
  ['ecec0d70-a603-11d0-96b1-00a0c91ece30', '2.0'],
  ['eff55e30-4ee2-11ce-a3c9-00aa00607271', '1.0'],
  ['f309ad18-d86a-11d0-a075-00c04fb68820', '0.0'],
  ['f50aac00-c7f3-428e-a022-a6b71bfb9d43', '1.0'],
  ['f5cc59b4-4264-101a-8c59-08002b2f8426', '1.1'],
  ['f5cc5a18-4264-101a-8c59-08002b2f8426', '56.0'],
  ['f5cc5a7c-4264-101a-8c59-08002b2f8426', '21.0'],
  ['f6beaff7-1e19-4fbb-9f8f-b89e2018337c', '1.0'],
  ['f930c514-1215-11d3-99a5-00a0c9b61b04', '1.0'],
  ['fc13257d-5567-4dea-898d-c6f9c48415a0', '1.0'],
  ['fd7a0523-dc70-43dd-9b2e-9c5ed48225b1', '1.0'],
  ['fdb3a030-065f-11d1-bb9b-00a024ea5525', '1.0'],
  ['ffe561b8-bf15-11cf-8c5e-08002bb49649', '2.0'],
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Stringify an error/exception (message), like Python's str(e). */
function errStr(e: unknown): string {
  if (e instanceof Error) return e.message || String(e);
  return String(e);
}

/** Compare two uuidtups for sorting, mirroring Python's sorted() on tuples. */
function tupCompare(a: [string, string], b: [string, string]): number {
  if (a[0] < b[0]) return -1;
  if (a[0] > b[0]) return 1;
  if (a[1] < b[1]) return -1;
  if (a[1] > b[1]) return 1;
  return 0;
}

/** Deduplicate uuidtups by their string form. */
function uniqueTups(tups: [string, string][]): [string, string][] {
  const seen = new Set<string>();
  const out: [string, string][] = [];
  for (const t of tups) {
    const key = `${t[0]}|${t[1]}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(t);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Extend the UUID database with the interfaces from ndrutils' KNOWN_UUIDS,
// mirroring impacket examples/rpcdatabase.py's `fix_ndr_uuid` + `.update()`.
//
// KNOWN_UUIDS is keyed on the first 18 bytes of a bound interface (16-byte
// UUID + 1-byte major + 1-byte minor version), hex-encoded. Re-pack the
// 1-byte major/minor pair as the 2x 2-byte little-endian fields that
// binToUuidtup()/uuidtupToBin() expect (a 20-byte NDR interface id), then
// fold the resulting tuples into the bruteforce set.
// ---------------------------------------------------------------------------

function fixNdrUuid(ndrHex: string): Buffer {
  const buf = Buffer.from(ndrHex, 'hex');
  if (buf.length !== 18) {
    throw new Error(`Expected an 18-byte NDR UUID, got ${buf.length} bytes`);
  }
  const verBuf = Buffer.alloc(4);
  verBuf.writeUInt16LE(buf[16]!, 0);
  verBuf.writeUInt16LE(buf[17]!, 2);
  return Buffer.concat([buf.subarray(0, 16), verBuf]);
}

const UUID_DATABASE_FULL: [string, string][] = uniqueTups([
  ...UUID_DATABASE,
  ...Object.keys(KNOWN_UUIDS).map((hex): [string, string] => binToUuidtup(fixNdrUuid(hex))),
]);

// ---------------------------------------------------------------------------
// RPCMap
// ---------------------------------------------------------------------------

interface DceLike {
  setAuthLevel(level: number): void;
  setCredentials(u: string, p: string, d?: string, lm?: string, nt?: string): void;
  connect(): Promise<void> | void;
  disconnect(): Promise<void> | void;
  bind(uuid: Buffer): Promise<unknown>;
  call(functionNum: number, body: Buffer): Promise<void>;
  recv(): Promise<Buffer>;
}

class RPCMap {
  private stringbinding: DCERPCStringBinding;
  private authLevel: number;
  private bruteUuids: boolean;
  private uuids: [string, string][];
  private bruteOpnums: boolean;
  private opnumMax: number;
  private bruteVersions: boolean;
  private versionMax: number;
  private msrpcLockoutProtection = false;
  private rpctransport: ReturnType<typeof DCERPCTransportFactory>;
  private dce: DceLike;

  constructor(opts: {
    stringbinding: string;
    authLevel?: number;
    bruteUuids?: boolean;
    uuids?: [string, string][];
    bruteOpnums?: boolean;
    opnumMax?: number;
    bruteVersions?: boolean;
    versionMax?: number;
  }) {
    try {
      this.stringbinding = new DCERPCStringBinding(opts.stringbinding);
    } catch {
      throw new Error('Provided stringbinding is not correct');
    }

    // Empty network address is only allowed when RpcProxy is used
    // (network address is then obtained from NTLMSSP of the RPC proxy).
    if (
      this.stringbinding.getNetworkAddress() === '' &&
      !this.stringbinding.isOptionSet('RpcProxy')
    ) {
      throw new Error('Provided stringbinding is not correct');
    }

    this.authLevel = opts.authLevel ?? RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    this.bruteUuids = opts.bruteUuids ?? false;
    this.uuids = opts.uuids ?? [];
    this.bruteOpnums = opts.bruteOpnums ?? false;
    this.opnumMax = opts.opnumMax ?? 64;
    this.bruteVersions = opts.bruteVersions ?? false;
    this.versionMax = opts.versionMax ?? 64;

    this.rpctransport = DCERPCTransportFactory(opts.stringbinding);
    this.dce = this.rpctransport.getDceRpc() as unknown as DceLike;
  }

  getRpcTransport(): ReturnType<typeof DCERPCTransportFactory> {
    return this.rpctransport;
  }

  setTransportCredentials(username: string, password: string, domain = '', hashes?: string | null): void {
    let lmhash = '';
    let nthash = '';
    if (hashes != null) {
      const parts = hashes.split(':');
      lmhash = parts[0] ?? '';
      nthash = parts[1] ?? '';
    }
    if (typeof (this.rpctransport as unknown as { setCredentials?: unknown }).setCredentials === 'function') {
      (this.rpctransport as unknown as {
        setCredentials(u: string, p: string, d: string, lm: string, nt: string): void;
      }).setCredentials(username, password, domain, lmhash, nthash);
    }
  }

  setRpcCredentials(username: string, password: string, domain = '', hashes?: string | null): void {
    let lmhash = '';
    let nthash = '';
    if (hashes != null) {
      const parts = hashes.split(':');
      lmhash = parts[0] ?? '';
      nthash = parts[1] ?? '';
    }
    if (typeof this.dce.setCredentials === 'function') {
      this.dce.setCredentials(username, password, domain, lmhash, nthash);
    }
    if (username !== '' || password !== '' || (hashes ?? '') !== '') {
      this.msrpcLockoutProtection = true;
    }
  }

  setSmbInfo(smbhost?: string | null, smbport?: number | null): void {
    if (this.rpctransport instanceof SMBTransport) {
      if (smbhost) this.rpctransport.setRemoteHost(smbhost);
      if (smbport) this.rpctransport.setDport(smbport);
    }
  }

  async connect(): Promise<void> {
    this.dce.setAuthLevel(this.authLevel);
    await this.dce.connect();
  }

  async disconnect(): Promise<void> {
    await this.dce.disconnect();
  }

  async do(): Promise<void> {
    try {
      // Connecting to MGMT interface
      await this.dce.bind(MSRPC_UUID_MGMT);

      // Retrieving interfaces UUIDs from the MGMT interface
      const ifids = await hinqIfIds(this.dce as never);

      // If -brute-uuids is set, bruteforce UUIDs instead of parsing ifids.
      // We must do it after hinqIfIds to prevent lockout of a specified account.
      if (this.bruteUuids) {
        await this.bruteforceUuids();
        return;
      }

      const vec = (ifids as unknown as { get(k: string): unknown }).get('if_id_vector') as {
        get(k: string): unknown;
      };
      const count = vec.get('count') as number;
      const ifIdArray = vec.get('if_id') as { get(k: string): unknown }[];

      let uuidtups: [string, string][] = [];
      for (let index = 0; index < count; index++) {
        const ptr = ifIdArray[index]!;
        const rpcIfId = ptr.get('Data') as { getData(): Buffer };
        uuidtups.push(binToUuidtup(rpcIfId.getData()));
      }

      // Adding the MGMT interface itself
      uuidtups.push(['AFA8BD80-7D8A-11C9-BEF4-08002B102989', '1.0']);

      uuidtups = uniqueTups(uuidtups).sort(tupCompare);

      for (const tup of uuidtups) {
        await this.handleDiscoveredTup(tup);
      }
    } catch (e) {
      if (!(e instanceof DCERPCException)) throw e;
      const msg = errStr(e);
      // nca_s_unk_if for Windows SMB
      // reason_not_specified for Samba 4
      // abstract_syntax_not_supported for Samba 3
      if (
        msg.indexOf('nca_s_unk_if') >= 0 ||
        msg.indexOf('reason_not_specified') >= 0 ||
        msg.indexOf('abstract_syntax_not_supported') >= 0
      ) {
        info('Target MGMT interface not available');
        info('Bruteforcing UUIDs. The result may not be complete.');
        await this.bruteforceUuids();
      } else if (msg.indexOf('rpc_s_access_denied') >= 0 && this.msrpcLockoutProtection === false) {
        info('Target MGMT interface requires authentication, but no credentials provided.');
        info('Bruteforcing UUIDs. The result may not be complete.');
        await this.bruteforceUuids();
      } else {
        throw e;
      }
    }
  }

  async bruteforceVersions(interfaceUuid: string): Promise<void> {
    const results: string[] = [];

    for (let i = 0; i <= this.versionMax; i++) {
      const binuuid = uuidtupToBin([interfaceUuid, `${i}.0`])!;
      // Is there a way to test multiple opnums in a single rpc channel?
      await this.dce.connect();

      try {
        await this.dce.bind(binuuid);
        results.push('success');
      } catch (e) {
        const msg = errStr(e);
        if (msg.indexOf('abstract_syntax_not_supported') >= 0) {
          results.push('abstract_syntax_not_supported (version not supported)');
        } else {
          results.push(msg);
        }
      }
    }

    if (results.length > 1 && results[results.length - 1] === results[results.length - 2]) {
      const suffix = results[results.length - 1];
      while (results.length && results[results.length - 1] === suffix) {
        results.pop();
      }
      for (let i = 0; i < results.length; i++) {
        console.log(`Versions ${i}: ${results[i]}`);
      }
      console.log(`Versions ${results.length}-${this.versionMax}: ${suffix}`);
    } else {
      for (let i = 0; i < results.length; i++) {
        console.log(`Versions ${i}: ${results[i]}`);
      }
    }
  }

  async bruteforceOpnums(binuuid: Buffer): Promise<void> {
    const results: string[] = [];

    for (let i = 0; i <= this.opnumMax; i++) {
      // Is there a way to test multiple opnums in a single rpc channel?
      await this.dce.connect();
      await this.dce.bind(binuuid);
      await this.dce.call(i, Buffer.alloc(0));

      try {
        await this.dce.recv();
        results.push('success');
      } catch (e) {
        const msg = errStr(e);
        if (msg.indexOf('nca_s_op_rng_error') >= 0) {
          results.push('nca_s_op_rng_error (opnum not found)');
        } else {
          results.push(msg);
        }
      }
    }

    if (results.length > 1 && results[results.length - 1] === results[results.length - 2]) {
      const suffix = results[results.length - 1];
      while (results.length && results[results.length - 1] === suffix) {
        results.pop();
      }
      for (let i = 0; i < results.length; i++) {
        console.log(`Opnum ${i}: ${results[i]}`);
      }
      console.log(`Opnums ${results.length}-${this.opnumMax}: ${suffix}`);
    } else {
      for (let i = 0; i < results.length; i++) {
        console.log(`Opnum ${i}: ${results[i]}`);
      }
    }
  }

  async bruteforceUuids(): Promise<void> {
    const sorted = uniqueTups(this.uuids).sort(tupCompare);

    for (const tup of sorted) {
      // Is there a way to test multiple UUIDs in a single rpc channel?
      await this.dce.connect();
      const binuuid = uuidtupToBin(tup)!;

      try {
        await this.dce.bind(binuuid);
      } catch (e) {
        if (e instanceof DCERPCException) {
          const msg = errStr(e);
          // For Windows SMB
          if (msg.indexOf('abstract_syntax_not_supported') >= 0) continue;
          // For Samba
          if (msg.indexOf('nca_s_proto_error') >= 0) continue;
          // For Samba
          if (msg.indexOf('reason_not_specified') >= 0) continue;
        } else {
          throw e;
        }
      }

      await this.handleDiscoveredTup(tup);
    }

    info(`Tested ${this.uuids.length} UUID(s)`);
  }

  async handleDiscoveredTup(tup: [string, string]): Promise<void> {
    const protoKey = tup[0].toUpperCase();
    if (KNOWN_PROTOCOLS[protoKey]) {
      console.log(`Protocol: ${KNOWN_PROTOCOLS[protoKey]}`);
    } else {
      console.log('Protocol: N/A');
    }

    const bin = uuidtupToBin(tup);
    const providerKey = bin ? bin.subarray(0, 18).toString('hex') : '';
    if (bin && KNOWN_UUIDS[providerKey]) {
      console.log(`Provider: ${KNOWN_UUIDS[providerKey]}`);
    } else {
      console.log('Provider: N/A');
    }

    console.log(`UUID: ${tup[0]} v${tup[1]}`);

    if (this.bruteVersions) {
      await this.bruteforceVersions(tup[0]);
    }

    if (this.bruteOpnums) {
      try {
        await this.bruteforceOpnums(uuidtupToBin(tup)!);
      } catch (e) {
        if (e instanceof DCERPCException && errStr(e).indexOf('abstract_syntax_not_supported') >= 0) {
          console.log('Listening: False');
        } else {
          throw e;
        }
      }
    }
    console.log('');
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/**
 * Resolve a password, prompting interactively when it wasn't supplied on the
 * command line. Mirrors impacket.examples.utils.parse_identity(): only
 * prompt when a username is set, no hashes were given, and -no-pass wasn't
 * passed.
 */
async function resolvePassword(
  password: string,
  username: string,
  hashes: string | undefined,
  noPass: boolean,
  promptMessage: string,
): Promise<string> {
  if (password !== '' || username === '' || hashes != null || noPass) {
    return password;
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise<string>((resolve) => {
    rl.question(promptMessage, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function printUsage(): void {
  console.log(`Lookups listening MSRPC interfaces.

usage: rpcmap [-h] [-brute-uuids] [-brute-opnums] [-brute-versions]
              [-opnum-max OPNUM_MAX] [-version-max VERSION_MAX]
              [-auth-level AUTH_LEVEL] [-uuid UUID] [-debug] [-ts]
              [-target-ip ip address] [-port [{139,445}]]
              [-auth-rpc AUTH_RPC] [-auth-transport AUTH_TRANSPORT]
              [-hashes-rpc LMHASH:NTHASH] [-hashes-transport LMHASH:NTHASH]
              [-no-pass]
              stringbinding

positional arguments:
  stringbinding         String binding to connect to MSRPC interface, for example:
                          ncacn_ip_tcp:192.168.0.1[135]
                          ncacn_np:192.168.0.1[\\pipe\\spoolss]
                          ncacn_http:192.168.0.1[593]
                          ncacn_http:[6001,RpcProxy=exchange.contoso.com:443]
                          ncacn_http:localhost[3388,RpcProxy=rds.contoso:443]

options:
  -h, --help            show this help message and exit
  -brute-uuids          Bruteforce UUIDs even if MGMT interface is available
  -brute-opnums         Bruteforce opnums for found UUIDs
  -brute-versions       Bruteforce major versions of found UUIDs
  -opnum-max OPNUM_MAX  Bruteforce opnums from 0 to N, default 64
  -version-max VERSION_MAX
                        Bruteforce versions from 0 to N, default 64
  -auth-level AUTH_LEVEL
                        MS-RPCE auth level, from 1 to 6, default 6
                        (RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
  -uuid UUID            Test only this UUID
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

ncacn-np-details:
  -target-ip ip address
                        IP Address of the target machine
  -port [{139,445}]     Destination port to connect to SMB Server

authentication:
  -auth-rpc AUTH_RPC    [domain/]username[:password]
  -auth-transport AUTH_TRANSPORT
                        [domain/]username[:password]
  -hashes-rpc LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -hashes-transport LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for passwords`);
}

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      options: {
        'brute-uuids': { type: 'boolean', default: false },
        'brute-opnums': { type: 'boolean', default: false },
        'brute-versions': { type: 'boolean', default: false },
        'opnum-max': { type: 'string', default: '64' },
        'version-max': { type: 'string', default: '64' },
        'auth-level': { type: 'string', default: '6' },
        uuid: { type: 'string' },
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
        'auth-rpc': { type: 'string', default: '' },
        'auth-transport': { type: 'string', default: '' },
        'hashes-rpc': { type: 'string' },
        'hashes-transport': { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: true,
      strict: true,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    printUsage();
    process.exit(values.help ? 0 : 1);
  }

  // Init the logger theme
  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const stringbinding = positionals[0]!;

  // Parse identities ([domain/]username[:password]), mirroring impacket's
  // parse_identity(): prompt for the password when it wasn't supplied on the
  // command line and neither hashes nor -no-pass were given.
  const [rpcdomain, rpcuser, rpcpassRaw] = parseCredentials(values['auth-rpc'] ?? '');
  const [transportdomain, transportuser, transportpassRaw] = parseCredentials(
    values['auth-transport'] ?? '',
  );

  const rpcpass = await resolvePassword(
    rpcpassRaw,
    rpcuser,
    values['hashes-rpc'],
    values['no-pass'],
    'Password for MSRPC communication: ',
  );
  const transportpass = await resolvePassword(
    transportpassRaw,
    transportuser,
    values['hashes-transport'],
    values['no-pass'],
    'Password for RPC transport (SMB or HTTP): ',
  );

  let bruteOpnums = values['brute-opnums'];
  const bruteVersions = values['brute-versions'];
  if (bruteOpnums && bruteVersions) {
    logError('Specify only -brute-opnums or -brute-versions');
    process.exit(1);
  }

  let bruteUuids = values['brute-uuids'];
  let uuids: [string, string][];
  if (values.uuid != null) {
    const tup = stringToUuidtup(values.uuid);
    if (!tup) {
      logError('Provided UUID is not correct');
      process.exit(1);
    }
    uuids = [tup];
    bruteUuids = true;
  } else {
    uuids = UUID_DATABASE_FULL;
  }

  let lookuper: RPCMap | undefined;
  try {
    lookuper = new RPCMap({
      stringbinding,
      authLevel: parseInt(values['auth-level']!, 10),
      bruteUuids,
      uuids,
      bruteOpnums,
      opnumMax: parseInt(values['opnum-max']!, 10),
      bruteVersions,
      versionMax: parseInt(values['version-max']!, 10),
    });
    lookuper.setRpcCredentials(rpcuser, rpcpass, rpcdomain, values['hashes-rpc'] ?? null);
    lookuper.setTransportCredentials(
      transportuser,
      transportpass,
      transportdomain,
      values['hashes-transport'] ?? null,
    );
    const smbPort = values['target-ip'] || values.port ? parseInt(values.port!, 10) : null;
    lookuper.setSmbInfo(values['target-ip'] ?? null, smbPort);
    await lookuper.connect();
    await lookuper.do();
    await lookuper.disconnect();
  } catch (e) {
    // This may contain UTF-8
    const errorText = `Protocol failed: ${errStr(e)}`;
    critical(errorText);

    // Exchange errors
    if (errorText.includes(RPC_PROXY_INVALID_RPC_PORT_ERR)) {
      critical(
        'This usually means the target is a MS Exchange Server, and connections to ' +
          'this rpc port on this host are not allowed (try port 6001)',
      );
    }

    if (
      errorText.includes(RPC_PROXY_RPC_OUT_DATA_404_ERR) ||
      errorText.includes(RPC_PROXY_CONN_A1_404_ERR)
    ) {
      critical(
        'This usually means the target is a MS Exchange Server, and connections to ' +
          'the specified RPC server are not allowed',
      );
    }

    // Other errors
    if (errorText.includes(RPC_PROXY_CONN_A1_0X6BA_ERR)) {
      critical('This usually means the target has no ACL to connect to this endpoint using RpcProxy');
    }

    if (
      errorText.includes(RPC_PROXY_HTTP_IN_DATA_401_ERR) ||
      errorText.includes(RPC_PROXY_CONN_A1_401_ERR)
    ) {
      // Only relevant for the HTTP RpcProxy transport (ncacn_http), which
      // exposes getAuthType(); other transports don't implement it.
      const proxyTransport = lookuper?.getRpcTransport() as unknown as {
        getAuthType?: () => unknown;
      };
      const authType =
        typeof proxyTransport?.getAuthType === 'function' ? proxyTransport.getAuthType() : undefined;
      if (authType === AUTH_BASIC && transportdomain === '') {
        critical(
          'RPC proxy basic authentication might require you to specify the domain. ' +
            'Your domain is empty!',
        );
      }
    }

    if (errorText.includes(RPC_PROXY_CONN_A1_401_ERR) || errorText.includes(RPC_PROXY_CONN_A1_404_ERR)) {
      info('A proxy in front of the target server detected (may be WAF / SIEM)');
    }

    if (errorText.includes('rpc_s_access_denied')) {
      critical('This usually means the credentials on the MSRPC level are invalid!');
    }

    process.exit(1);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
