Time window:
{{ $json.body.ts_start }} - {{ $json.body.ts_end }}

Devices on network (JSON):
{{ JSON.stringify($json.body.devices, null, 2) }}

Top flows (JSON):
{{ JSON.stringify($json.body.summary.top_flows, null, 2) }}

WAN activity (JSON):
{{ JSON.stringify($json.body.summary.wan_activity, null, 2) }}

Scan indicators (JSON):
{{ JSON.stringify($json.body.summary.scan_indicators, null, 2) }}
