# OSI & TCP/IP — Layers comparison

This note shows the OSI 7-layer model and the TCP/IP model, and how their layers map to each other.

## Visualization

<table style="border-collapse:collapse; width:100%; text-align:left;">
	<tr>
		<th style="padding:8px; border:1px solid #ddd; width:50%">OSI Model (top ↓)</th>
		<th style="padding:8px; border:1px solid #ddd; width:50%">TCP/IP Model (top ↓)</th>
	</tr>
	<tr>
		<td style="padding:8px; border:1px solid #ddd; color: #b95eff">App (7) — Application layer</td>
		<td style="padding:8px; border:1px solid #ddd; color: #b95eff">App (4) — (HTTP, DNS, FTP)</td>
	</tr>
	<tr>
		<td style="padding:8px; border:1px solid #ddd; color: #71f6ff">Pres (6) — Presentation (formatting, encryption)</td>
		<td style="padding:8px; border:1px solid #ddd; color: #71f6ff">App (4) — (presentation handled by app layer)</td>
	</tr>
	<tr>
		<td style="padding:8px; border:1px solid #ddd; color: #7272ff">Sess (5) — Session (dialogs, sessions)</td>
		<td style="padding:8px; border:1px solid #ddd; color: #7272ff">App (4)</td>
	</tr>
	<tr>
		<td style="padding:8px; border:1px solid #ddd; color: #03ce83">Trans (4) — Transport (TCP/UDP)</td>
		<td style="padding:8px; border:1px solid #ddd; color: #03ce83">Trans (3) — TCP/UDP (ports, reliability)</td>
	</tr>
	<tr>
		<td style="padding:8px; border:1px solid #ddd; color: #FFD700">Network (3) — IP & routing</td>
		<td style="padding:8px; border:1px solid #ddd; color: #FFD700">Internet (2) — IP</td>
	</tr>
	<tr>
		<td style="padding:8px; border:1px solid #ddd; color: #FFA500">Data Link (2) — Ethernet, MAC</td>
		<td style="padding:8px; border:1px solid #ddd; color: #FFA500">Link (1) — Ethernet / PHY</td>
	</tr>
	<tr>
		<td style="padding:8px; border:1px solid #ddd; color: #ff4b4b">Physical (1) — electrical / optical signaling</td>
		<td style="padding:8px; border:1px solid #ddd; color: #ff4b4b">Link (1) — physical medium</td>
	</tr>
</table>