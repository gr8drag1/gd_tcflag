<h1>gd_tcflag release history</h1>
<table>
<body>
<tr>
<th>r4</th><td>The single flag End de-aggregated into Fin and Rst</td></tr>
<th>r5</th><td>Individual flag names added to the filter syntax</td></tr>
<th>r6</th><td>Counter added for tracking "tcp.analysis.flags"</td></tr>
<th>r7</th><td>Added not tcp_keep_alive check to the payload (Data) tracking</td></tr>
<th>r8</th><td>Added tracking for jumbo IP MTU and for IP fragments</td></tr>
<th>r9</th><td>Changed IP fragments check from "ip.fragment" to "ip.flags.mf"</td></tr>
<th>r10</th><td>Added detalisation branches for r6</td></tr>
<th>r11</th><td>Duplicate Ack added to tracking "tcp.analysis.flags"</td></tr>
<th>r12</th><td>Simplified filter syntax for flags set on either A or B (or both)</td></tr>
<th>r13</th><td>Keep counters separate for fast, spurious and plain retransmissions</td></tr>
<th>r14</th><td>Allow multiple passes in TCP analysis tracking</td></tr>
<th>r15</th><td>Added TCP analysis differentiation between peers</td></tr>
<th>r16</th><td>Added statistics section</td></tr>
<tr><th>r17</th><td>Sections activation made configurable</td></tr>
</tbody>
</table>
