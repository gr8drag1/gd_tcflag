<h1>gd_tcflag release history</h1>
<table>
<body>
<tr>
<th>r4</th><td>The single flag End de-aggregated into Fin and Rst.
  <b>gd_tcflag.tcbm.End</b> remains for filtering TCP streams containing either Fin or Rst</td></tr>
<th>r5</th><td>Individual flag names added to the filter syntax</td></tr>
<th>r6</th><td>Counter for tracking "tcp.analysis.flags" added</td></tr>
<th>r7</th><td>Check for not tcp_keep_alive when tracking the payload (Data)</td></tr>
<th>r8</th><td>Tracking for jumbo IP MTU and for IP fragments added</td></tr>
<th>r9</th><td>Changed IP fragments check from "ip.fragment" to "ip.flags.mf"</td></tr>
<th>r10</th><td>Branches detalisation section for r6 added</td></tr>
<th>r11</th><td>Duplicate Ack added to tracking "tcp.analysis.flags"</td></tr>
<th>r12</th><td>Simplified filter syntax for flags set on either A or B (or both)</td></tr>
<th>r13</th><td>Keep counters separate for fast, spurious and plain retransmissions</td></tr>
<th>r14</th><td>Support for multiple passes in TCP analysis tracking</td></tr>
<th>r15</th><td>TCP analysis differentiation between peers added</td></tr>
<th>r16</th><td>Statistics section added</td></tr>
<tr><th>r17</th><td>Sections activation made configurable</td></tr>
<tr><th>r18</th><td>TCP window size field tracking added to the statistics</td></tr>
<tr><th>r19</th><td>TCP bytes in flight tracking added to the statistics</td></tr>
</tbody>
</table>
