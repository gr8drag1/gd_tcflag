<h1><b>gd_tcflag</b> post-dissector plugin</h1>

<p>
A Wireshark Lua post-dissector for express analysis of TCP conversations.<br>
The TCP conversation is tracked for endpoint A and B individually. The decision which side is A and B is performed as follows:
<ul>
 <li>If one TCP port is numerically smaller than the other, then the smaller port is A and the greater port is B</li>
 <li>If the port values are identical, then A is the numerically smaller IP address</li>
</ul>
The post-dissector creates its own section with three subsections.
</p>

<h2>Protocol flags subsection, <b>gd_tcflag.tcbm</b></h2>
    
<p>
Composed of the following boolean flags:
<ul>
 <li><b>gd_tcflag.tcbm.Syn</b> : either gd_tcflag.tcbm.SynA or gd_tcflag.tcbm.SynB
  <blockquote>
  [1] gd_tcflag.tcbm.SynA : peer A sent flag Syn<br>
  [2] gd_tcflag.tcbm.SynB : peer B sent flag Syn
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.SnA</b> : either gd_tcflag.tcbm.SnAA or gd_tcflag.tcbm.SnAB
  <blockquote>
  [4] gd_tcflag.tcbm.SnAA : peer A sent flags Syn+Ack<br>
  [8] gd_tcflag.tcbm.SnAB : peer B sent flags Syn+Ack
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.Ack</b> : either gd_tcflag.tcbm.AckA or gd_tcflag.tcbm.AckB
  <blockquote>
  [16] gd_tcflag.tcbm.AckA : peer A sent flag Ack (with no data payload)<br>
  [32] gd_tcflag.tcbm.AckB : peer B sent flag Ack (with no data payload)
  </blockquote>
</li>
 <li><b>gd_tcflag.tcbm.Dat</b> : either gd_tcflag.tcbm.DatA or gd_tcflag.tcbm.DatB
  <blockquote>
  [64] gd_tcflag.tcbm.DatA : peer A sent a TCP segment containing data payload<br>
  [128] gd_tcflag.tcbm.DatB : peer B sent a TCP segment containing data payload
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.MTUgt1500</b> : either gd_tcflag.tcbm.MTUgt1500A or gd_tcflag.tcbm.MTUgt1500B
  <blockquote>
   [256] gd_tcflag.tcbm.MTUgt1500A : peer A sent an IP packet longer than 1500 B<br>
   [512] gd_tcflag.tcbm.MTUgt1500B : peer B sent an IP packet longer than 1500 B
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.fragment</b> : either gd_tcflag.tcbm.fragmentA or gd_tcflag.tcbm.fragmentB
  <blockquote>
    [1024] gd_tcflag.tcbm.fragmentA : peer A sent a IP packet with MF (more fragments) flag set<br>
    [2048] gd_tcflag.tcbm.fragmentB : peer B sent a IP packet with MF (more fragments) flag set
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.Fin</b> : either gd_tcflag.tcbm.FinA or gd_tcflag.tcbm.FinB
  <blockquote>
   [4096] gd_tcflag.tcbm.FinA : peer A sent flag Fin<br>
   [8192] gd_tcflag.tcbm.FinB : peer B sent flag Fin
  </blockquote>
 </li>
 <li><b>gd_tcflag.tcbm.Rst</b> : either gd_tcflag.tcbm.RstA or gd_tcflag.tcbm.RstB
  <blockquote>
   [16384] gd_tcflag.tcbm.RstA : peer A sent flag Rst<br>
   [32768] gd_tcflag.tcbm.RstB : peer B sent flag Rst
  </blockquote>
 </li>
</ul>
</p>

<h2>Protocol analysis counters subsection, <b>gd_tcflag.tcanflcn</b></h2>

<p>
TCP payload gone missing
 <ul>
  <li>gd_tcflag.tcanflcn.ooo : tcp.analysis.out_of_order</li>
  <li>gd_tcflag.tcanflcn.rtr : tcp.analysis.retransmission</li>
  <li>gd_tcflag.tcanflcn.frtr : tcp.analysis.fast_retransmission</li>
  <li>gd_tcflag.tcanflcn.srtr : tcp.analysis.spurious_retransmission</li>
  <li>gd_tcflag.tcanflcn.dack : tcp.analysis.duplicate_ack_num</li>
  <li>gd_tcflag.tcanflcn.losg : tcp.analysis.lost_segment</li>
 </ul>
</p>

<p>
TCP window flow control
<ul>
 <li>gd_tcflag.tcanflcn.wful : tcp.analysis.window_full</li>
 <li>gd_tcflag.tcanflcn.wupd : tcp.analysis.window_update</li>
 <li>gd_tcflag.tcanflcn.zwin : tcp.analysis.zero_window</li>
 <li>gd_tcflag.tcanflcn.zwp : tcp.analysis.zero_window_probe</li>
 <li>gd_tcflag.tcanflcn.zwpa : tcp.analysis.zero_window_probe_ack</li>
</ul>
</p>

<p>
TCP keep-alive
<ul>
 <li>gd_tcflag.tcanflcn.ka : tcp.analysis.keep_alive</li>
 <li>gd_tcflag.tcanflcn.kaa : tcp.analysis.keep_alive_ack</li>
</ul>
</p>

<p>
Miscellaneous
<ul><li>gd_tcflag.tcanflcn.rusp : tcp.analysis.reused_ports</li></ul>
</p>

<h2>Protocol statistics counters subsection, <b>gd_tcflag.tcstatf</b></h2>

<p>
 <ul>
  <li>gd_tcflag.tcstatfl.duration : TCP stream duration</li>
  <li>gd_tcflag.tcstatfl.begin : First frame of the TCP stream</li>
  <li>gd_tcflag.tcstatfl.end : Last frame of the TCP stream</li>
 </ul>
</p>

<p>
 <ul>
  <li>gd_tcflag.tcstatfl.framcount : Total number of frames
   <ul>
    <li>gd_tcflag.tcstatfl.framcount_A : Number of frames received from A</li>
    <li>gd_tcflag.tcstatfl.framcount_B : Number of frames received from B</li>
   </ul>
  </ul>
</p>

<p>
gd_tcflag.tcstatfl.bytecount : Total number of payload bytes
 <ul>
  <li>gd_tcflag.tcstatfl.bytecount_A : Number of payload bytes received from A</li>
  <li>      gd_tcflag.tcstatfl.bytecount_B : Number of payload bytes received from B</li>
  <li>      gd_tcflag.tcstatfl.byteratio : Ratio of payload bytes, dB (logarithmic, between 0 and 100)</li>
 </ul>
</p>

<h2>Known limitations</h2>

<p>
Believed fundamental to the architecture of the host code
</p>

<p>
Wireshark (GUI) parses the loaded packet trace digressing during the second pass (displaying the packets updated by these digressions) , while tshark (CLI) performs the second pass (explicitly enforced with option -2) linearly. As a result:
<ul>
 <li>In the GUI gd_tcflag values always covers the complete TCP stream and it is immediately possible to see whether the respective TCP stream contained any Syn, data payload, Fin or Rst by looking at any arbitrary TCP segment of the stream</li>
 <li>In the CLI gd_tcflag values may be accumulating over the lifetime of the TCP stream registering new events with only the last TCP segment of the stream is guaranteed to contain the complete record</li>
 <li>TCP stream numbering. The decision between whether a frame belongs to an existing TCP stream or to a new one belongs to the TCP protocol dissector</li>
</ul>
