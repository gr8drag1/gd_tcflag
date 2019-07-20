<h1><b>gd_tcflag</b> Wireshark Lua (wslua) post-dissector plugin</h1>

<p>
A Wireshark Lua post-dissector for express analysis of TCP conversations.<br>
Each conversation endpoint, A and B, is tracked individually. The decision which side is A or B is performed as follows:
<ul>
 <li>If one TCP port is numerically less than the other, then the lesser port is A and the greater port is B</li>
 <li>If the port values are identical, then A is the numerically lesser IP address</li>
</ul>
The post-dissector creates its own section with three subsections.
</p>

<h2>Protocol flags subsection, <i>gd_tcflag.tcbm</i></h2>
    
<p>
Composed of the following boolean flags:
<ul>
 <li><b>gd_tcflag.tcbm.Syn</b> : either gd_tcflag.tcbm.SynA or gd_tcflag.tcbm.SynB
  <blockquote>
  <sup>[1]</sup> gd_tcflag.tcbm.SynA : peer A sent flag Syn<br>
  <sup>[2]</sup> gd_tcflag.tcbm.SynB : peer B sent flag Syn
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

<h2>Protocol analysis counters subsection, <i>gd_tcflag.tcanflcn</i></h2>

<p>
TCP payload gone missing
 <ul>
  <li>gd_tcflag.tcanflcn.ooo : <b>tcp.analysis.out_of_order</b></li>
  <li>gd_tcflag.tcanflcn.rtr : <b>tcp.analysis.retransmission</b></li>
  <li>gd_tcflag.tcanflcn.frtr : <b>tcp.analysis.fast_retransmission</b></li>
  <li>gd_tcflag.tcanflcn.srtr : <b>tcp.analysis.spurious_retransmission</b></li>
  <li>gd_tcflag.tcanflcn.dack : <b>tcp.analysis.duplicate_ack_num</b></li>
  <li>gd_tcflag.tcanflcn.losg : <b>tcp.analysis.lost_segment</b></li>
 </ul>
</p>

<p>
TCP window flow control
<ul>
 <li>gd_tcflag.tcanflcn.wful : <b>tcp.analysis.window_full</b></li>
 <li>gd_tcflag.tcanflcn.wupd : <b>tcp.analysis.window_update</b></li>
 <li>gd_tcflag.tcanflcn.zwin : <b>tcp.analysis.zero_window</b></li>
 <li>gd_tcflag.tcanflcn.zwp : <b>tcp.analysis.zero_window_probe</b></li>
 <li>gd_tcflag.tcanflcn.zwpa : <b>tcp.analysis.zero_window_probe_ack</b></li>
</ul>
</p>

<p>
TCP keep-alive
<ul>
 <li>gd_tcflag.tcanflcn.ka : <b>tcp.analysis.keep_alive</b></li>
 <li>gd_tcflag.tcanflcn.kaa : <b>tcp.analysis.keep_alive_ack</b></li>
</ul>
</p>

<p>
Miscellaneous
<ul><li>gd_tcflag.tcanflcn.rusp : <b>tcp.analysis.reused_ports</b></li></ul>
</p>

<h2>Protocol statistics counters subsection, <i>gd_tcflag.tcstatf</i></h2>

<p>
 <ul>
  <li><b>gd_tcflag.tcstatfl.duration</b> : TCP stream duration</li>
  <li><b>gd_tcflag.tcstatfl.begin</b> : First frame of the TCP stream</li>
  <li><b>gd_tcflag.tcstatfl.end</b> : Last frame of the TCP stream</li>
 </ul>
</p>

<p>
 <ul>
  <li>gd_tcflag.tcstatfl.framcount : Total number of frames
   <ul>
    <li><b>gd_tcflag.tcstatfl.framcount_A</b> : Number of frames received from A</li>
    <li><b>gd_tcflag.tcstatfl.framcount_B</b> : Number of frames received from B</li>
   </ul>
  </li> 
 </ul>
</p>

<p>
<ul>
 <li>gd_tcflag.tcstatfl.bytecount : Total number of payload bytes
  <ul>
   <li><b>gd_tcflag.tcstatfl.bytecount_A</b> : Number of payload bytes received from A</li>
   <li><b>gd_tcflag.tcstatfl.bytecount_B</b> : Number of payload bytes received from B</li>
   <li><b>gd_tcflag.tcstatfl.byteratio</b> : Ratio of payload bytes, dB (logarithmic, between 0 and 100)
    <ul>
     <li>If the actual ratio value is higher, it it capped at 100 dB still</li>
     <li>Values close to 0 dB mean that each endpoint sent an approximately equal number of payload bytes</li>
     <li>By the nature of the scale, each 3 dB approximately equals to two times the difference. Each 10 dB represents an order of magnitude difference</li>
   </li>
  </ul>
 </li>
</ul>
</p>

<h2>Known limitations</h2>

<p>
Believed fundamental to the architecture of the host code
</p>

<p>
<ul>
 <li>TCP stream numbering. The decision between whether a frame belongs to an existing TCP stream or to a new one belongs to the TCP protocol dissector</li>
  <li>Wireshark (GUI) parses the loaded packet trace digressing during the second pass [displaying the packets updated by these digressions], while tshark (CLI) performs the second pass [explicitly enforced with option <b>-2</b>] linearly. As a result:
<ul>
 <li>In the GUI gd_tcflag values always covers the complete TCP stream and it is immediately possible to see whether the respective TCP stream contained any Syn, data payload, Fin or Rst by looking at any arbitrary TCP segment of the stream</li>
 <li>In the CLI gd_tcflag values may be accumulating over the lifetime of the TCP stream registering new events with only the last TCP segment of the stream is guaranteed to contain the complete record</li>
</ul>
 </li>
 </ul>
