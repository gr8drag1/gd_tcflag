<h1>gd_tcflag postdissector plugin</h1>

<p>
A Wireshark Lua post-dissector for express analysis of TCP conversations<br>
The post-dissector creates its own section with three subsections
</p>

<h2>Protocol flags gd_tcflag.tcbm</h2>

    The TCP conversation is tracked for each endpoint individually: flags set by endpoint A and flags set by endpoint B. The decision which side is A and B is performed as follows:
        If one TCP port is numerically smaller than the other, then the smaller port is A and the greater port is B
        If the port values are identical, then A is the numerically smaller IP address
    Protocol field gd_tcflag.tcbm is composed of the following boolean flags:
        gd_tcflag.tcbm.Syn : either gd_tcflag.tcbm.SynA or gd_tcflag.tcbm.SynB
        [1] gd_tcflag.tcbm.SynA : peer A sent flag Syn
        [2] gd_tcflag.tcbm.SynB : peer B sent flag Syn
        gd_tcflag.tcbm.SnA : either gd_tcflag.tcbm.SnAA or gd_tcflag.tcbm.SnAB
        [4] gd_tcflag.tcbm.SnAA : peer A sent flags Syn+Ack
        [8] gd_tcflag.tcbm.SnAB : peer B sent flags Syn+Ack
        gd_tcflag.tcbm.Ack : either gd_tcflag.tcbm.AckA or gd_tcflag.tcbm.AckB
        [16] gd_tcflag.tcbm.AckA : peer A sent flag Ack (with no data payload)
        [32] gd_tcflag.tcbm.AckB : peer B sent flag Ack (with no data payload)
        gd_tcflag.tcbm.Dat : either gd_tcflag.tcbm.DatA or gd_tcflag.tcbm.DatB
        [64] gd_tcflag.tcbm.DatA : peer A sent a TCP segment containing data payload
        [128] gd_tcflag.tcbm.DatB : peer B sent a TCP segment containing data payload
        gd_tcflag.tcbm.MTUgt1500 : either gd_tcflag.tcbm.MTUgt1500A or gd_tcflag.tcbm.MTUgt1500B
        [256] gd_tcflag.tcbm.MTUgt1500A : peer A sent an IP packet longer than 1500 B
        [512] gd_tcflag.tcbm.MTUgt1500B : peer B sent an IP packet longer than 1500 B
        gd_tcflag.tcbm.fragment : either gd_tcflag.tcbm.fragmentA or gd_tcflag.tcbm.fragmentB
        [1024] gd_tcflag.tcbm.fragmentA : peer A sent a IP packet with MF (more fragments) flag set
        [2048] gd_tcflag.tcbm.fragmentB : peer B sent a IP packet with MF (more fragments) flag set
        gd_tcflag.tcbm.Fin : either gd_tcflag.tcbm.FinA or gd_tcflag.tcbm.FinB
        [4096] gd_tcflag.tcbm.FinA : peer A sent flag Fin
        [8192] gd_tcflag.tcbm.FinB : peer B sent flag Fin
        gd_tcflag.tcbm.Rst : either gd_tcflag.tcbm.RstA or gd_tcflag.tcbm.RstB
        [16384] gd_tcflag.tcbm.RstA : peer A sent flag Rst
        [32768] gd_tcflag.tcbm.RstB : peer B sent flag Rst

Protocol analysis counters gd_tcflag.tcanflcn

    TCP payload gone missing
        gd_tcflag.tcanflcn.ooo : tcp.analysis.out_of_order
        gd_tcflag.tcanflcn.rtr : tcp.analysis.retransmission
        gd_tcflag.tcanflcn.frtr : tcp.analysis.fast_retransmission
        gd_tcflag.tcanflcn.srtr : tcp.analysis.spurious_retransmission
        gd_tcflag.tcanflcn.dack : tcp.analysis.duplicate_ack_num
        gd_tcflag.tcanflcn.losg : tcp.analysis.lost_segment

    TCP window flow control
        gd_tcflag.tcanflcn.wful : tcp.analysis.window_full
        gd_tcflag.tcanflcn.wupd : tcp.analysis.window_update
        gd_tcflag.tcanflcn.zwin : tcp.analysis.zero_window
        gd_tcflag.tcanflcn.zwp : tcp.analysis.zero_window_probe
        gd_tcflag.tcanflcn.zwpa : tcp.analysis.zero_window_probe_ack

    TCP keep-alive
        gd_tcflag.tcanflcn.ka : tcp.analysis.keep_alive
        gd_tcflag.tcanflcn.kaa : tcp.analysis.keep_alive_ack

    Miscellaneous
        gd_tcflag.tcanflcn.rusp : tcp.analysis.reused_ports
    Click to add a new task...

Protocol statistics counters gd_tcflag.tcstatf

    gd_tcflag.tcstatfl.duration : TCP stream duration
    gd_tcflag.tcstatfl.begin : First frame of the TCP stream
    gd_tcflag.tcstatfl.end : Last frame of the TCP stream

    gd_tcflag.tcstatfl.framcount : Total number of frames
        gd_tcflag.tcstatfl.framcount_A : Number of frames received from A
        gd_tcflag.tcstatfl.framcount_B : Number of frames received from B

    gd_tcflag.tcstatfl.bytecount : Total number of payload bytes
        gd_tcflag.tcstatfl.bytecount_A : Number of payload bytes received from A
        gd_tcflag.tcstatfl.bytecount_B : Number of payload bytes received from B
        gd_tcflag.tcstatfl.byteratio : Ratio of payload bytes, dB (logarithmic, between 0 and 100)


Known limitations

Believed fundamental to the architecture of the host code

    Wireshark (GUI) parses the loaded packet trace digressing during the second pass [displaying the packets updated by these digressions] , while tshark (CLI) performs the second pass [explicitly enforced with option -2] linearly. As a result:
         In the GUI gd_tcflag values always covers the complete TCP stream and it is immediately possible to see whether the respective TCP stream contained any Syn, data payload, Fin or Rst by looking at any arbitrary TCP segment of the stream
        In the CLI gd_tcflag values may be accumulating over the lifetime of the TCP stream registering new events with only the last TCP segment of the stream is guaranteed to contain the complete record
    TCP stream numbering. The decision between whether a frame belongs to an existing TCP stream or to a new one belongs to the TCP protocol dissector
