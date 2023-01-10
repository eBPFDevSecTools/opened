/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/bcc/urandomread.c,
 Startline: 1,
 Endline: 5,
 Funcname: TRACEPOINT_PROBE,
 Input: (random, urandom_read),
 Output: NA,
 Helpers: [bpf_trace_printk,],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
TRACEPOINT_PROBE (random, urandom_read)
{
	    bpf_trace_printk ("%d\\n", args->got_bits);
	        return 0;
}
