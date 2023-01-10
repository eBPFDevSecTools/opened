//int hello (void *ctx)
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/bcc/trace_fields.c,
 Startline: 2,
 Endline: 6,
 Funcname: hello,
 Input: (NA),
 Output: int,
 Helpers: [bpf_trace_printk,],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
int hello ()
{
	    bpf_trace_printk ("Hello, World!\\n");
	        return 0;
}
