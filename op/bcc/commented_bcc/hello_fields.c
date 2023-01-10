/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/bcc/hello_fields.c,
 Startline: 1,
 Endline: 4,
 Funcname: hello,
 Input: (void *ctx),
 Output: int,
 Helpers: [bpf_trace_printk,],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
int hello(void *ctx) {
	bpf_trace_printk("Hello, World!\\n");
	return 0;
}
