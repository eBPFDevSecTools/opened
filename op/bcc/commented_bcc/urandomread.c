/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"\\t     \\\"%d\\\\\\\\n\\\"\",\n  \" args->got_bits\"\n ]\n}"
    ]
  },
  "startLine": 1,
  "endLine": 5,
  "File": "/home/sayandes/opened_extraction/examples/bcc/urandomread.c",
  "Funcname": "TRACEPOINT_PROBE",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    ""
  ],
  "Input": [
    "random",
    " urandom_read"
  ],
  "Output": "NA",
  "Helper": "bpf_trace_printk,",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
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
