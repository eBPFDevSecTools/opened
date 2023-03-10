// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

static int (*ebpf_get_current_comm)(char* buffer, uint32_t buffer_size) = (void*) 16;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Copy the comm attribute of the current task into <[ buf ]>(IP: 0) of size_of_buf. The comm attribute contains the name of the executable (excluding the path) for the current task. The <[ size_of_buf ]>(IP: 1) must be strictly positive. On success , the helper makes sure that the <[ buf ]>(IP: 0) is NUL-terminated. On failure , it is filled with zeroes. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "get_current_comm",
          "Input Params": [
            "{Type: char ,Var: *buf}",
            "{Type:  u32 ,Var: size_of_buf}"
          ],
          "compatible_hookpoints": [
            "kprobe",
            "tracepoint",
            "perf_event",
            "raw_tracepoint",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "bcc",
          "FunctionName": "bpf_get_current_comm",
          "Return Type": "int",
          "Description": "bpf_get_current_comm(char *buf, int size_of_buf) Return: 0 on success Populates the first argument address with the current process name. It should be a pointer to a char array of at least size TASK_COMM_LEN, which is defined in linux/sched.h. For example: ```C include ",
          "Return": "0 on success",
          "Input Prameters": [
            "{Type: char* ,Var: buf}",
            "{Type: int ,Var: size_of_buf}"
          ],
          "compatible_hookpoints": [
            "kprobe",
            "tracepoint",
            "perf_event",
            "raw_tracepoint",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 15,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/badhelpercall.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "int",
  "helper": [
    "get_current_comm",
    "bpf_get_current_comm"
  ],
  "compatibleHookpoints": [
    "tracepoint",
    "kprobe",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "perf_event"
  ],
  "source": [
    "int func ()\n",
    "{\n",
    "    char buffer [1];\n",
    "    return ebpf_get_current_comm (buffer, 20);\n",
    "}\n"
  ],
  "called_function_list": [
    "ebpf_map_update_elem",
    "ebpf_get_current_comm"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
int func()
{
    char buffer[1];

    // The following should fail verification since it asks the helper
    // to write past the end of the stack.
    return ebpf_get_current_comm(buffer, 20);
}
