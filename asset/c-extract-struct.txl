%Author: Sayandeep Sen (sayandes@in.ibm.com)
%Author: Palani Kodeswaran (palani.kodeswaran@in.ibm.com)

% Null transform - format output according to grammar
%include "c.grm.1"
include "c.grm"

% Ignore byte order marks on source files
include "bom.grm"

% Uncomment this line to approximately parse and preserve comments
% include "C18/c-comments.grm"
% TODO: uncommenting is leading to issues with multiline '//' comments, so disabled

define begin_marker
 [NL] '<[SPOFF] 'struct '>[SPON] [NL]
end define

define end_marker
 '<[SPOFF] '/struct '>[SPON] [NL]
end define

define block
    [compound_statement]
end define

redefine function_definition_or_declaration
    	[function_definition]  	
    |	[struct_or_union_definition]  	
    |	[opt begin_marker] [struct_or_union_definition] [opt end_marker]
    |	[enum_definition]  	
    |	[declaration] 		
#ifdef GNU
    |	[asm_statement] 
#endif
#ifdef LINUX
    |	[macro_declaration_or_statement]  
#endif
#ifdef PREPROCESSOR
    |	[preprocessor]
#endif
end redefine


rule replaceStruct0
	replace [function_definition_or_declaration]
	  T [struct_or_union_definition] 
% U [declarator_opt_init_semi] %S [semi] 

	construct BEG [begin_marker]
	 '< 'struct  '>

	construct END [end_marker]
	 '<  '/struct '>

	by
	   BEG  T  END
end rule

function main 
	replace [program] 
		P  [program]
	by
	 	P %[debug]
		  [replaceStruct0]
end function
