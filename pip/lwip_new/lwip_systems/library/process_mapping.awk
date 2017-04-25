#!/usr/bin/awk -f
BEGIN {
	FS = ",";
	ORS = "";
}
{
	if ($0 ~/^$/)
		next;
	if (index($1, "#") > 0)
		next;

	gsub(/ /, "", $2);
	gsub(/ /, "", $3);

	if ($2 !~/^ *$/) {
		syscall_pre[$1] = $2;
	}

	if ($3 !~/^ *$/) {
		syscall_post[$1] = $3;
	}
}
END {
	print "`#'define PRE_HANDLER_ENTRY \\\n"
	count = length(syscall_pre);
	for (i in syscall_pre) {
		print "[SYS_" i "] = ", syscall_pre[i];
		if (--count > 0)
			print ", \\";
		print "\n";
	}
	print "\n";
	
	print "`#'define POST_HANDLER_ENTRY \\\n"
	count = length(syscall_post);
	for (i in syscall_post) {
		print "[SYS_" i "] = ", syscall_post[i];
		if (--count > 0)
			print ", \\";
		print "\n";
	}
	print "\n";

}
