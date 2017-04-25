#!/usr/bin/awk -f
BEGIN {
	FS = ",";
	ORS = "";
}
{
	if ($0 ~/^$/)
		next;

        gsub(/ /, "", $2);
        gsub(/ /, "", $3);
        gsub(/ /, "", $4);



        if ($1 == "H") {
                if ($3 !~/^ *$/) {
                        high_syscall_pre[$2] = $3;
                }

                if ($4 !~/^ *$/) {
                        high_syscall_post[$2] = $4;
                }
        } else if ($1 == "L") {
                if ($3 !~/^ *$/) {
                        low_syscall_pre[$2] = $3;
                }

                if ($4 !~/^ *$/) {
                        low_syscall_post[$2] = $4;
                }
        } else if ($1 == "B") {
                if ($3 !~/^ *$/) {
                        low_syscall_pre[$2] = $3;
                        high_syscall_pre[$2] = $3;
                }

                if ($4 !~/^ *$/) {
                        low_syscall_post[$2] = $4;
                        high_syscall_post[$2] = $4;
                }
        }

}
END {
	print "`#'define HIGH_PRE_HANDLER_ENTRY \\\n"
	count = length(high_syscall_pre);
	for (i in high_syscall_pre) {
		print "[SYS_" i "] = ", high_syscall_pre[i];
		if (--count > 0)
			print ", \\";
		print "\n";
	}
	print "\n";
	
	print "`#'define HIGH_POST_HANDLER_ENTRY \\\n"
	count = length(high_syscall_post);
	for (i in high_syscall_post) {
		print "[SYS_" i "] = ", high_syscall_post[i];
		if (--count > 0)
			print ", \\";
		print "\n";
	}
	print "\n";

	print "`#'define LOW_PRE_HANDLER_ENTRY \\\n"
	count = length(low_syscall_pre);
	for (i in low_syscall_pre) {
		print "[SYS_" i "] = ", low_syscall_pre[i];
		if (--count > 0)
			print ", \\";
		print "\n";
	}
	print "\n";
	
	print "`#'define LOW_POST_HANDLER_ENTRY \\\n"
	count = length(low_syscall_post);
	for (i in low_syscall_post) {
		print "[SYS_" i "] = ", low_syscall_post[i];
		if (--count > 0)
			print ", \\";
		print "\n";
	}
	print "\n";

}
