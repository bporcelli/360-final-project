#/bin/bash

CWD=$(readlink -f $0)
CWD=$(dirname $CWD)
cd $CWD



for f in $(find /lwip/opendb/ -type f -name "*openTrace"); do
	if [ -f $f.redirect ]; then
		if test $f.redirect -nt $f; then
			echo "skipping $f"
			continue
		fi
	fi
	echo "processing $f"
	./getRedirectedList.sh $f > $f.redirect
done

exit 0

find /lwip/opendb/ -type f -name "*openTrace" |xargs -I'{}' bash -c "./getRedirectedList.sh {} > {}.redirect"

#Fix permission problems
find /lwip/opendb/ -type f|xargs chgrp trusted_group 
find /lwip/opendb/ -type f|xargs chmod g+rwx,o+r

