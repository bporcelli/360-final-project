#/bin/bash

realConfig=$1
path=$2


grep "^A: RW " $path |cut -f 3 -d " "|sort|uniq > /tmp/ronly
grep "^A: R " $path |gawk '{print $3}'|sort|uniq >> /tmp/ronly

sort /tmp/ronly > /tmp/r0
grep "regarded as explicit" $path |cut -f 4 -d " "|sort|uniq > /tmp/explicit

comm /tmp/r0 /tmp/explicit -23|grep "$realConfig" > /tmp/collected



lwip_trusted find $realConfig -type f|grep -v Cache| sort > /tmp/real

echo ". entries: $(wc -l /tmp/real)"
echo "FP of . entries: $(comm -23 /tmp/collected /tmp/real|wc -l)"
echo "FN of . entries: $(comm -13 /tmp/collected /tmp/real|wc -l)"

exit 0

echo "Identified: $(comm -12 /tmp/collected /tmp/real|wc -l)"
echo "Missed: $(comm -13 /tmp/collected /tmp/real|wc -l)"
echo "Extra:  $(comm -23 /tmp/collected /tmp/real|wc -l)"


echo "Identified"
comm -12 /tmp/collected /tmp/real

echo "Extra"
comm -23 /tmp/collected /tmp/real

echo "Missed"
comm -13 /tmp/collected /tmp/real



