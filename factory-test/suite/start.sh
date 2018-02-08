#!/bin/bash
echo "Welcome to the demo test suite!"
echo
echo "Manufacturers can use this tool to perform tests in the factory"
echo "environment. The USB drive used to load it can now be removed."
echo "The tool can reboot the machine if needed, /var/eos-factory-test/start.sh"
echo "will be executed again if found during boot. The tool should completely"
echo "remove /var/eos-factory-test after it finishes, as well as any other"
echo "files it may have created."
echo

SECS=5
while [ ${SECS} -gt 0 ] ; do
	echo -ne "Rebooting in ${SECS}s\033[0K\r"
	sleep 1
	: $((SECS--))
done

echo -ne "Cleaning /var/eos-factory-test..."
rm -rf /var/eos-factory-test
sleep 1
echo " OK"

sleep 1
reboot
