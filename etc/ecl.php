<?php
/*
 * ecl.php
 *
 * Copyright (c) 2010-2015 Rubicon Communications, LLC (Netgate). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *    "This product includes software developed by the pfSense Project
 *    for use in the pfSense® software distribution. (http://www.pfsense.org/).
 *
 * 4. The names "pfSense" and "pfSense Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    coreteam@pfsense.org.
 *
 * 5. Products derived from this software may not be called "pfSense"
 *    nor may "pfSense" appear in their names without prior written
 *    permission of the Electric Sheep Fencing, LLC.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *
 * "This product includes software developed by the pfSense Project
 * for use in the pfSense software distribution (http://www.pfsense.org/).
 *
 * THIS SOFTWARE IS PROVIDED BY THE pfSense PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE pfSense PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

require_once("globals.inc");
require_once("functions.inc");
require_once("config.lib.inc");
require_once("config.inc");

$debug = false;

function get_boot_disk() {
	global $g, $debug;
	$disk = exec("/sbin/mount | /usr/bin/grep \"on / \" | /usr/bin/cut -d'/' -f3 | /usr/bin/cut -d' ' -f1");
	return $disk;
}

function get_swap_disks() {
	exec("/usr/sbin/swapinfo | /usr/bin/sed '/^\/dev/!d; s,^/dev/,,; s, .*\$,,'", $disks);
	return $disks;
}

function get_disk_slices($disk) {
	global $g, $debug;
	$slices = glob("/dev/" . $disk . "s*");
	$slices = str_replace("/dev/", "", $slices);
	return $slices;
}

function get_disks() {
	global $g, $debug;
	$disks_array = array();
	$disks_s = explode(" ", get_single_sysctl("kern.disks"));
	foreach ($disks_s as $disk) {
		if (trim($disk)) {
			$disks_array[] = $disk;
		}
	}
	return $disks_array;
}

function discover_config($mountpoint) {
	global $g, $debug;
	$locations_to_check = array("/", "/config");
	foreach ($locations_to_check as $ltc) {
		$tocheck = "/tmp/mnt/cf{$ltc}config.xml";
		if ($debug) {
			echo "\nChecking for $tocheck";
			if (file_exists($tocheck)) {
				echo " -> found!";
			}
		}
		if (file_exists($tocheck)) {
			return $tocheck;
		}
	}
	return "";
}

function test_config($file_location) {
	global $g, $debug;
	if (!$file_location) {
		return;
	}
	// config.xml was found.  ensure it is sound.
	$root_obj = trim("<{$g['xml_rootobj']}>");
	$xml_file_head = exec("/usr/bin/head -2 " . escapeshellarg($file_location) . " | /usr/bin/tail -n1");
	if ($debug) {
		echo "\nroot obj  = $root_obj";
		echo "\nfile head = $xml_file_head";
	}
	if ($xml_file_head == $root_obj) {
		// Now parse config to make sure
		$config_status = config_validate($file_location);
		if ($config_status) {
			return true;
		}
	}
	return false;
}

// Probes all disks looking for config.xml
function find_config_xml() {
	global $g, $debug;
	$disks = get_disks();
	// Safety check.
	if (!is_array($disks)) {
		return;
	}
	$boot_disk = get_boot_disk();
	$swap_disks = get_swap_disks();
	exec("/bin/mkdir -p /tmp/mnt/cf");
	foreach ($disks as $disk) {
		$slices = get_disk_slices($disk);
		if (is_array($slices)) {
			foreach ($slices as $slice) {
				if ($slice == "") {
					continue;
				}
				if (stristr($slice, $boot_disk)) {
					if ($debug) {
						echo "\nSkipping boot device slice $slice";
					}
					continue;
				}
				if (in_array($slice, $swap_disks)) {
					if ($debug) {
						echo "\nSkipping swap device slice $slice";
					}
					continue;
				}
				echo " $slice";
				// First try msdos fs
				if ($debug) {
					echo "\n/sbin/mount -t msdosfs /dev/{$slice} /tmp/mnt/cf 2>/dev/null \n";
				}
				$result = exec("/sbin/mount -t msdosfs /dev/{$slice} /tmp/mnt/cf 2>/dev/null");
				// Next try regular fs (ufs)
				if (!$result) {
					if ($debug) {
						echo "\n/sbin/mount /dev/{$slice} /tmp/mnt/cf 2>/dev/null \n";
					}
					$result = exec("/sbin/mount /dev/{$slice} /tmp/mnt/cf 2>/dev/null");
				}
				$mounted = trim(exec("/sbin/mount | /usr/bin/grep -v grep | /usr/bin/grep '/tmp/mnt/cf' | /usr/bin/wc -l"));
				if ($debug) {
					echo "\nmounted: $mounted ";
				}
				if (intval($mounted) > 0) {
					// Item was mounted - look for config.xml file
					$config_location = discover_config($slice);
					if ($config_location) {
						if (test_config($config_location)) {
							// We have a valid configuration.  Install it.
							echo " -> found config.xml\n";
							echo "Backing up old configuration...\n";
							backup_config();
							echo "Restoring [{$slice}] {$config_location}...\n";
							restore_backup($config_location);
							echo "Cleaning up...\n";
							exec("/sbin/umount /tmp/mnt/cf");
							exit;
						}
					}
					exec("/sbin/umount /tmp/mnt/cf");
				}
			}
		}
	}
}

echo "External config loader 1.0 is now starting...";
find_config_xml();
echo "\n";

?>
