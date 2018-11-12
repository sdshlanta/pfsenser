<?php
/*
 * ifstats.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2004-2016 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
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

##|+PRIV
##|*IDENT=page-xmlrpcinterfacestats
##|*NAME=XMLRPC Interface Stats
##|*DESCR=Allow access to the 'XMLRPC Interface Stats' page.
##|*MATCH=ifstats.php*
##|-PRIV

$nocsrf = true;

require_once('guiconfig.inc');
require_once("interfaces.inc");


//overload the use of this page until the conversion of both traffic graphs have been completed
if($_POST['if']) {

	$ifs = $_POST['if'];

	$ifarray = explode("|", $ifs);

	$temp = gettimeofday();
	$timing = (double)$temp["sec"] + (double)$temp["usec"] / 1000000.0;
	$obj = [];
	$count = 0;

	foreach ($ifarray as $if) {

		$realif = get_real_interface($if);

		if (!$realif) {
			$realif = $if; // Need for IPsec case interface.
		}

		$ifinfo = pfSense_get_interface_stats($realif);

		$obj[$if] = [];

		$obj[$if][0]['key'] = $if . "in";
		$obj[$if][0]['values'] = array($timing, $ifinfo['inbytes']);

		$obj[$if][1]['key'] = $if . "out";
		$obj[$if][1]['values'] = array($timing, $ifinfo['outbytes']);
/*
		$obj[$count]['key'] = $if . "in";
		$obj[$count]['name'] = $if . " (in)";
		$obj[$count]['values'] = array($timing, $ifinfo['inbytes']);

		$count++;

		$obj[$count]['key'] = $if . "out";
		$obj[$count]['name'] = $if . " (out)";
		$obj[$count]['values'] = array($timing, $ifinfo['outbytes']);

		$count++;
*/
	}

	header('Content-Type: application/json');
	echo json_encode($obj,JSON_PRETTY_PRINT|JSON_PARTIAL_OUTPUT_ON_ERROR|JSON_NUMERIC_CHECK);

} else {

	$if = $_GET['if'];

	$realif = get_real_interface($if);

	if (!$realif) {
		$realif = $if; // Need for IPsec case interface.
	}

	$ifinfo = pfSense_get_interface_stats($realif);

	$temp = gettimeofday();
	$timing = (double)$temp["sec"] + (double)$temp["usec"] / 1000000.0;

	header("Last-Modified: " . gmdate("D, j M Y H:i:s") . " GMT");
	header("Expires: " . gmdate("D, j M Y H:i:s", time()) . " GMT");
	header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP/1.1
	header("Pragma: no-cache"); // HTTP/1.0

	echo "$timing|" . $ifinfo['inbytes'] . "|" . $ifinfo['outbytes'] . "\n";

}

?>
