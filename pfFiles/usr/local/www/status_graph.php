<?php
/*
 * status_graph.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2004-2016 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
 *
 * originally based on m0n0wall (http://m0n0.ch/wall)
 * Copyright (c) 2003-2004 Manuel Kasper <mk@neon1.net>.
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
##|*IDENT=page-status-trafficgraph
##|*NAME=Status: Traffic Graph
##|*DESCR=Allow access to the 'Status: Traffic Graph' page.
##|*MATCH=status_graph.php*
##|*MATCH=bandwidth_by_ip.php*
##|*MATCH=graph.php*
##|*MATCH=ifstats.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("ipsec.inc");

// Get configured interface list
$ifdescrs = get_configured_interface_with_descr();
if (ipsec_enabled()) {
	$ifdescrs['enc0'] = gettext("IPsec");
}

foreach (array('server', 'client') as $mode) {
	if (is_array($config['openvpn']["openvpn-{$mode}"])) {
		foreach ($config['openvpn']["openvpn-{$mode}"] as $id => $setting) {
			if (!isset($setting['disable'])) {
				$ifdescrs['ovpn' . substr($mode, 0, 1) . $setting['vpnid']] = gettext("OpenVPN") . " " . $mode . ": ".htmlspecialchars($setting['description']);
			}
		}
	}
}

// Compatiblity to restore GET parameters used pre-2.3
// Useful to save a URL for a given graph configuration
if (isset($_GET['if']) && !isset($_POST['if'])) {
	$_POST['if'] = $_GET['if'];
}
if (isset($_GET['sort']) && !isset($_POST['sort'])) {
	$_POST['sort'] = $_GET['sort'];
}
if (isset($_GET['filter']) && !isset($_POST['filter'])) {
	$_POST['filter'] = $_GET['filter'];
}
if (isset($_GET['hostipformat']) && !isset($_POST['hostipformat'])) {
	$_POST['hostipformat'] = $_GET['hostipformat'];
}

if ($_POST['if']) {
	$curif = $_POST['if'];
	$found = false;
	foreach ($ifdescrs as $descr => $ifdescr) {
		if ($descr == $curif) {
			$found = true;
			break;
		}
	}
	if ($found === false) {
		header("Location: status_graph.php");
		exit;
	}
} else {
	if (empty($ifdescrs["wan"])) {
		/* Handle the case when WAN has been disabled. Use the first key in ifdescrs. */
		reset($ifdescrs);
		$curif = key($ifdescrs);
	} else {
		$curif = "wan";
	}
}
if ($_POST['sort']) {
	$cursort = $_POST['sort'];
} else {
	$cursort = "";
}
if ($_POST['filter']) {
	$curfilter = $_POST['filter'];
} else {
	$curfilter = "";
}
if ($_POST['hostipformat']) {
	$curhostipformat = $_POST['hostipformat'];
} else {
	$curhostipformat = "";
}
if ($_POST['backgroundupdate']) {
	$curbackgroundupdate = $_POST['backgroundupdate'];
} else {
	$curbackgroundupdate = "";
}

function iflist() {
	global $ifdescrs;

	$iflist = array();

	foreach ($ifdescrs as $ifn => $ifd) {
		$iflist[$ifn] = $ifd;
	}

	return($iflist);
}

$pgtitle = array(gettext("Status"), gettext("Traffic Graph"));

include("head.inc");

$form = new Form(false);
$form->addClass('auto-submit');

$section = new Form_Section('Graph Settings');

$group = new Form_Group('');

$group->add(new Form_Select(
	'if',
	null,
	$curif,
	iflist()
))->setHelp('Interface');

$group->add(new Form_Select(
	'sort',
	null,
	$cursort,
	array (
		'in'	=> gettext('Bandwidth In'),
		'out'	=> gettext('Bandwidth Out')
	)
))->setHelp('Sort by');

$group->add(new Form_Select(
	'filter',
	null,
	$curfilter,
	array (
		'local'	=> gettext('Local'),
		'remote'=> gettext('Remote'),
		'all'	=> gettext('All')
	)
))->setHelp('Filter');

$group->add(new Form_Select(
	'hostipformat',
	null,
	$curhostipformat,
	array (
		''			=> gettext('IP Address'),
		'hostname'	=> gettext('Host Name'),
		'descr'		=> gettext('Description'),
		'fqdn'		=> gettext('FQDN')
	)
))->setHelp('Display');

$group->add(new Form_Select(
	'backgroundupdate',
	null,
	$curbackgroundupdate,
	array (
		'false'	=> gettext('Clear graphs when not visible.'),
		'true'	=> gettext('Keep graphs updated on inactive tab. (increases cpu usage)'),
	)
))->setHelp('Background updates');

$section->add($group);

$form->add($section);
print $form;

?>

<script src="/vendor/d3/d3.min.js"></script>
<script src="/vendor/nvd3/nv.d3.js"></script>
<script src="/vendor/visibility/visibility-1.2.3.min.js"></script>

<link href="/vendor/nvd3/nv.d3.css" media="screen, projection" rel="stylesheet" type="text/css">

<script type="text/javascript">

//<![CDATA[
events.push(function() {

	var InterfaceString = "<?=$curif?>";

	//store saved settings in a fresh localstorage
	localStorage.clear();
	localStorage.setItem('interval', 1);
	localStorage.setItem('invert', "true");
	localStorage.setItem('size', 1);
	window.interfaces = InterfaceString.split("|");
	window.charts = {};
    window.myData = {};
    window.updateIds = 0;
    window.updateTimerIds = 0;
    window.latest = [];
    var refreshInterval = localStorage.getItem('interval');

    //TODO make it fall on a second value so it increments better
    var now = then = new Date(Date.now());

    var nowTime = now.getTime();

	$.each( window.interfaces, function( key, value ) {

		myData[value] = [];
		updateIds = 0;
		updateTimerIds = 0;

		var itemIn = new Object();
		var itemOut = new Object();

		itemIn.key = value + " (in)";
		if(localStorage.getItem('invert') === "true") { itemIn.area = true; }
		itemIn.first = true;
		itemIn.values = [{x: nowTime, y: 0}];
		myData[value].push(itemIn);

		itemOut.key = value + " (out)";
		if(localStorage.getItem('invert') === "true") { itemOut.area = true; }
		itemOut.first = true;
		itemOut.values = [{x: nowTime, y: 0}];
		myData[value].push(itemOut);

	});

    var backgroundupdate = $('#backgroundupdate').val() === "true";
	draw_graph(refreshInterval, then, backgroundupdate);

	//re-draw graph when the page goes from inactive (in it's window) to active
	Visibility.change(function (e, state) {
		if($('#backgroundupdate').val() === "true"){
			return;
		}
		if(state === "visible") {

			now = then = new Date(Date.now());

			var nowTime = now.getTime();

			$.each( window.interfaces, function( key, value ) {

				Visibility.stop(updateIds);
				clearInterval(updateTimerIds);

				myData[value] = [];

				var itemIn = new Object();
				var itemOut = new Object();

				itemIn.key = value + " (in)";
				if(localStorage.getItem('invert') === "true") { itemIn.area = true; }
				itemIn.first = true;
				itemIn.values = [{x: nowTime, y: 0}];
				myData[value].push(itemIn);

				itemOut.key = value + " (out)";
				if(localStorage.getItem('invert') === "true") { itemOut.area = true; }
				itemOut.first = true;
				itemOut.values = [{x: nowTime, y: 0}];
				myData[value].push(itemOut);

			});

			draw_graph(refreshInterval, then, false);

		}
	});

});
//]]>
</script>

<script src="/js/traffic-graphs.js"></script>

<script type="text/javascript">
//<![CDATA[

var graph_interfacenames = <?php
	foreach ($ifdescrs as $ifname => $ifdescr) {
		$iflist[$ifname] = $ifdescr;
	}
	echo json_encode($iflist);
?>;
function updateBandwidth() {
	$.ajax(
		'/bandwidth_by_ip.php',
		{
			type: 'get',
			data: $(document.forms[0]).serialize(),
			success: function (data) {
				var hosts_split = data.split("|");

				$('#top10-hosts').empty();

				//parse top ten bandwidth abuser hosts
				for (var y=0; y<10; y++) {
					if ((y < hosts_split.length) && (hosts_split[y] != "") && (hosts_split[y] != "no info")) {
						hostinfo = hosts_split[y].split(";");

						$('#top10-hosts').append('<tr>'+
							'<td>'+ hostinfo[0] +'</td>'+
							'<td>'+ hostinfo[1] +' <?=gettext("Bits/sec");?></td>'+
							'<td>'+ hostinfo[2] +' <?=gettext("Bits/sec");?></td>'+
						'</tr>');
					}
				}
			},
	});
}

events.push(function() {
	$('form.auto-submit').on('change', function() {
		$(this).submit();
	});

	setInterval('updateBandwidth()', 3000);

	updateBandwidth();
});
//]]>
</script>
<?php

/* link the ipsec interface magically */
if (ipsec_enabled()) {
	$ifdescrs['enc0'] = gettext("IPsec");
}

?>
<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext("Traffic Graph");?></h2>
	</div>
	<div class="panel-body">
		<div class="col-sm-6">
			<div id="traffic-chart-<?=$curif?>" class="d3-chart traffic-widget-chart">
				<svg></svg>
			</div>
		</div>
		<div class="col-sm-6">
			<table class="table table-striped table-condensed">
				<thead>
					<tr>
						<th><?=(($curhostipformat == "") ? gettext("Host IP") : gettext("Host Name or IP")); ?></th>
						<th><?=gettext("Bandwidth In"); ?></th>
						<th><?=gettext("Bandwidth Out"); ?></th>
					</tr>
				</thead>
				<tbody id="top10-hosts">
					<!-- to be added by javascript -->
				</tbody>
			</table>
		</div>
	</div>
</div>
<?php include("foot.inc");
