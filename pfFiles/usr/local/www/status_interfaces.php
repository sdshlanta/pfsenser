<?php
/*
 * status_interfaces.php
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
##|*IDENT=page-status-interfaces
##|*NAME=Status: Interfaces
##|*DESCR=Allow access to the 'Status: Interfaces' page.
##|*MATCH=status_interfaces.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("shaper.inc");
require_once("filter.inc");

if ($_POST['ifdescr'] && $_POST['submit']) {
	$interface = $_POST['ifdescr'];
	if ($_POST['status'] == "up") {
		if ($_POST['relinquish_lease']) {
			dhcp_relinquish_lease($_POST['if'], $_POST['ifdescr'], $_POST['ipv']);
		}
		interface_bring_down($interface);
	} else {
		interface_configure($interface);
	}
	header("Location: status_interfaces.php");
	exit;
}

$formtemplate = '<form name="%s" action="status_interfaces.php" method="post">' .
					'<input type="hidden" name="ifdescr" value="%s" />' .
					'<input type="hidden" name="status" value="%s" />' .
					'%s' .
					'<button type="submit" name="submit" class="btn btn-warning btn-xs" value="%s">' .
					'<i class="fa fa-refresh icon-embed-btn"></i>' .
					'%s' .
					'</button>' .
					'%s' .
					'</form>';

// Display a term/definition pair
function showDef($show, $term, $def) {
	if ($show) {
		print('<dt>' . $term . '</dt>');
		print('<dd>' . htmlspecialchars($def) . '</dd>');
	}
}

// Display a term/definition pair with a button
function showDefBtn($show, $term, $def, $ifdescr, $btnlbl, $chkbox_relinquish_lease) {
	global $formtemplate;

	if ($show) {
		print('<dt>' . $term . '</dt>');
		print('<dd>');
		printf($formtemplate, $term, $ifdescr, $show, htmlspecialchars($def)	. ' ', $btnlbl, $btnlbl, $chkbox_relinquish_lease);
		print('</dd>');
	}
}

// Relinquish the DHCP lease from the server.
function dhcp_relinquish_lease($if, $ifdescr, $ipv) {
	$leases_db = '/var/db/dhclient.leases.' . $if;
	$conf_file = '/var/etc/dhclient_'.$ifdescr.'.conf';
	$script_file = '/sbin/dhclient-script';

	if (file_exists($leases_db) && file_exists($script_file)) {
		mwexec('/usr/local/sbin/dhclient -'.$ipv.' -d -r -lf '.$leases_db.' -cf '.$conf_file.' -sf '.$script_file);
	}
}

$pgtitle = array(gettext("Status"), gettext("Interfaces"));
$shortcut_section = "interfaces";
include("head.inc");

$ifdescrs = get_configured_interface_with_descr(false, true);

foreach ($ifdescrs as $ifdescr => $ifname):
	$ifinfo = get_interface_info($ifdescr);
	$mac_man = load_mac_manufacturer_table();

	$chkbox_relinquish_lease = 	'&nbsp;&nbsp;&nbsp;' .
								'<input type="checkbox" name="relinquish_lease" value="true" title="' . gettext("Send a gratuitous DHCP release packet to the server.") . '" /> ' . gettext("Relinquish Lease") .
								'<input type="hidden" name="if" value='.$ifinfo['if'].' />';
	$chkbox_relinquish_lease_v4 = $chkbox_relinquish_lease . '<input type="hidden" name="ipv" value=4 />';
	$chkbox_relinquish_lease_v6 = $chkbox_relinquish_lease . '<input type="hidden" name="ipv" value=6 />';
?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars($ifname)?><?=gettext(" Interface "); ?>(<?=htmlspecialchars($ifdescr)?>, <?=htmlspecialchars($ifinfo['hwif'])?>)</h2></div>
	<div class="panel-body">
		<dl class="dl-horizontal">
<?php
		showDef(true, gettext("Status"), $ifinfo['status']);
		showDefBtn($ifinfo['dhcplink'], 'DHCP', $ifinfo['dhcplink'], $ifdescr, $ifinfo['dhcplink'] == "up" ? gettext("Release") : gettext("Renew"), $ifinfo['dhcplink'] == "up" ? $chkbox_relinquish_lease_v4 : '');
		showDefBtn($ifinfo['dhcp6link'], 'DHCP6', $ifinfo['dhcp6link'], $ifdescr, $ifinfo['dhcp6link'] == "up" ? gettext("Release") : gettext("Renew"), $ifinfo['dhcp6link'] == "up" ? $chkbox_relinquish_lease_v6 : '');
		showDefBtn($ifinfo['pppoelink'], 'PPPoE', $ifinfo['pppoelink'], $ifdescr, $ifinfo['pppoelink'] == "up" ? gettext("Disconnect") : gettext("Connect"), '');
		showDefBtn($ifinfo['pptplink'], 'PPTP', $ifinfo['pptplink'], $ifdescr, $ifinfo['pptplink'] == "up" ? gettext("Disconnect") : gettext("Connect"), '');
		showDefBtn($ifinfo['l2tplink'], 'L2TP', $ifinfo['l2tplink'], $ifdescr, $ifinfo['l2tplink'] == "up" ? gettext("Disconnect") : gettext("Connect"), '');
		showDefBtn($ifinfo['ppplink'], 'PPP', $ifinfo['ppplink'], $ifdescr, ($ifinfo['ppplink'] == "up" && !$ifinfo['nodevice']) ? gettext("Disconnect") : gettext("Connect"), '');
		showDef($ifinfo['ppp_uptime'] || $ifinfo['ppp_uptime_accumulated'], gettext("Uptime") . ' ' . ($ifinfo['ppp_uptime_accumulated'] ? '(historical)':''), $ifinfo['ppp_uptime'] . $ifinfo['ppp_uptime_accumulated']);
		showDef($ifinfo['cell_rssi'], gettext("Cell Signal (RSSI)"), $ifinfo['cell_rssi']);
		showDef($ifinfo['cell_mode'], gettext("Cell Mode"), $ifinfo['cell_mode']);
		showDef($ifinfo['cell_simstate'], gettext("Cell SIM State"), $ifinfo['cell_simstate']);
		showDef($ifinfo['cell_service'], gettext("Cell Service"), $ifinfo['cell_service']);
		showDef($ifinfo['cell_bwupstream'], gettext("Cell Upstream"), $ifinfo['cell_bwupstream']);
		showDef($ifinfo['cell_bwdownstream'], gettext("Cell Downstream"), $ifinfo['cell_bwdownstream']);
		showDef($ifinfo['cell_upstream'], gettext("Cell Current Up"), $ifinfo['cell_upstream']);
		showDef($ifinfo['cell_downstream'], gettext("Cell Current Down"), $ifinfo['cell_downstream']);

		if ($ifinfo['macaddr']) {
			$mac=$ifinfo['macaddr'];
			$mac_hi = strtoupper($mac[0] . $mac[1] . $mac[3] . $mac[4] . $mac[6] . $mac[7]);
			showDef( $ifinfo['macaddr'], gettext('MAC Address'), $mac . (isset($mac_man[$mac_hi]) ? ' - ' . $mac_man[$mac_hi] : ''));
		}

		if ($ifinfo['status'] != "down") {
			if ($ifinfo['dhcplink'] != "down" && $ifinfo['pppoelink'] != "down" && $ifinfo['pptplink'] != "down") {
				showDef($ifinfo['ipaddr'], gettext('IPv4 Address'), $ifinfo['ipaddr']);
				showDef($ifinfo['subnet'], gettext('Subnet mask IPv4'), $ifinfo['subnet']);
				showDef($ifinfo['gateway'], gettext('Gateway IPv4'), $ifinfo['gateway']);
				showDef($ifinfo['linklocal'], gettext('IPv6 Link Local'), $ifinfo['linklocal']);
				showDef($ifinfo['ipaddrv6'], gettext('IPv6 Address'), $ifinfo['ipaddrv6']);
				showDef($ifinfo['subnetv6'], gettext('Subnet mask IPv6'), $ifinfo['subnetv6']);
				showDef($ifinfo['gatewayv6'], gettext("Gateway IPv6"), $config['interfaces'][$ifdescr]['gatewayv6'] . " " . $ifinfo['gatewayv6']);

				if ($ifdescr == "wan" && file_exists("{$g['varetc_path']}/resolv.conf")) {
					$dns_servers = get_dns_servers();
					$dnscnt = 0;
					foreach ($dns_servers as $dns) {
						showDef(true, $dnscnt == 0 ? gettext('DNS servers'):'', $dns);
						$dnscnt++;
					}
				}
			}

			showDef($ifinfo['mtu'], gettext("MTU"), $ifinfo['mtu']);
			showDef($ifinfo['media'], gettext("Media"), $ifinfo['media']);
			showDef($ifinfo['laggproto'], gettext("LAGG Protocol"), $ifinfo['laggproto']);
			showDef($ifinfo['laggport'], gettext("LAGG Ports"), $laggport);
			showDef($ifinfo['channel'], gettext("Channel"), $ifinfo['channel']);
			showDef($ifinfo['ssid'], gettext("SSID"), $ifinfo['ssid']);
			showDef($ifinfo['bssid'], gettext("BSSID"), $ifinfo['bssid']);
			showDef($ifinfo['rate'], gettext("Rate"), $ifinfo['rate']);
			showDef($ifinfo['rssi'], gettext("RSSI"), $ifinfo['rssi']);
			showDef(true, gettext("In/out packets"),
			    $ifinfo['inpkts'] . '/' . $ifinfo['outpkts'] . " (" . format_bytes($ifinfo['inbytes']) . "/" . format_bytes($ifinfo['outbytes']) . ")");
			showDef(true, gettext("In/out packets (pass)"),
			    $ifinfo['inpktspass'] . '/' . $ifinfo['outpktspass'] . " (" . format_bytes($ifinfo['inbytespass']) . "/" . format_bytes($ifinfo['outbytespass']) . ")");
			showDef(true, gettext("In/out packets (block)"),
			    $ifinfo['inpktsblock'] . '/' . $ifinfo['outpktsblock'] . " (" . format_bytes($ifinfo['inbytesblock']) . "/" . format_bytes($ifinfo['outbytesblock']) . ")");
			showDef(isset($ifinfo['inerrs']), gettext("In/out errors"), $ifinfo['inerrs'] . "/" . $ifinfo['outerrs']);
			showDef(isset($ifinfo['collisions']), gettext("Collisions"), $ifinfo['collisions']);
		} // e-o-if ($ifinfo['status'] != "down")

		showDef($ifinfo['bridge'], gettext('Bridge (') . $ifinfo['bridgeint'] . ')', $ifinfo['bridge']);

		if (file_exists("/usr/bin/vmstat")) {
			$real_interface = "";
			$interrupt_total = "";
			$interrupt_sec = "";
			$real_interface = $ifinfo['hwif'];
			$interrupt_total = `vmstat -i | grep $real_interface | awk '{ print $3 }'`;
			$interrupt_sec = `vmstat -i | grep $real_interface | awk '{ print $4 }'`;

			if (strstr($interrupt_total, "hci")) {
				$interrupt_total = `vmstat -i | grep $real_interface | awk '{ print $4 }'`;
				$interrupt_sec = `vmstat -i | grep $real_interface | awk '{ print $5 }'`;
			}

			unset($interrupt_total);

			showDef($interrupt_total, gettext('Total interrupts'), $interrupt_total);
			showDef($interrupt_total, '', $interrupt_sec . " " . $interrupt_total);
		}
?>
		</dl>
	</div>
</div>

<?php
	endforeach;

print_info_box(gettext("Using dial-on-demand will bring the connection up again if any packet ".
	    "triggers it. To substantiate this point: disconnecting manually ".
	    "will <strong>not</strong> prevent dial-on-demand from making connections ".
	    "to the outside! Don't use dial-on-demand if the line ".
	    "is to be kept disconnected."), 'warning', false);
include("foot.inc");
?>
