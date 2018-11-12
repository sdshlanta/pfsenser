<?php
/*
 * services_dyndns.php
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
##|*IDENT=page-services-dynamicdnsclients
##|*NAME=Services: Dynamic DNS clients
##|*DESCR=Allow access to the 'Services: Dynamic DNS clients' page.
##|*MATCH=services_dyndns.php*
##|-PRIV

require_once("guiconfig.inc");

if (!is_array($config['dyndnses']['dyndns'])) {
	$config['dyndnses']['dyndns'] = array();
}

$a_dyndns = &$config['dyndnses']['dyndns'];
global $dyndns_split_domain_types;

if ($_GET['act'] == "del") {
	$conf = $a_dyndns[$_GET['id']];
	if (in_array($conf['type'], $dyndns_split_domain_types)) {
		$hostname = $conf['host'] . "." . $conf['domainname'];
	} else {
		$hostname = $conf['host'];
	}
	@unlink("{$g['conf_path']}/dyndns_{$conf['interface']}{$conf['type']}" . escapeshellarg($hostname) . "{$conf['id']}.cache");
	unset($a_dyndns[$_GET['id']]);

	write_config();
	services_dyndns_configure();

	header("Location: services_dyndns.php");
	exit;
} else if ($_GET['act'] == "toggle") {
	if ($a_dyndns[$_GET['id']]) {
		if (isset($a_dyndns[$_GET['id']]['enable'])) {
			unset($a_dyndns[$_GET['id']]['enable']);
		} else {
			$a_dyndns[$_GET['id']]['enable'] = true;
		}
		write_config();
		services_dyndns_configure();

		header("Location: services_dyndns.php");
		exit;
	}
}
$pgtitle = array(gettext("Services"), gettext("Dynamic DNS"), gettext("Dynamic DNS Clients"));
$pglinks = array("", "@self", "@self");
include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}

$tab_array = array();
$tab_array[] = array(gettext("Dynamic DNS Clients"), true, "services_dyndns.php");
$tab_array[] = array(gettext("RFC 2136 Clients"), false, "services_rfc2136.php");
$tab_array[] = array(gettext("Check IP Services"), false, "services_checkip.php");
display_top_tabs($tab_array);
?>
<form action="services_dyndns.php" method="post" name="iform" id="iform">
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Dynamic DNS Clients')?></h2></div>
		<div class="panel-body">
			<div class="table-responsive">
				<table class="table table-striped table-hover table-condensed table-rowdblclickedit">
					<thead>
						<tr>
							<th><?=gettext("Interface")?></th>
							<th><?=gettext("Service")?></th>
							<th><?=gettext("Hostname")?></th>
							<th><?=gettext("Cached IP")?></th>
							<th><?=gettext("Description")?></th>
							<th><?=gettext("Actions")?></th>
						</tr>
					</thead>
					<tbody>
<?php
$i = 0;
foreach ($a_dyndns as $dyndns):
	if (in_array($dyndns['type'], $dyndns_split_domain_types)) {
		$hostname = $dyndns['host'] . "." . $dyndns['domainname'];
	} else {
		$hostname = $dyndns['host'];
	}
?>
						<tr<?=!isset($dyndns['enable'])?' class="disabled"':''?>>
							<td>
<?php
	$iflist = get_configured_interface_with_descr();
	foreach ($iflist as $if => $ifdesc) {
		if ($dyndns['interface'] == $if) {
			print($ifdesc);

			break;
		}
	}

	$groupslist = return_gateway_groups_array();
	foreach ($groupslist as $if => $group) {
		if ($dyndns['interface'] == $if) {
			print($if);
			break;
		}
	}
?>
							</td>
							<td>
<?php
	$types = explode(",", DYNDNS_PROVIDER_DESCRIPTIONS);
	$vals = explode(" ", DYNDNS_PROVIDER_VALUES);

	for ($j = 0; $j < count($vals); $j++) {
		if ($vals[$j] == $dyndns['type']) {
			print(htmlspecialchars($types[$j]));

			break;
		}
	}
?>
							</td>
							<td>
<?php
	print(insert_word_breaks_in_domain_name(htmlspecialchars($hostname)));
?>
							</td>
							<td>
<?php
	$filename = "{$g['conf_path']}/dyndns_{$dyndns['interface']}{$dyndns['type']}" . escapeshellarg($hostname) . "{$dyndns['id']}.cache";
	$filename_v6 = "{$g['conf_path']}/dyndns_{$dyndns['interface']}{$dyndns['type']}" . escapeshellarg($hostname) . "{$dyndns['id']}_v6.cache";
	if (file_exists($filename)) {
		$ipaddr = dyndnsCheckIP($dyndns['interface']);
		$cached_ip_s = explode("|", file_get_contents($filename));
		$cached_ip = $cached_ip_s[0];

		if ($ipaddr != $cached_ip) {
			print('<span class="text-danger">');
		} else {
			print('<span class="text-success">');
		}

		print(htmlspecialchars($cached_ip));
		print('</span>');
	} else if (file_exists($filename_v6)) {
		$ipv6addr = get_interface_ipv6($dyndns['interface']);
		$cached_ipv6_s = explode("|", file_get_contents($filename_v6));
		$cached_ipv6 = $cached_ipv6_s[0];

		if ($ipv6addr != $cached_ipv6) {
			print('<span class="text-danger">');
		} else {
			print('<span class="text-success">');
		}

		print(htmlspecialchars($cached_ipv6));
		print('</span>');
	} else {
		print('N/A');
	}
?>
							</td>
							<td>
<?php
	print(htmlspecialchars($dyndns['descr']));
?>
							</td>
							<td>
								<a class="fa fa-pencil" title="<?=gettext('Edit service')?>" href="services_dyndns_edit.php?id=<?=$i?>"></a>
<?php if (isset($dyndns['enable'])) {
?>
								<a class="fa fa-ban" title="<?=gettext('Disable service')?>" href="?act=toggle&amp;id=<?=$i?>"></a>
<?php } else {
?>
								<a class="fa fa-check-square-o" title="<?=gettext('Enable service')?>" href="?act=toggle&amp;id=<?=$i?>"></a>
<?php }
?>
								<a class="fa fa-trash" title="<?=gettext('Delete service')?>"	href="services_dyndns.php?act=del&amp;id=<?=$i?>"></a>
							</td>
						</tr>
<?php
	$i++;
	endforeach;
?>
					</tbody>
			  </table>
			</div>
		</div>
	</div>
</form>

<nav class="action-buttons">
	<a href="services_dyndns_edit.php" class="btn btn-sm btn-success btn-sm">
		<i class="fa fa-plus icon-embed-btn"></i>
		<?=gettext('Add')?>
	</a>
</nav>

<div>
	<?=gettext('IP addresses appearing in <span class="text-success">green</span> are up to date with Dynamic DNS provider. ')?>
	<?=gettext('An update for an IP address can be forced on the edit page for that service.')?>
</div>

<?php
include("foot.inc");
