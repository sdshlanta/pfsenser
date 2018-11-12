<?php
/*
 * system_information.widget.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2004-2016 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2007 Scott Dale
 * All rights reserved.
 *
 * originally part of m0n0wall (http://m0n0.ch/wall)
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

require_once("functions.inc");
require_once("guiconfig.inc");
require_once('notices.inc');
require_once('system.inc');
include_once("includes/functions.inc.php");

$sysinfo_items = array(
	'name' => gettext('Name'),
	'system' => gettext('System'),
	'bios' => gettext('BIOS'),
	'version' => gettext('Version'),
	'platform' => gettext('Platform'),
	'cpu_type' => gettext('CPU Type'),
	'hwcrypto' => gettext('Hardware Crypto'),
	'uptime' => gettext('Uptime'),
	'current_datetime' => gettext('Current Date/Time'),
	'dns_servers' => gettext('DNS Server(s)'),
	'last_config_change' => gettext('Last Config Change'),
	'state_table_size' => gettext('State Table Size'),
	'mbuf_usage' => gettext('MBUF Usage'),
	'temperature' => gettext('Temperature'),
	'load_average' => gettext('Load Average'),
	'cpu_usage' => gettext('CPU Usage'),
	'memory_usage' => gettext('Memory Usage'),
	'swap_usage' => gettext('Swap Usage'),
	'disk_usage' => gettext('Disk Usage')
	);

if ($_REQUEST['getupdatestatus']) {
	require_once("pkg-utils.inc");

	if (isset($config['system']['firmware']['disablecheck'])) {
		exit;
	}

	$system_version = get_system_pkg_version();

	if ($system_version === false) {
		print(gettext("<i>Unable to check for updates</i>"));
		exit;
	}

	if (!is_array($system_version) ||
	    !isset($system_version['version']) ||
	    !isset($system_version['installed_version'])) {
		print(gettext("<i>Error in version information</i>"));
		exit;
	}

	$version_compare = pkg_version_compare(
	    $system_version['installed_version'], $system_version['version']);

	switch ($version_compare) {
	case '<':
?>
		<div>
			<?=gettext("Version ")?>
			<span class="text-success"><?=$system_version['version']?></span> <?=gettext("is available.")?>
			<a class="fa fa-cloud-download fa-lg" href="/pkg_mgr_install.php?id=firmware"></a>
		</div>
<?php
		break;
	case '=':
		print(gettext("The system is on the latest version."));
		break;
	case '>':
		print(gettext("The system is on a later version than<br />the official release."));
		break;
	default:
		print(gettext( "<i>Error comparing installed version<br />with latest available</i>"));
		break;
	}

	exit;
} elseif ($_POST) {

	$validNames = array();

	foreach ($sysinfo_items as $sysinfo_item_key => $sysinfo_item_name) {
		array_push($validNames, $sysinfo_item_key);
	}

	if (is_array($_POST['show'])) {
		$user_settings['widgets']['system_information']['filter'] = implode(',', array_diff($validNames, $_POST['show']));
	} else {
		$user_settings['widgets']['system_information']['filter'] = implode(',', $validNames);
	}

	save_widget_settings($_SESSION['Username'], $user_settings["widgets"], gettext("Saved System Information Widget Filter via Dashboard."));
	header("Location: /index.php");
}

/*   Adding one second to the system widet update period
 *   will ensure that we update the GUI right after the stats are updated.
 */
$widgetperiod = isset($config['widgets']['period']) ? $config['widgets']['period'] * 1000 : 10000;
$widgetperiod += 1000;

$filesystems = get_mounted_filesystems();

$skipsysinfoitems = explode(",", $user_settings['widgets']['system_information']['filter']);
$rows_displayed = false;
?>

<div class="table-responsive">
<table class="table table-hover table-striped table-condensed">
	<tbody>
<?php
	if (!in_array('name', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("Name");?></th>
			<td><?php echo htmlspecialchars($config['system']['hostname'] . "." . $config['system']['domain']); ?></td>
		</tr>
<?php
	endif;
	if (!in_array('system', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("System");?></th>
			<td>
			<?php
				$platform = system_identify_specific_platform();
				if (isset($platform['descr'])) {
					echo $platform['descr'];
				} else {
					echo gettext('Unknown system');
				}
			?>
			<br />
			<?=gettext("Serial: ");?><strong><?=system_get_serial();?></strong>
<?php
		// If the uniqueID is available, display it here
		$idfile = "/var/db/uniqueid";
		if (file_exists($idfile)) {
			print("<br />" . gettext("Netgate Unique ID:") . " <strong>" . file_get_contents($idfile) . "</strong>");
		}
?>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('bios', $skipsysinfoitems)):
		$rows_displayed = true;
		unset($biosvendor);
		unset($biosversion);
		unset($biosdate);
		$_gb = exec('/bin/kenv -q smbios.bios.vendor 2>/dev/null', $biosvendor);
		$_gb = exec('/bin/kenv -q smbios.bios.version 2>/dev/null', $biosversion);
		$_gb = exec('/bin/kenv -q smbios.bios.reldate 2>/dev/null', $biosdate);
		/* Only display BIOS information if there is any to show. */
		if (!empty($biosvendor[0]) || !empty($biosversion[0]) || !empty($biosdate[0])):
?>
		<tr>
			<th><?=gettext("BIOS");?></th>
			<td>
			<?php if (!empty($biosvendor[0])): ?>
				<?=gettext("Vendor: ");?><strong><?=$biosvendor[0];?></strong><br/>
			<?php endif; ?>
			<?php if (!empty($biosversion[0])): ?>
				<?=gettext("Version: ");?><strong><?=$biosversion[0];?></strong><br/>
			<?php endif; ?>
			<?php if (!empty($biosdate[0])): ?>
				<?=gettext("Release Date: ");?><strong><?=$biosdate[0];?></strong><br/>
			<?php endif; ?>
			</td>
		</tr>
<?php
		endif;
	endif;
	if (!in_array('version', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("Version");?></th>
			<td>
				<strong><?=$g['product_version_string']?></strong>
				(<?php echo php_uname("m"); ?>)
				<br />
				<?=gettext('built on')?> <?php readfile("/etc/version.buildtime"); ?>
			<?php if (!$g['hideuname']): ?>
				<br />
				<span title="<?php echo php_uname("a"); ?>"><?php echo php_uname("s") . " " . php_uname("r"); ?></span>
			<?php endif; ?>
			<?php if (!isset($config['system']['firmware']['disablecheck'])): ?>
				<br /><br />
				<div id='updatestatus'><?php echo gettext("Obtaining update status "); ?><i class="fa fa-cog fa-spin"></i></div>
			<?php endif; ?>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('platform', $skipsysinfoitems)):
?>
		<?php if (!$g['hideplatform']): ?>
		<tr>
			<th><?=gettext("Platform");?></th>
			<td>
				<?=htmlspecialchars($g['platform']);?>
				<?php if (($g['platform'] == "nanobsd") && (file_exists("/etc/nanosize.txt"))) {
					echo " (" . htmlspecialchars(trim(file_get_contents("/etc/nanosize.txt"))) . ")";
				} ?>
			</td>
		</tr>
		<?php endif; ?>
		<?php if ($g['platform'] == "nanobsd"): ?>
			<?php
			global $SLICE, $OLDSLICE, $TOFLASH, $COMPLETE_PATH, $COMPLETE_BOOT_PATH;
			global $GLABEL_SLICE, $UFS_ID, $OLD_UFS_ID, $BOOTFLASH;
			global $BOOT_DEVICE, $REAL_BOOT_DEVICE, $BOOT_DRIVE, $ACTIVE_SLICE;
			nanobsd_detect_slice_info();
			$rw = is_writable("/") ? "(rw)" : "(ro)";
			?>
		<tr>
			<th><?=gettext("NanoBSD Boot Slice");?></th>
			<td>
				<?=htmlspecialchars(nanobsd_friendly_slice_name($BOOT_DEVICE));?> / <?=htmlspecialchars($BOOTFLASH);?><?=$rw;?>
				<?php if ($BOOTFLASH != $ACTIVE_SLICE): ?>
				<br /><br /><?=gettext('Next Boot')?>:<br />
				<?=htmlspecialchars(nanobsd_friendly_slice_name($GLABEL_SLICE));?> / <?=htmlspecialchars($ACTIVE_SLICE);?>
				<?php endif; ?>
			</td>
		</tr>
		<?php endif; ?>
<?php
	endif;
	if (!in_array('cpu_type', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("CPU Type");?></th>
			<td><?=htmlspecialchars(get_single_sysctl("hw.model"))?>
				<div id="cpufreq"><?= get_cpufreq(); ?></div>
		<?php
			$cpucount = get_cpu_count();
			if ($cpucount > 1): ?>
				<div id="cpucount">
					<?= htmlspecialchars($cpucount) ?> <?=gettext('CPUs')?>: <?= htmlspecialchars(get_cpu_count(true)); ?>
				</div>
		<?php endif; ?>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('hwcrypto', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<?php if ($hwcrypto): ?>
		<tr>
			<th><?=gettext("Hardware crypto");?></th>
			<td><?=htmlspecialchars($hwcrypto);?></td>
		</tr>
		<?php endif; ?>
<?php
	endif;
	if (!in_array('uptime', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("Uptime");?></th>
			<td id="uptime"><?= htmlspecialchars(get_uptime()); ?></td>
		</tr>
<?php
	endif;
	if (!in_array('current_datetime', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("Current date/time");?></th>
			<td><div id="datetime"><?= date("D M j G:i:s T Y"); ?></div></td>
		</tr>
<?php
	endif;
	if (!in_array('dns_servers', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("DNS server(s)");?></th>
			<td>
				<ul style="margin-bottom:0px">
				<?php
					$dns_servers = get_dns_servers();
					foreach ($dns_servers as $dns) {
						echo "<li>{$dns}</li>";
					}
				?>
				</ul>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('last_config_change', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<?php if ($config['revision']): ?>
		<tr>
			<th><?=gettext("Last config change");?></th>
			<td><?= htmlspecialchars(date("D M j G:i:s T Y", intval($config['revision']['time'])));?></td>
		</tr>
		<?php endif; ?>
<?php
	endif;
	if (!in_array('state_table_size', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("State table size");?></th>
			<td>
				<?php
					$pfstatetext = get_pfstate();
					$pfstateusage = get_pfstate(true);
				?>
				<div class="progress">
					<div id="statePB" class="progress-bar progress-bar-striped" role="progressbar" aria-valuenow="<?=$pfstateusage?>" aria-valuemin="0" aria-valuemax="100" style="width: <?=$pfstateusage?>%">
					</div>
				</div>
				<span id="pfstateusagemeter"><?=$pfstateusage?>%</span>&nbsp;<span id="pfstate">(<?= htmlspecialchars($pfstatetext)?>)</span>&nbsp;<span><a href="diag_dump_states.php"><?=gettext("Show states");?></a></span>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('mbuf_usage', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("MBUF Usage");?></th>
			<td>
				<?php
					$mbufstext = get_mbuf();
					$mbufusage = get_mbuf(true);
				?>
				<div class="progress">
					<div id="mbufPB" class="progress-bar progress-bar-striped" role="progressbar" aria-valuenow="<?=$mbufusage?>" aria-valuemin="0" aria-valuemax="100" style="width: <?=$mbufusage?>%">
					</div>
				</div>
				<span id="mbufusagemeter"><?=$mbufusage?>%</span>&nbsp;<span id="mbuf">(<?= htmlspecialchars($mbufstext)?>)</span>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('temperature', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<?php if (get_temp() != ""): ?>
		<tr>
			<th><?=gettext("Temperature");?></th>
			<td>
				<?php $temp_deg_c = get_temp(); ?>
				<div class="progress">
					<div id="tempPB" class="progress-bar progress-bar-striped" role="progressbar" aria-valuenow="<?=$temp_deg_c?>" aria-valuemin="0" aria-valuemax="100" style="width: <?=$temp_deg_c?>%">
					</div>
				</div>
				<span id="tempmeter"><?= $temp_deg_c . "&deg;C"; ?></span>
			</td>
		</tr>
		<?php endif; ?>
<?php
	endif;
	if (!in_array('load_average', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("Load average");?></th>
			<td>
				<div id="load_average" title="<?=gettext('Last 1, 5 and 15 minutes')?>"><?= get_load_average(); ?></div>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('cpu_usage', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("CPU usage");?></th>
			<td>
				<div class="progress">
					<div id="cpuPB" class="progress-bar progress-bar-striped" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="width: 0%">
					</div>
				</div>
				<?php $update_period = (!empty($config['widgets']['period'])) ? $config['widgets']['period'] : "10"; ?>
				<span id="cpumeter"><?=sprintf(gettext("Updating in %s seconds"), $update_period)?></span>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('memory_usage', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<tr>
			<th><?=gettext("Memory usage");?></th>
			<td>
				<?php $memUsage = mem_usage(); ?>

				<div class="progress" >
					<div id="memUsagePB" class="progress-bar progress-bar-striped" role="progressbar" aria-valuenow="<?=$memUsage?>" aria-valuemin="0" aria-valuemax="100" style="width: <?=$memUsage?>%">
					</div>
				</div>
				<span id="memusagemeter"><?=$memUsage?></span><span>% of <?= sprintf("%.0f", get_single_sysctl('hw.physmem') / (1024*1024)) ?> MiB</span>
			</td>
		</tr>
<?php
	endif;
	if (!in_array('swap_usage', $skipsysinfoitems)):
		$rows_displayed = true;
?>
		<?php if ($showswap == true): ?>
		<tr>
			<th><?=gettext("SWAP usage");?></th>
			<td>
				<?php $swapusage = swap_usage(); ?>
				<div class="progress">
					<div class="progress-bar progress-bar-striped" role="progressbar" aria-valuenow="<?=$swapusage?>" aria-valuemin="0" aria-valuemax="100" style="width: <?=$swapusage?>%">
					</div>
				</div>
				<span><?=$swapusage?>% of <?= sprintf("%.0f", `/usr/sbin/swapinfo -m | /usr/bin/grep -v Device | /usr/bin/awk '{ print $2;}'`) ?> MiB</span>
			</td>
		</tr>
		<?php endif; ?>

<?php
	endif;
	if (!in_array('disk_usage', $skipsysinfoitems)):
		$rows_displayed = true;
		$diskidx = 0;
		foreach ($filesystems as $fs):
?>
		<tr>
			<th><?=gettext("Disk usage");?>&nbsp;( <?=$fs['mountpoint']?> )</th>
			<td>
				<div class="progress" >
					<div id="diskspace<?=$diskidx?>" class="progress-bar progress-bar-striped" role="progressbar" aria-valuenow="<?=$fs['percent_used']?>" aria-valuemin="0" aria-valuemax="100" style="width: <?=$fs['percent_used']?>%">
					</div>
				</div>
				<span><?=$fs['percent_used']?>%<?=gettext(" of ")?><?=$fs['total_size']?>iB - <?=$fs['type'] . ("md" == substr(basename($fs['device']), 0, 2) ? " " . gettext("in RAM") : "")?></span>
			</td>
		</tr>
<?php
			$diskidx++;
		endforeach;
	endif;
	if (!$rows_displayed):
?>
		<tr>
			<td class="text-center">
				<?=gettext('All System Information items are hidden.');?>
			</td>
		</tr>
<?php
	endif;
?>

	</tbody>
</table>
</div>
<!-- close the body we're wrapped in and add a configuration-panel -->
</div><div id="widget-<?=$widgetname?>_panel-footer" class="panel-footer collapse">

<form action="/widgets/widgets/system_information.widget.php" method="post" class="form-horizontal">
    <div class="panel panel-default col-sm-10">
		<div class="panel-body">
			<div class="table responsive">
				<table class="table table-striped table-hover table-condensed">
					<thead>
						<tr>
							<th><?=gettext("Item")?></th>
							<th><?=gettext("Show")?></th>
						</tr>
					</thead>
					<tbody>
<?php
				foreach ($sysinfo_items as $sysinfo_item_key => $sysinfo_item_name):
?>
						<tr>
							<td><?=gettext($sysinfo_item_name)?></td>
							<td class="col-sm-2"><input id="show[]" name ="show[]" value="<?=$sysinfo_item_key?>" type="checkbox" <?=(!in_array($sysinfo_item_key, $skipsysinfoitems) ? 'checked':'')?>></td>
						</tr>
<?php
				endforeach;
?>
					</tbody>
				</table>
			</div>
		</div>
	</div>

	<div class="form-group">
		<div class="col-sm-offset-3 col-sm-6">
			<button type="submit" class="btn btn-primary"><i class="fa fa-save icon-embed-btn"></i><?=gettext('Save')?></button>
			<button id="showallsysinfoitems" type="button" class="btn btn-info"><i class="fa fa-undo icon-embed-btn"></i><?=gettext('All')?></button>
		</div>
	</div>
</form>

<script type="text/javascript">
//<![CDATA[
<?php if (!isset($config['system']['firmware']['disablecheck'])): ?>
function systemStatusGetUpdateStatus() {
	$.ajax({
		type: 'get',
		url: '/widgets/widgets/system_information.widget.php',
		data: 'getupdatestatus=1',
		dataFilter: function(raw){
			// We reload the entire widget, strip this block of javascript from it
			return raw.replace(/<script>([\s\S]*)<\/script>/gi, '');
		},
		dataType: 'html',
		success: function(data){
			$('#widget-system_information #updatestatus').html(data);
		}
	});
}

setTimeout('systemStatusGetUpdateStatus()', 4000);
<?php endif; ?>

function updateMeters() {
	url = '/getstats.php';

	$.ajax(url, {
		type: 'get',
		success: function(data) {
			response = data || "";
			if (response != "")
				stats(data);
		}
	});

	setTimer();

}

events.push(function(){
	set_widget_checkbox_events("#widget-<?=$widgetname?>_panel-footer [id^=show]", "showallsysinfoitems");
});

var update_interval = "<?=$widgetperiod?>";

function setProgress(barName, percent) {
	$('#' + barName).css('width', percent + '%').attr('aria-valuenow', percent);
}

function setTimer() {
	timeout = window.setTimeout('updateMeters()', update_interval);
}

function stats(x) {
	var values = x.split("|");
	if ($.each(values,function(key,value) {
		if (value == 'undefined' || value == null)
			return true;
		else
			return false;
	}))

	updateUptime(values[2]);
	updateDateTime(values[5]);
	updateCPU(values[0]);
	updateMemory(values[1]);
	updateState(values[3]);
	updateTemp(values[4]);
	updateInterfaceStats(values[6]);
	updateInterfaces(values[7]);
	updateCpuFreq(values[8]);
	updateLoadAverage(values[9]);
	updateMbuf(values[10]);
	updateMbufMeter(values[11]);
	updateStateMeter(values[12]);
}

function updateMemory(x) {
	if ($('#memusagemeter')) {
		$("#memusagemeter").html(x);
	}
	if ($('#memUsagePB')) {
		setProgress('memUsagePB', parseInt(x));
	}
}

function updateMbuf(x) {
	if ($('#mbuf')) {
		$("#mbuf").html('(' + x + ')');
	}
}

function updateMbufMeter(x) {
	if ($('#mbufusagemeter')) {
		$("#mbufusagemeter").html(x + '%');
	}
	if ($('#mbufPB')) {
		setProgress('mbufPB', parseInt(x));
	}
}

function updateCPU(x) {

	if ($('#cpumeter')) {
		$("#cpumeter").html(x + '%');
	}
	if ($('#cpuPB')) {
		setProgress('cpuPB', parseInt(x));
	}

	/* Load CPU Graph widget if enabled */
	if (widgetActive('cpu_graphs')) {
		GraphValue(graph[0], x);
	}
}

function updateTemp(x) {
	if ($("#tempmeter")) {
		$("#tempmeter").html(x + '&deg;' + 'C');
	}
	if ($('#tempPB')) {
		setProgress('tempPB', parseInt(x));
	}
}

function updateDateTime(x) {
	if ($('#datetime')) {
		$("#datetime").html(x);
	}
}

function updateUptime(x) {
	if ($('#uptime')) {
		$("#uptime").html(x);
	}
}

function updateState(x) {
	if ($('#pfstate')) {
		$("#pfstate").html('(' + x + ')');
	}
}

function updateStateMeter(x) {
	if ($('#pfstateusagemeter')) {
		$("#pfstateusagemeter").html(x + '%');
	}
	if ($('#statePB')) {
		setProgress('statePB', parseInt(x));
	}
}

function updateCpuFreq(x) {
	if ($('#cpufreq')) {
		$("#cpufreq").html(x);
	}
}

function updateLoadAverage(x) {
	if ($('#load_average')) {
		$("#load_average").html(x);
	}
}

function updateInterfaceStats(x) {
	if (widgetActive("interface_statistics")) {
		statistics_split = x.split(",");
		var counter = 1;
		for (var y=0; y<statistics_split.length-1; y++) {
			if ($('#stat' + counter)) {
				$('#stat' + counter).html(statistics_split[y]);
				counter++;
			}
		}
	}
}

function updateInterfaces(x) {
	if (widgetActive("interfaces")) {
		interfaces_split = x.split("~");
		interfaces_split.each(function(iface){
			details = iface.split("^");
			if (details[2] == '') {
				ipv4_details = '';
			} else {
				ipv4_details = details[2] + '<br />';
			}
			switch (details[1]) {
				case "up":
					$('#' + details[0] + '-up').css("display","inline");
					$('#' + details[0] + '-down').css("display","none");
					$('#' + details[0] + '-block').css("display","none");
					$('#' + details[0] + '-ip').html(ipv4_details);
					$('#' + details[0] + '-ipv6').html(details[3]);
					$('#' + details[0] + '-media').html(details[4]);
					break;
				case "down":
					$('#' + details[0] + '-down').css("display","inline");
					$('#' + details[0] + '-up').css("display","none");
					$('#' + details[0] + '-block').css("display","none");
					$('#' + details[0] + '-ip').html(ipv4_details);
					$('#' + details[0] + '-ipv6').html(details[3]);
					$('#' + details[0] + '-media').html(details[4]);
					break;
				case "block":
					$('#' + details[0] + '-block').css("display","inline");
					$('#' + details[0] + '-down').css("display","none");
					$('#' + details[0] + '-up').css("display","none");
					break;
			}
		});
	}
}

function widgetActive(x) {
	var widget = $('#' + x + '-container');
	if ((widget != null) && (widget.css('display') != null) && (widget.css('display') != "none")) {
		return true;
	} else {
		return false;
	}
}

/* start updater */
events.push(function(){
	setTimer();
});
//]]>
</script>
