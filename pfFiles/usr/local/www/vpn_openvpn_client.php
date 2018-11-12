<?php
/*
 * vpn_openvpn_client.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2004-2016 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2008 Shrew Soft Inc.
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
##|*IDENT=page-openvpn-client
##|*NAME=OpenVPN: Clients
##|*DESCR=Allow access to the 'OpenVPN: Clients' page.
##|*MATCH=vpn_openvpn_client.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("openvpn.inc");
require_once("pkg-utils.inc");

global $openvpn_topologies;

if (!is_array($config['openvpn']['openvpn-client'])) {
	$config['openvpn']['openvpn-client'] = array();
}

$a_client = &$config['openvpn']['openvpn-client'];

if (!is_array($config['ca'])) {
	$config['ca'] = array();
}

$a_ca =& $config['ca'];

if (!is_array($config['cert'])) {
	$config['cert'] = array();
}

$a_cert =& $config['cert'];

if (!is_array($config['crl'])) {
	$config['crl'] = array();
}

$a_crl =& $config['crl'];

if (is_numericint($_GET['id'])) {
	$id = $_GET['id'];
}
if (isset($_POST['id']) && is_numericint($_POST['id'])) {
	$id = $_POST['id'];
}

$act = $_GET['act'];
if (isset($_POST['act'])) {
	$act = $_POST['act'];
}

if (isset($id) && $a_client[$id]) {
	$vpnid = $a_client[$id]['vpnid'];
} else {
	$vpnid = 0;
}

if ($_GET['act'] == "del") {

	if (!isset($a_client[$id])) {
		pfSenseHeader("vpn_openvpn_client.php");
		exit;
	}
	if (!empty($a_client[$id])) {
		openvpn_delete('client', $a_client[$id]);
	}
	unset($a_client[$id]);
	write_config();
	$savemsg = gettext("Client successfully deleted.");
}

if ($_GET['act'] == "new") {
	$pconfig['autokey_enable'] = "yes";
	$pconfig['tlsauth_enable'] = "yes";
	$pconfig['autotls_enable'] = "yes";
	$pconfig['interface'] = "wan";
	$pconfig['server_port'] = 1194;
	$pconfig['verbosity_level'] = 1; // Default verbosity is 1
	// OpenVPN Defaults to SHA1
	$pconfig['digest'] = "SHA1";
}

global $simplefields;
$simplefields = array('auth_user', 'auth_pass');

if ($_GET['act'] == "edit") {

	if (isset($id) && $a_client[$id]) {
		foreach ($simplefields as $stat) {
			$pconfig[$stat] = $a_client[$id][$stat];
		}

		$pconfig['disable'] = isset($a_client[$id]['disable']);
		$pconfig['mode'] = $a_client[$id]['mode'];
		$pconfig['protocol'] = $a_client[$id]['protocol'];
		$pconfig['interface'] = $a_client[$id]['interface'];
		if (!empty($a_client[$id]['ipaddr'])) {
			$pconfig['interface'] = $pconfig['interface'] . '|' . $a_client[$id]['ipaddr'];
		}
		$pconfig['local_port'] = $a_client[$id]['local_port'];
		$pconfig['server_addr'] = $a_client[$id]['server_addr'];
		$pconfig['server_port'] = $a_client[$id]['server_port'];
		$pconfig['resolve_retry'] = $a_client[$id]['resolve_retry'];
		$pconfig['proxy_addr'] = $a_client[$id]['proxy_addr'];
		$pconfig['proxy_port'] = $a_client[$id]['proxy_port'];
		$pconfig['proxy_user'] = $a_client[$id]['proxy_user'];
		$pconfig['proxy_passwd'] = $a_client[$id]['proxy_passwd'];
		$pconfig['proxy_authtype'] = $a_client[$id]['proxy_authtype'];
		$pconfig['description'] = $a_client[$id]['description'];
		$pconfig['custom_options'] = $a_client[$id]['custom_options'];
		$pconfig['ns_cert_type'] = $a_client[$id]['ns_cert_type'];
		$pconfig['dev_mode'] = $a_client[$id]['dev_mode'];

		if ($pconfig['mode'] != "p2p_shared_key") {
			$pconfig['caref'] = $a_client[$id]['caref'];
			$pconfig['certref'] = $a_client[$id]['certref'];
			if ($a_client[$id]['tls']) {
				$pconfig['tlsauth_enable'] = "yes";
				$pconfig['tls'] = base64_decode($a_client[$id]['tls']);
			}
		} else {
			$pconfig['shared_key'] = base64_decode($a_client[$id]['shared_key']);
		}
		$pconfig['crypto'] = $a_client[$id]['crypto'];
		// OpenVPN Defaults to SHA1 if unset
		$pconfig['digest'] = !empty($a_client[$id]['digest']) ? $a_client[$id]['digest'] : "SHA1";
		$pconfig['engine'] = $a_client[$id]['engine'];

		$pconfig['tunnel_network'] = $a_client[$id]['tunnel_network'];
		$pconfig['tunnel_networkv6'] = $a_client[$id]['tunnel_networkv6'];
		$pconfig['remote_network'] = $a_client[$id]['remote_network'];
		$pconfig['remote_networkv6'] = $a_client[$id]['remote_networkv6'];
		$pconfig['use_shaper'] = $a_client[$id]['use_shaper'];
		$pconfig['compression'] = $a_client[$id]['compression'];
		$pconfig['passtos'] = $a_client[$id]['passtos'];
		$pconfig['topology'] = $a_client[$id]['topology'];

		// just in case the modes switch
		$pconfig['autokey_enable'] = "yes";
		$pconfig['autotls_enable'] = "yes";

		$pconfig['no_tun_ipv6'] = $a_client[$id]['no_tun_ipv6'];
		$pconfig['route_no_pull'] = $a_client[$id]['route_no_pull'];
		$pconfig['route_no_exec'] = $a_client[$id]['route_no_exec'];
		if (isset($a_client[$id]['verbosity_level'])) {
			$pconfig['verbosity_level'] = $a_client[$id]['verbosity_level'];
		} else {
			$pconfig['verbosity_level'] = 1; // Default verbosity is 1
		}
	}
}

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	if (isset($id) && $a_client[$id]) {
		$vpnid = $a_client[$id]['vpnid'];
	} else {
		$vpnid = 0;
	}

	list($iv_iface, $iv_ip) = explode ("|", $pconfig['interface']);
	if (is_ipaddrv4($iv_ip) && (stristr($pconfig['protocol'], "6") !== false)) {
		$input_errors[] = gettext("Protocol and IP address families do not match. An IPv6 protocol and an IPv4 IP address cannot be selected.");
	} elseif (is_ipaddrv6($iv_ip) && (stristr($pconfig['protocol'], "6") === false)) {
		$input_errors[] = gettext("Protocol and IP address families do not match. An IPv4 protocol and an IPv6 IP address cannot be selected.");
	} elseif ((stristr($pconfig['protocol'], "6") === false) && !get_interface_ip($iv_iface) && ($pconfig['interface'] != "any")) {
		// If an underlying interface to be used by this client uses DHCP, then it may not have received an IP address yet.
		// So in that case we do not report a problem.
		if (!interface_has_dhcp($iv_iface, 4)) {
			$input_errors[] = gettext("An IPv4 protocol was selected, but the selected interface has no IPv4 address.");
		}
	} elseif ((stristr($pconfig['protocol'], "6") !== false) && !get_interface_ipv6($iv_iface) && ($pconfig['interface'] != "any")) {
		// If an underlying interface to be used by this client uses DHCP6, then it may not have received an IP address yet.
		// So in that case we do not report a problem.
		if (!interface_has_dhcp($iv_iface, 6)) {
			$input_errors[] = gettext("An IPv6 protocol was selected, but the selected interface has no IPv6 address.");
		}
	}

	if ($pconfig['mode'] != "p2p_shared_key") {
		$tls_mode = true;
	} else {
		$tls_mode = false;
	}

	/* input validation */
	if ($pconfig['local_port']) {

		if ($result = openvpn_validate_port($pconfig['local_port'], 'Local port')) {
			$input_errors[] = $result;
		}

		$portused = openvpn_port_used($pconfig['protocol'], $pconfig['interface'], $pconfig['local_port'], $vpnid);
		if (($portused != $vpnid) && ($portused != 0)) {
			$input_errors[] = gettext("The specified 'Local port' is in use. Please select another value");
		}
	}

	if ($result = openvpn_validate_host($pconfig['server_addr'], 'Server host or address')) {
		$input_errors[] = $result;
	}

	if ($result = openvpn_validate_port($pconfig['server_port'], 'Server port')) {
		$input_errors[] = $result;
	}

	if (!array_key_exists($pconfig['topology'], $openvpn_topologies)) {
		$input_errors[] = gettext("The field 'Topology' contains an invalid selection");
	}

	if ($pconfig['proxy_addr']) {

		if ($result = openvpn_validate_host($pconfig['proxy_addr'], 'Proxy host or address')) {
			$input_errors[] = $result;
		}

		if ($result = openvpn_validate_port($pconfig['proxy_port'], 'Proxy port')) {
			$input_errors[] = $result;
		}

		if ($pconfig['proxy_authtype'] != "none") {
			if (empty($pconfig['proxy_user']) || empty($pconfig['proxy_passwd'])) {
				$input_errors[] = gettext("User name and password are required for proxy with authentication.");
			}

			if ($pconfig['proxy_passwd'] != $pconfig['proxy_passwd_confirm']) {
				$input_errors[] = gettext("Password and confirmation must match.");
			}
		}
	}

	if ($pconfig['tunnel_network']) {
		if ($result = openvpn_validate_cidr($pconfig['tunnel_network'], 'IPv4 Tunnel Network', false, "ipv4")) {
			$input_errors[] = $result;
		}
	}

	if ($pconfig['tunnel_networkv6']) {
		if ($result = openvpn_validate_cidr($pconfig['tunnel_networkv6'], 'IPv6 Tunnel Network', false, "ipv6")) {
			$input_errors[] = $result;
		}
	}

	if ($result = openvpn_validate_cidr($pconfig['remote_network'], 'IPv4 Remote Network', true, "ipv4")) {
		$input_errors[] = $result;
	}

	if ($result = openvpn_validate_cidr($pconfig['remote_networkv6'], 'IPv6 Remote Network', true, "ipv6")) {
		$input_errors[] = $result;
	}

	if (!empty($pconfig['use_shaper']) && (!is_numeric($pconfig['use_shaper']) || ($pconfig['use_shaper'] <= 0))) {
		$input_errors[] = gettext("The bandwidth limit must be a positive numeric value.");
	}

	if ($pconfig['autokey_enable']) {
		$pconfig['shared_key'] = openvpn_create_key();
	}

	if (!$tls_mode && !$pconfig['autokey_enable']) {
		if (!strstr($pconfig['shared_key'], "-----BEGIN OpenVPN Static key V1-----") ||
		    !strstr($pconfig['shared_key'], "-----END OpenVPN Static key V1-----")) {
			$input_errors[] = gettext("The field 'Shared Key' does not appear to be valid");
		}
	}

	if ($tls_mode && $pconfig['tlsauth_enable'] && !$pconfig['autotls_enable']) {
		if (!strstr($pconfig['tls'], "-----BEGIN OpenVPN Static key V1-----") ||
		    !strstr($pconfig['tls'], "-----END OpenVPN Static key V1-----")) {
			$input_errors[] = gettext("The field 'TLS Authentication Key' does not appear to be valid");
		}
	}

	/* If we are not in shared key mode, then we need the CA/Cert. */
	if ($pconfig['mode'] != "p2p_shared_key") {
		$reqdfields = explode(" ", "caref");
		$reqdfieldsn = array(gettext("Certificate Authority"));
	} elseif (!$pconfig['autokey_enable']) {
		/* We only need the shared key filled in if we are in shared key mode and autokey is not selected. */
		$reqdfields = array('shared_key');
		$reqdfieldsn = array(gettext('Shared key'));
	}

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if (($pconfig['mode'] != "p2p_shared_key") && empty($pconfig['certref']) && empty($pconfig['auth_user']) && empty($pconfig['auth_pass'])) {
		$input_errors[] = gettext("If no Client Certificate is selected, a username and/or password must be entered.");
	}

	if ($pconfig['auth_pass'] != $pconfig['auth_pass_confirm']) {
		$input_errors[] = gettext("Password and confirmation must match.");
	}

	if (!$input_errors) {

		$client = array();

		if (isset($id) && $a_client[$id] &&
		    $pconfig['dev_mode'] <> $a_client[$id]['dev_mode']) {
			/*
			 * delete old interface so a new TUN or TAP interface
			 * can be created.
			 */
			openvpn_delete('client', $a_client[$id]);
		}

		foreach ($simplefields as $stat) {
			if (($stat == 'auth_pass') && ($_POST[$stat] == DMYPWD)) {
				$client[$stat] = $a_client[$id]['auth_pass'];
			} else {
				update_if_changed($stat, $client[$stat], $_POST[$stat]);
			}
		}

		if ($vpnid) {
			$client['vpnid'] = $vpnid;
		} else {
			$client['vpnid'] = openvpn_vpnid_next();
		}

		if ($_POST['disable'] == "yes") {
			$client['disable'] = true;
		}
		$client['protocol'] = $pconfig['protocol'];
		$client['dev_mode'] = $pconfig['dev_mode'];
		list($client['interface'], $client['ipaddr']) = explode ("|", $pconfig['interface']);
		$client['local_port'] = $pconfig['local_port'];
		$client['server_addr'] = $pconfig['server_addr'];
		$client['server_port'] = $pconfig['server_port'];
		$client['resolve_retry'] = $pconfig['resolve_retry'];
		$client['proxy_addr'] = $pconfig['proxy_addr'];
		$client['proxy_port'] = $pconfig['proxy_port'];
		$client['proxy_authtype'] = $pconfig['proxy_authtype'];
		$client['proxy_user'] = $pconfig['proxy_user'];
		if ($pconfig['proxy_passwd'] != DMYPWD) {
			$client['proxy_passwd'] = $pconfig['proxy_passwd'];
		}
		$client['description'] = $pconfig['description'];
		$client['mode'] = $pconfig['mode'];
		$client['topology'] = $pconfig['topology'];
		$client['custom_options'] = str_replace("\r\n", "\n", $pconfig['custom_options']);

		if ($tls_mode) {
			$client['caref'] = $pconfig['caref'];
			$client['certref'] = $pconfig['certref'];
			if ($pconfig['tlsauth_enable']) {
				if ($pconfig['autotls_enable']) {
					$pconfig['tls'] = openvpn_create_key();
				}
				$client['tls'] = base64_encode($pconfig['tls']);
			}
		} else {
			$client['shared_key'] = base64_encode($pconfig['shared_key']);
		}
		$client['crypto'] = $pconfig['crypto'];
		$client['digest'] = $pconfig['digest'];
		$client['engine'] = $pconfig['engine'];

		$client['tunnel_network'] = $pconfig['tunnel_network'];
		$client['tunnel_networkv6'] = $pconfig['tunnel_networkv6'];
		$client['remote_network'] = $pconfig['remote_network'];
		$client['remote_networkv6'] = $pconfig['remote_networkv6'];
		$client['use_shaper'] = $pconfig['use_shaper'];
		$client['compression'] = $pconfig['compression'];
		$client['passtos'] = $pconfig['passtos'];

		$client['no_tun_ipv6'] = $pconfig['no_tun_ipv6'];
		$client['route_no_pull'] = $pconfig['route_no_pull'];
		$client['route_no_exec'] = $pconfig['route_no_exec'];
		$client['verbosity_level'] = $pconfig['verbosity_level'];

		if (isset($id) && $a_client[$id]) {
			$a_client[$id] = $client;
		} else {
			$a_client[] = $client;
		}

		write_config();
		openvpn_resync('client', $client);

		header("Location: vpn_openvpn_client.php");
		exit;
	}
}

$pgtitle = array(gettext("VPN"), gettext("OpenVPN"), gettext("Clients"));
$pglinks = array("", "vpn_openvpn_server.php", "vpn_openvpn_client.php");

if ($act=="new" || $act=="edit") {
	$pgtitle[] = gettext('Edit');
	$pglinks[] = "@self";
}
$shortcut_section = "openvpn";

include("head.inc");

if (!$savemsg) {
	$savemsg = "";
}

if ($input_errors) {
	print_input_errors($input_errors);
}

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

$tab_array = array();
$tab_array[] = array(gettext("Servers"), false, "vpn_openvpn_server.php");
$tab_array[] = array(gettext("Clients"), true, "vpn_openvpn_client.php");
$tab_array[] = array(gettext("Client Specific Overrides"), false, "vpn_openvpn_csc.php");
$tab_array[] = array(gettext("Wizards"), false, "wizard.php?xml=openvpn_wizard.xml");
add_package_tabs("OpenVPN", $tab_array);
display_top_tabs($tab_array);

if ($act=="new" || $act=="edit"):
	$form = new Form();

	$section = new Form_Section('General Information');

	$section->addInput(new Form_Checkbox(
		'disable',
		'Disabled',
		'Disable this client',
		$pconfig['disable']
	))->setHelp('Set this option to disable this client without removing it from the list.');

	$section->addInput(new Form_Select(
		'mode',
		'*Server mode',
		$pconfig['mode'],
		$openvpn_client_modes
		));

	$section->addInput(new Form_Select(
		'protocol',
		'*Protocol',
		$pconfig['protocol'],
		array_combine($openvpn_prots, $openvpn_prots)
		));

	$section->addInput(new Form_Select(
		'dev_mode',
		'*Device mode',
		empty($pconfig['dev_mode']) ? 'tun':$pconfig['dev_mode'],
		array_combine($openvpn_dev_mode, $openvpn_dev_mode)
		));

	$section->addInput(new Form_Select(
		'interface',
		'*Interface',
		$pconfig['interface'],
		openvpn_build_if_list()
		));

	$section->addInput(new Form_Input(
		'local_port',
		'Local port',
		'number',
		$pconfig['local_port'],
		['min' => '0']
	))->setHelp('Set this option to bind to a specific port. Leave this blank or enter 0 for a random dynamic port.');

	$section->addInput(new Form_Input(
		'server_addr',
		'*Server host or address',
		'text',
		$pconfig['server_addr']
	));

	$section->addInput(new Form_Input(
		'server_port',
		'*Server port',
		'number',
		$pconfig['server_port']
	));

	$section->addInput(new Form_Input(
		'proxy_addr',
		'Proxy host or address',
		'text',
		$pconfig['proxy_addr']
	));

	$section->addInput(new Form_Input(
		'proxy_port',
		'Proxy port',
		number,
		$pconfig['proxy_port']
	));

	$section->addInput(new Form_Select(
		'proxy_authtype',
		'Proxy Auth. - Extra options',
		$pconfig['proxy_authtype'],
		array('none' => gettext('none'), 'basic' => gettext('basic'), 'ntlm' => gettext('ntlm'))
		));

	$section->addInput(new Form_Input(
		'proxy_user',
		'Username',
		'text',
		$pconfig['proxy_user']
	));

	$section->addPassword(new Form_Input(
		'proxy_passwd',
		'Password',
		'password',
		$pconfig['proxy_passwd']
	));

	$section->addInput(new Form_Checkbox(
		'resolve_retry',
		'Server hostname resolution',
		'Infinitely resolve server ',
		$pconfig['resolve_retry']
	))->setHelp('Continuously attempt to resolve the server host name. ' .
				'Useful when communicating with a server that is not permanently connected to the Internet.');

	$section->addInput(new Form_Input(
		'description',
		'Description',
		'text',
		$pconfig['description']
	))->setHelp('A description may be entered here for administrative reference (not parsed).');

	$form->add($section);
	$section = new Form_Section('User Authentication Settings');
	$section->addClass('authentication');

	$section->addInput(new Form_Input(
		'auth_user',
		'Username',
		'text',
		$pconfig['auth_user']
	))->setHelp('Leave empty when no user name is needed');

	$section->addPassword(new Form_Input(
		'auth_pass',
		'Password',
		'password',
		$pconfig['auth_pass']
	))->setHelp('Leave empty when no password is needed');

	$form->add($section);

	$section = new Form_Section('Cryptographic Settings');

	$section->addInput(new Form_Checkbox(
		'tlsauth_enable',
		'TLS authentication',
		'Enable authentication of TLS packets.',
		$pconfig['tlsauth_enable']
	));

	if (!$pconfig['tls']) {
		$section->addInput(new Form_Checkbox(
			'autotls_enable',
			null,
			'Automatically generate a shared TLS authentication key.',
			$pconfig['autotls_enable']
		));
	}

	$section->addInput(new Form_Textarea(
		'tls',
		'*Key',
		$pconfig['tls']
	))->setHelp('Paste the shared key here');

	if (count($a_ca)) {
		$list = array();
		foreach ($a_ca as $ca) {
			$list[$ca['refid']] = $ca['descr'];
		}

		$section->addInput(new Form_Select(
			'caref',
			'*Peer Certificate Authority',
			$pconfig['caref'],
			$list
		));
	} else {
		$section->addInput(new Form_StaticText(
			'*Peer Certificate Authority',
			sprintf('No Certificate Authorities defined. One may be created here: %s', '<a href="system_camanager.php">System &gt; Cert. Manager</a>')
		));
	}

	if (count($a_crl)) {
		$section->addInput(new Form_Select(
			'crlref',
			'Peer Certificate Revocation list',
			$pconfig['crlref'],
			openvpn_build_crl_list()
		));
	} else {
		$section->addInput(new Form_StaticText(
			'Peer Certificate Revocation list',
			sprintf('No Certificate Revocation Lists defined. One may be created here: %s', '<a href="system_crlmanager.php">System &gt; Cert. Manager &gt; Certificate Revocation</a>')
		));
	}

	$section->addInput(new Form_Checkbox(
		'autokey_enable',
		'Auto generate',
		'Automatically generate a shared key',
		$pconfig['autokey_enable'] && empty($pconfig['shared_key'])
	));

	$section->addInput(new Form_Textarea(
		'shared_key',
		'*Shared Key',
		$pconfig['shared_key']
	))->setHelp('Paste the shared key here');

	$cl = openvpn_build_cert_list(true);

	$section->addInput(new Form_Select(
		'certref',
		'Client Certificate',
		$pconfig['certref'],
		$cl['server']
		));

	$section->addInput(new Form_Select(
		'crypto',
		'*Encryption Algorithm',
		$pconfig['crypto'],
		openvpn_get_cipherlist()
		));

	$section->addInput(new Form_Select(
		'digest',
		'*Auth digest algorithm',
		$pconfig['digest'],
		openvpn_get_digestlist()
		))->setHelp('Leave this set to SHA1 unless all clients are set to match. SHA1 is the default for OpenVPN. ');

	$section->addInput(new Form_Select(
		'engine',
		'Hardware Crypto',
		$pconfig['engine'],
		openvpn_get_engines()
		));

	$form->add($section);

	$section = new Form_Section('Tunnel Settings');

	$section->addInput(new Form_Input(
		'tunnel_network',
		'IPv4 Tunnel Network',
		'text',
		$pconfig['tunnel_network']
	))->setHelp('This is the IPv4 virtual network used for private communications between this client and the server ' .
				'expressed using CIDR (e.g. 10.0.8.0/24). The second network address will be assigned to ' .
				'the client virtual interface.');

	$section->addInput(new Form_Input(
		'tunnel_networkv6',
		'IPv6 Tunnel Network',
		'text',
		$pconfig['tunnel_networkv6']
	))->setHelp('This is the IPv6 virtual network used for private ' .
				'communications between this client and the server expressed using CIDR (e.g. fe80::/64). ' .
				'The second network address will be assigned to the client virtual interface.');

	$section->addInput(new Form_Input(
		'remote_network',
		'IPv4 Remote network(s)',
		'text',
		$pconfig['remote_network']
	))->setHelp('IPv4 networks that will be routed through the tunnel, so that a site-to-site VPN can be established without manually ' .
				'changing the routing tables. Expressed as a comma-separated list of one or more CIDR ranges. ' .
				'If this is a site-to-site VPN, enter the remote LAN/s here. May be left blank for non site-to-site VPN.');

	$section->addInput(new Form_Input(
		'remote_networkv6',
		'IPv6 Remote network(s)',
		'text',
		$pconfig['remote_networkv6']
	))->setHelp('These are the IPv6 networks that will be routed through the tunnel, so that a site-to-site VPN can be established without manually ' .
				'changing the routing tables. Expressed as a comma-separated list of one or more IP/PREFIX. ' .
				'If this is a site-to-site VPN, enter the remote LAN/s here. May be left blank for non site-to-site VPN.');

	$section->addInput(new Form_Input(
		'use_shaper',
		'Limit outgoing bandwidth',
		'number',
		$pconfig['use_shaper'],
		['min' => 100, 'max' => 100000000, 'placeholder' => 'Between 100 and 100,000,000 bytes/sec']
	))->setHelp('Maximum outgoing bandwidth for this tunnel. Leave empty for no limit. The input value has to be something between 100 bytes/sec and 100 Mbytes/sec (entered as bytes per second).');

	$section->addInput(new Form_Select(
		'compression',
		'Compression',
		$pconfig['compression'],
		$openvpn_compression_modes
		))->setHelp('Compress tunnel packets using the LZO algorithm. Adaptive compression will dynamically disable compression for a period of time if OpenVPN detects that the data in the packets is not being compressed efficiently.');

	$section->addInput(new Form_Select(
		'topology',
		'Topology',
		$pconfig['topology'],
		$openvpn_topologies
	))->setHelp('Specifies the method used to configure a virtual adapter IP address.');

	$section->addInput(new Form_Checkbox(
		'passtos',
		'Type-of-Service',
		'Set the TOS IP header value of tunnel packets to match the encapsulated packet value.',
		$pconfig['passtos']
	));

	$section->addInput(new Form_Checkbox(
		'no_tun_ipv6',
		'Disable IPv6',
		'Don\'t forward IPv6 traffic. ',
		$pconfig['no_tun_ipv6']
	));

	$section->addInput(new Form_Checkbox(
		'route_no_pull',
		'Don\'t pull routes',
		'Bars the server from adding routes to the client\'s routing table',
		$pconfig['route_no_pull']
	))->setHelp('This option still allows the server to set the TCP/IP properties of the client\'s TUN/TAP interface. ');

	$section->addInput(new Form_Checkbox(
		'route_no_exec',
		'Don\'t add/remove routes',
		'Don\'t add or remove routes automatically',
		$pconfig['route_no_exec']
	))->setHelp('Pass routes to --route-upscript using environmental variables.');

	$form->add($section);

	$section = new Form_Section('Advanced Configuration');
	$section->addClass('advanced');

	$section->addInput(new Form_Textarea(
		'custom_options',
		'Custom options',
		$pconfig['custom_options']
	))->setHelp('Enter any additional options to add to the OpenVPN client configuration here, separated by semicolon.');

	$section->addInput(new Form_Select(
		'verbosity_level',
		'Verbosity level',
		$pconfig['verbosity_level'],
		$openvpn_verbosity_level
		))->setHelp('Each level shows all info from the previous levels. Level 3 is recommended for a good summary of what\'s happening without being swamped by output.' . '<br /><br />' .
					'None: Only fatal errors' . '<br />' .
					'Default through 4: Normal usage range' . '<br />' .
					'5: Output R and W characters to the console for each packet read and write. Uppercase is used for TCP/UDP packets and lowercase is used for TUN/TAP packets.' .'<br />' .
					'6-11: Debug info range');

	$section->addInput(new Form_Input(
		'act',
		null,
		'hidden',
		$act
	));

	if (isset($id) && $a_client[$id]) {
		$section->addInput(new Form_Input(
			'id',
			null,
			'hidden',
			$id
		));
	}

	$form->add($section);
	print($form);
else:
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('OpenVPN Clients')?></h2></div>
		<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th><?=gettext("Protocol")?></th>
					<th><?=gettext("Server")?></th>
					<th><?=gettext("Description")?></th>
					<th><?=gettext("Actions")?></th>
				</tr>
			</thead>

			<tbody>
<?php
	$i = 0;
	foreach ($a_client as $client):
		$server = "{$client['server_addr']}:{$client['server_port']}";
?>
				<tr <?=isset($client['disable']) ? 'class="disabled"':''?>>
					<td>
						<?=htmlspecialchars($client['protocol'])?>
					</td>
					<td>
						<?=htmlspecialchars($server)?>
					</td>
					<td>
						<?=htmlspecialchars($client['description'])?>
					</td>
					<td>
						<a class="fa fa-pencil"	title="<?=gettext('Edit client')?>"	href="vpn_openvpn_client.php?act=edit&amp;id=<?=$i?>"></a>
						<a class="fa fa-trash"	title="<?=gettext('Delete client')?>" href="vpn_openvpn_client.php?act=del&amp;id=<?=$i?>"></a>
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

<nav class="action-buttons">
	<a href="vpn_openvpn_client.php?act=new" class="btn btn-sm btn-success">
		<i class="fa fa-plus icon-embed-btn"></i>
		<?=gettext("Add")?>
	</a>
</nav>

<?php
endif;

// Note:
// The following *_change() functions were converted from Javascript/DOM to JQuery but otherwise
// mostly left unchanged. The logic on this form is complex and this works!
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	function mode_change() {
		switch ($('#mode').val()) {
			case "p2p_tls":
				hideCheckbox('tlsauth_enable', false);
				hideInput('caref', false);
				hideInput('certref', false);
				hideClass('authentication', false);
				hideCheckbox('autokey_enable', true);
				hideInput('shared_key', true);
				hideLabel('Peer Certificate Revocation list', true);
				hideInput('topology', false);
				break;
			case "p2p_shared_key":
				hideCheckbox('tlsauth_enable', true);
				hideInput('caref', true);
				hideInput('certref', true);
				hideClass('authentication', true);
				hideCheckbox('autokey_enable', false);
				hideInput('shared_key', false);
				hideLabel('Peer Certificate Revocation list', false);
				hideInput('topology', true);
				break;
		}

		tlsauth_change();
		autokey_change();
		dev_mode_change();

	}

	function dev_mode_change() {
		hideCheckbox('no_tun_ipv6', ($('#dev_mode').val() == 'tap'));
		hideInput('topology',  ($('#dev_mode').val() == 'tap') || $('#mode').val() == "p2p_shared_key");
	}

	// Process "Automatically generate a shared key" checkbox
	function autokey_change() {
		hideInput('shared_key', $('#autokey_enable').prop('checked'));
	}

	function useproxy_changed() {
		hideInput('proxy_user', ($('#proxy_authtype').val() == 'none'));
		hideInput('proxy_passwd', ($('#proxy_authtype').val() == 'none'));
	}

	// Process "Enable authentication of TLS packets" checkbox
	function tlsauth_change() {
		hideCheckbox('autotls_enable', !($('#tlsauth_enable').prop('checked'))  || ($('#mode').val() == 'p2p_shared_key'));
		autotls_change();
	}

	// Process "Automatically generate a shared TLS authentication key" checkbox
	function autotls_change() {
		hideInput('tls', $('#autotls_enable').prop('checked') || !$('#tlsauth_enable').prop('checked'));
	}

	// ---------- Monitor elements for change and call the appropriate display functions ------------------------------

	 // TLS Authorization
	$('#tlsauth_enable').click(function () {
		tlsauth_change();
	});

	 // Auto key
	$('#autokey_enable').click(function () {
		autokey_change();
	});

	 // Mode
	$('#mode').change(function () {
		mode_change();
	});

	 // Use proxy
	$('#proxy_authtype').change(function () {
		useproxy_changed();
	});

	 // Tun/tap
	$('#dev_mode').change(function () {
		dev_mode_change();
	});

	 // Auto TLS
	$('#autotls_enable').click(function () {
		autotls_change();
	});

	// ---------- Set initial page display state ----------------------------------------------------------------------
	mode_change();
	autokey_change();
	tlsauth_change();
	useproxy_changed();
});
//]]>
</script>

<?php include("foot.inc");
