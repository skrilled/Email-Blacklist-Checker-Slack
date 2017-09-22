<?php

// url to slack webhook
$slack_url = 'https://hooks.slack.com/services/...'; 

// ip ranges to check in cidr format
$ipRanges = [
	'10.0.0.0/24',
	'192.168.0.0/24'
];

// name of blacklist -> dnsbl location to check against
$dnsbls = [
	"uceprotect-lvl1" => "dnsbl-1.uceprotect.net",
	"uceprotect-lvl2" => "dnsbl-2.uceprotect.net",
	"uceprotect-lvl3" => "dnsbl-3.uceprotect.net",
	"dronebl"         => "dnsbl.dronebl.org",
	"sorbs"           => "dnsbl.sorbs.net",
	"spamhaus-zen"    => "zen.spamhaus.org",
	"spamcop"         => "bl.spamcop.net",
	"dnsbl"           => "list.dsbl.org",
	"spamhaus-sbl"    => "sbl.spamhaus.org",
	"spamhaus-xbl"    => "xbl.spamhaus.org"
];

/* end configuration values */

foreach($ipRanges as $cidr) {
	$blacklisted = [];
	// convert cidr to array of IP addresses
	$actualRange = range_to_ips(cidr_to_range($cidr));
	// run through those IPs
	foreach($actualRange as $ipaddr) {
		$result = check_ip($ipaddr);
		if($result !== false) {
			$blacklisted[$ipaddr] = $result;
		}
	}
	if(count($blacklisted)==0) {
		$messageData = [
			'attachments' => array([
				'color'   => '#42f44e',
				'title'   => 'No IPs in '.$cidr.' are Blacklisted',
				'text' => 'Great news! None of the IPs in the '.$cidr.' range are blacklisted.'
			])
		];
	} else {
		$blacklistedMessage = "";
		
		foreach($blacklisted as $blacklistedIP => $lists) {
			$blacklistedMessage.= $blacklistedIP . " is on the following blacklists: ".implode($lists, ",");
		}
		
		$messageData = [
			'attachments' => array([
				'color'   => '#f44e42',
				'title'   => 'IPs in '.$cidr.' are Blacklisted!',
				'text' => "The world as we know it is crashing before our very eyes!\n\n".$blacklistedMessage
			])
		];
	}
	
	$data_string = json_encode($messageData);
	
	$ch = curl_init($slack_url);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
	curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array(
		'Content-Type: application/json',
		'Content-Length: ' . strlen($data_string))
	);
	$result = curl_exec($ch);
}

function check_ip($ip) {
	global $dnsbls;	
	$reverse_ip = implode(".", array_reverse(explode(".", $ip)));
	$listedOn = [];
	foreach ($dnsbls as $k=>$host) {
		if (checkdnsrr($reverse_ip . "." . $host . ".", "A")) {
			$listedOn[] = $k;
		}
	}	
	return count($listedOn)>0 ? $listedOn : false;
}

function cidr_to_range($cidr)
{
    $ip_arr = explode('/', $cidr);
    $start = ip2long($ip_arr[0]);
    $nm = $ip_arr[1];
    $num = pow(2, 32 - $nm);
    $end = $start + $num - 1;
    return array($ip_arr[0], long2ip($end));
}


function range_to_ips($range) {
    $ips = array();
    $start = ip2long($range[0]);
    $stop  = ip2long($range[1]);
    for ($ip = $start; $ip <= $stop; $ip++) {	
        if(in_array(explode(".", long2ip($ip))[3], [0,1,255,254])) continue; // not useable IPs so don't include these..
        $ips[] = long2ip($ip);		
    }
    return $ips;
}
