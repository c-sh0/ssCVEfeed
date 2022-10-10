<?php
/*
* -------------------------------------------------------------
* Super Simple CVE Feed
* -------------------------------------------------------------
*
* References:
* * https://nvd.nist.gov/developers/vulnerabilities
*
* [/csh:]> date "+%D"
* 10/08/22
-------------------------------------------------------------
*/
include 'header.inc';
// note: php.ini - date.timezone
$lDateTime = date("D F j, Y, g:i:sa (T)");
$nvdApi = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
$tsFile = '/tmp/cve-feed-last_reload.ts';
$pName  = basename(__FILE__);
$ePoch  = null;
$sslOptions=array(
    "ssl"=>array(
        "verify_peer"=>false,
        "verify_peer_name"=>false,
    ),
);

function do_epoch($f, $m) {
        $ts = time();
        $fd = fopen($f, $m) or die("Unable to open file!");

        switch($m) {
	   case $m == 'w':
        	fwrite($fd, $ts);
           break;
	   case $m == 'r':
		$ts = fgets($fd);
           break;
	}
	fclose($fd);

  return($ts);
}

function mk_dt($ep, $offset) {
        $ep += $offset;
        $dt = date("Y-m-d\TH:i:s",$ep);

  return($dt);
}

// main
if(!file_exists($tsFile)) {
	$ePoch = do_epoch($tsFile,'w');
}

if(isset($_POST['done']) && $_POST['done'] == 'done') {
          do_epoch($tsFile,'w');
          print("<script>document.location.href='';</script>");
}

$ePoch = do_epoch($tsFile,'r');
$sDate = mk_dt($ePoch,0);
$eDate = mk_dt(time(),0);
$url   = "$nvdApi/?pubStartDate=$sDate&pubEndDate=$eDate";

print("$lDateTime<br><br>
	<b>CVE Feed</b><br>
	<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"$url\">$url</a>
	<hr>
	<form action=\"$pName\" method=\"POST\">
		<input type=\"submit\" value=\" Refresh \">
	</form>");

$json   = file_get_contents($url, false, stream_context_create($sslOptions));
$jsnObj = json_decode($json, TRUE);

if($jsnObj['totalResults'] > 0) {
	printf("Count: %s<br>",$jsnObj['totalResults']);

	print("<center>");
	foreach($jsnObj['vulnerabilities'] as $vuln) {
                $cvssv3  = '';
		$cveId   = $vuln['cve']['id'];
		$cveDesc = $vuln['cve']['descriptions'][0]['value'];

                if(is_array($vuln['cve']['metrics'])) {
			if(isset($vuln['cve']['metrics']['cvssMetricV31'][0])) {
				$cvssv3 = $vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'];
			} else {
				$cvssv3 = $vuln['cve']['vulnStatus'];
			}
                }
		print("<table>
				<tr>
				<th><a target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://nvd.nist.gov/vuln/detail/$cveId\">$cveId</a></th>
				<td>CVSSv3: $cvssv3</td>
				</tr>
			</table>
			<table>
				<tr>
				<td>$cveDesc</td>
				</tr>
			</table>
			<table>
				<tr>
				<td><hr></td>
				</tr>
			</table>
			<br>");

	}

	print("<br>
		<form action=\"$pName\" method=\"POST\">
		<input type=\"hidden\" name=\"done\" value=\"done\">
		<input type=\"submit\" value=\" DONE \">
		</form>
		<br>
		<br>");

	print("</center>");

} else {
	print("Count: 0<br>");
}

include 'footer.inc';
?>

