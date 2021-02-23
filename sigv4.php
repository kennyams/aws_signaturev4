<?php
	function cmp($a, $b) {
		return strcasecmp($a, $b);
	}
	function sign($key,$msg){
		return hash_hmac('sha256',$msg,hex2bin($key));
	}
	function Send($path,$payload){
		$root=$_SERVER['DOCUMENT_ROOT'];
		if(! defined('IOT_ENDPOINT')
			|| ! defined('IOT_PORT')
			|| ! defined('IOT_CRED_FILE')){
			print_r("IOT endpoint not defined");
		}
		$server=IOT_ENDPOINT.":".IOT_PORT;
		$cred=IOT_CRED_FILE;
		$requrl=$server.$path."?qos=1";
		$region="eu-west-2";
		$method="";

		$ksecret="";
		$keyid='';
		$lines = file("$root/../ssl/creds/kennyams.cred");
		foreach ($lines as $no => $line){
			$crd=explode(' = ',$line);
			if(array_key_exists(1,$crd)){
				if($crd[0]=='aws_access_key_id'){
					$keyid=trim($crd[1]);
				}else{
					$ksecret=trim($crd[1]);
				}
			}
		}

		$method="POST";
		$datetime=new DateTime("now");
		$tz=new DateTimeZone("UTC");
		date_timezone_set($datetime,$tz);
		$dt=$datetime->format("Ymd\THis\Z");
		$d=$datetime->format("Ymd");
		$service="iotdata";

		$parsedurl=parse_url($requrl);
		$request=$method."\n";

		if($parsedurl['path']=='/'){
			$request.="/\n";
		}else{
			$request.=$parsedurl['path']."\n";
		}
		$request.=utf8_encode($parsedurl['query'])."\n";

		$headers='';
		$signedHeaders='';
		$headersToBSigned = array(
			'host'=>$parsedurl['host'],
			'X-Amz-Date'=>$dt
		);

		uksort($headersToBSigned,'cmp');


		foreach($headersToBSigned as $key => $value){
			$headers.=strtolower($key).":".$value."\n";
			$signedHeaders.=strtolower($key).";";
		} 
		//echo "HEADERS=>".$headers."--------------------------\n";
		$signedHeaders=substr($signedHeaders,0,-1);
		//echo "SIGNEDHEADERS=>".$signedHeaders."--------------------------\n";

		$request.=$headers."\n".$signedHeaders."\n";

		$request.=hash('sha256',$payload);

		//echo "REQUEST=>\n".$request."--------------------\n";
		$hrequest=hash('sha256',$request);

		//echo "HREQUEST for step 2=>\n".$hrequest."---------------------\n\n";


		$credentialsScope=$d."/".$region."/".$service."/aws4_request";
		$stringtosign = "AWS4-HMAC-SHA256\n";
		$stringtosign.= $dt."\n";
		$stringtosign.= $credentialsScope."\n";
		//$stringtosign.= $d."/".$region."/iot/aws4_request\n";
		$stringtosign.= $hrequest;
		//echo "STRING TO SIGN=>\n".$stringtosign."\n----------------\n\n";
		//echo "STEP3\n";
		$kdate = sign(bin2hex("AWS4".$ksecret),$d);
		$kregion = sign($kdate,$region);
		$kservice = sign($kregion,$service);
		$ksigning = sign($kservice ,"aws4_request");
		//echo "SIGNING KEY=>\n".$ksigning."\n";

		$signed=sign($ksigning,$stringtosign);
		//echo "signed\n";
		//echo $signed."\n";

		$headers=array();
		foreach($headersToBSigned as $key => $value){
			array_push($headers,$key.":".$value);
		}
		//print_r($signedHeaders."\n");
		array_push($headers,'Content-Length:'.strlen($payload));
		$authorization='Authorization:'."AWS4-HMAC-SHA256 Credential=".$keyid."/".$credentialsScope.",SignedHeaders=".$signedHeaders.",Signature=".$signed;
		//echo "AUTHORIZATION=>\n".$authorization."\n";
		array_push($headers,$authorization);
		//print_r($headers);

		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $requrl);
		if( $method=="POST"){
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
		}
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

		$out = curl_exec($ch);
		//print_r(curl_getinfo($ch, CURLINFO_HTTP_CODE));
		if($out === False){
			print_r(curl_error($ch));
			echo "NOK";
		}else{
			//echo "OK";
			//print_r($out);
		}
		//echo "</textarea>";
		curl_close($ch);
		return $out;
	}
?>
