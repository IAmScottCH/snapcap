<?php

/*
 *
 * SnapCap Version 2.0.1
 * 
 * Application file and database backup utility.
 * SnapCap client PHP CLI implementation.
 * 
 * Copyright (c) 2021, Primal Apparatus Workshop
 *                         
 *                      A A  
 *                     aa aa
 *                    ppp ppp         Primal
 *                A  pppp pppp  A 
 *               aa  pppp pppp  aa 
 *              pPPp  PpP PpP  pPPp   Apparatus
 *              pppp           pppp 
 *              PppP  wwWWWww  PppP 
 *                   wwwwwwwww        Workshop
 *                 wwwwwwWwwwwww
 *                wwwwwwwwwwwwwww   
 *                 WwwwW   WwwwW  
 * 
 * MOST IMPORTANT NOTE: Exception messages must be read in a sultry, female, robot voice.  Thank you.
 * 
 * Sample sequence for setup (in reality, the whole sequence is handled by SUP, because there is a key change):
 * php -f snapclient.php HLO localhost
 * php -f snapclient.php SUP /home/scott/.ssh/test_sc_app localhost '/'
 *                           where to find test_sc_app.pem and .pub, target host, path to snapserver from doc root on target host
 * php -f snapclient.php BYE localhost
 */

$renv='PRD';
if(isset($_SERVER['SCENV']))
    $renv=$_SERVER['SCENV'];
if($renv==='DEV')
{
    DEFINE('SC_SETUP_KEY','/home/scott/.ssh/scsetup.pem');
    DEFINE('SC_SETUP_PUB_KEY','/home/scott/.ssh/scsetup.pub');
}
else 
{
    DEFINE('SC_SETUP_KEY','/home/lain/bin/snapcap/keys/scsetup.pem');
    DEFINE('SC_SETUP_PUB_KEY','/home/lain/bin/snapcap/keys/scsetup.pub');
}

DEFINE('SC_SEVERITY_ERR',2);
DEFINE('SC_SEVERITY_WRN',1);

class ClaSnapClient
{
    private $scsetupkey;  // the setup key
    private $hostKeyBase; // where locally the key pair can be found, and the name without the extensions.
    private $scsetuppub;  // the pub setup key, for testing
    private $hostkey;     // current host key
    private $currentHost;
    private $scsid;
    private $sessionData;
    private $setupMode; // convenient!
    const BLKSIZE=400;
    private $lastExecMsg;
    private $cookiejar;
    private $currentSaltKey;
    private $currentIV;
    
    public function __construct()
    {
        $this->setupMode=false;
        $this->sessionData=array();
        $this->scsid=null;
        $this->currentHost='';
        $this->hostkey=null;
        $this->lastExecMsg='';
        $this->hostKeyBase='';
        $this->currentCookies=null;
        $this->currentSaltKey=null;
        $this->currentIV=null;
        $this->cookiejar=__DIR__ . DIRECTORY_SEPARATOR . "snapcap_cookiejar.txt";
       
        $this->scsetupkey=openssl_pkey_get_private('file://' . SC_SETUP_KEY);
        if($this->scsetupkey===false)
            throw new Exception('I could not parse the setup key.',SC_SEVERITY_ERR);
        $this->scsetuppub=openssl_pkey_get_public('file://' . SC_SETUP_PUB_KEY);
        if($this->scsetuppub===false)
            throw new Exception('I could not parse the setup public key.',SC_SEVERITY_ERR);
                
    }
    private function decryptFile($efile,$pfile)
    {
      $fsize=filesize($efile);
      $fsh=fopen($efile,"rb");
      if($fsh===false)
          throw new Exception("Could not open source file for decryption",SC_SEVERITY_ERR);
      $fth=fopen($pfile,"wb");
      if($fth===false)
      {
          fclose($fsh);
          throw new Exception("Could not open target file for decryption",SC_SEVERITY_ERR);
      }
      
      $fw=true;
      $fsize=filesize($efile);
      while(!feof($fsh))
      {
        $pstr='';
        $estr=stream_get_line($fsh,$fsize,',');  // does not return delimiter itself
        if($estr===false)
        {
            fclose($fsh);
            fclose($fth);
            throw new Exception("Error decrypting file during read",SC_SEVERITY_ERR);
        }
        try 
        {
            $pstr=$this->decryptString($estr);
            
        } catch (Exception $e) 
        {
            fclose($fsh);
            fclose($fth);
            throw $e;
        }
        if(!$fw)
        {
            if(fwrite($fth,',')===false)
            {
                fclose($fsh);
                fclose($fth);
                throw new Exception("Error decrypting file while writing separator",SC_SEVERITY_ERR);
            }
            $fw=false;
        }
        if(fwrite($fth,$pstr)===false)
        {
            fclose($fsh);
            fclose($fth);
            throw new Exception("Error decrypting file during write",SC_SEVERITY_ERR);
        }
      }
      
         
      
      fclose($fsh);
      fclose($fth);        
    }
    // decrypt $argstring with the imported key $ekey
    // see encryptString for the way the message is structured in chunks and encoded.
    private function decryptString($argstring)
    {
        $ekey=($this->setupMode?$this->scsetupkey:$this->hostkey);
        $estr=base64_decode($argstring);
        $echunks=explode(',',$estr);
        $rstr='';
        foreach($echunks as $chunk)
        {
            
            $pchunk='';
            if(!openssl_private_decrypt(base64_decode($chunk),$pchunk,$ekey,  OPENSSL_PKCS1_OAEP_PADDING))
                throw new Exception('I could not decrypt one of the server chunks.',SC_SEVERITY_ERR);
                $rstr.=$pchunk;
        }
        return $rstr;
        
    }
    private function decryptFileSymmetric($efile,$pfile,$kfile)
    {
        
      $keys=file_get_contents($kfile);
      $kparts=explode("\n",$keys);
      $this->currentSaltKey=base64_decode($kparts[0]);
      $this->currentIV=base64_decode($kparts[1]);
      
      $fsize=filesize($efile);
      $fsh=fopen($efile,"rb");
      if($fsh===false)
          throw new Exception("Could not open source file for decryption",SC_SEVERITY_ERR);
      $fth=fopen($pfile,"wb");
      if($fth===false)
      {
          fclose($fsh);
          throw new Exception("Could not open target file for decryption",SC_SEVERITY_ERR);
      }
      
      $fw=true;
      $fsize=filesize($efile);
      while(!feof($fsh))
      {
        $pstr='';
        $estr=stream_get_line($fsh,$fsize,',');  // does not return delimiter itself
        if($estr===false)
        {
            fclose($fsh);
            fclose($fth);
            throw new Exception("Error decrypting file during read",SC_SEVERITY_ERR);
        }
        try 
        {
            $pstr=$this->decryptStringSymmetric($estr,$this->currentSaltKey,$this->currentIV);
            
        } catch (Exception $e) 
        {
            fclose($fsh);
            fclose($fth);
            throw $e;
        }
        if(!$fw)
        {
            if(fwrite($fth,',')===false)
            {
                fclose($fsh);
                fclose($fth);
                throw new Exception("Error decrypting file while writing separator",SC_SEVERITY_ERR);
            }
            $fw=false;
        }
        if(fwrite($fth,$pstr)===false)
        {
            fclose($fsh);
            fclose($fth);
            throw new Exception("Error decrypting file during write",SC_SEVERITY_ERR);
        }
      }
      
         
      
      fclose($fsh);
      fclose($fth);        
    }
    // decrypt $argstring with the imported key $ekey
    // see encryptString for the way the message is structured in chunks and encoded.
    private function decryptStringSymmetric($argstring,$ekey,$iv)
    {
        //$ekey=($this->setupMode?$this->scsetupkey:$this->hostkey);
        $estr=base64_decode($argstring);
        $echunks=explode(',',$estr);
        $rstr='';
        foreach($echunks as $chunk)
        {
            
            $pchunk=openssl_decrypt(base64_decode($chunk),'AES-128-CBC',$ekey,OPENSSL_RAW_DATA,$iv);
            if($pchunk===false)
                throw new Exception('I could not decrypt one of the server chunks.',SC_SEVERITY_ERR);
            $rstr.=$pchunk;
        }
        return $rstr;
        
    }    
    private function encryptFileSymmetric($srcfile,$tarfile,$ekey,$iv)
    {
        $BLKSIZE=ClaSnapClient::BLKSIZE;
        
        $fsh=fopen($srcfile,"rb");
        if($fsh===false)
        {
            header("HTTP/1.0 500 Source file unreadable");
            throw new Exception("Source file could not be opened for encryption");
        }
        $fth=fopen($tarfile,"wb");
        if($fth===false)
        {
            fclose($fsh);
            header("HTTP/1.0 500 Target file unwritable");
            throw new Exception("Target file could not be opened for receiving encrypted data");
        }
        
        $fw=true;
        while(!feof($fsh))
        {
            $pstr=fread($fsh,$BLKSIZE);
            if($pstr===false)
            {
                fclose($fsh);
                fclose($fth);
                header("HTTP/1.0 500 Source file read error");
                throw new Exception("Data for encryption could not be read");
            }
            try
            {
                $estr=$this->encryptStringSymmetric($pstr, $ekey, $iv);
                
            } catch (Exception $e)
            {
                fclose($fsh);
                fclose($fth);
                throw $e;
            }
            if(!$fw)
            {
                if(fwrite($fth,',')===false)
                {
                    fclose($fsh);
                    fclose($fth);
                    header("HTTP/1.0 500 Target file delimiter write error");
                    throw new Exception("Separator could not written while encrypting the file");
                }
            }
            if(fwrite($fth,$estr)===false)
            {
                fclose($fsh);
                fclose($fth);
                header("HTTP/1.0 500 Target file write error");
                throw new Exception("Encrypted data could not be written");
            }
            $fw=false;
        }
        
        
        
        fclose($fsh);
        fclose($fth);
    }
    
    //use a symmetric key.
    private function encryptStringSymmetric($pstr,$ekey,$iv)
    {
        $BLKSIZE=ClaSnapClient::BLKSIZE;
        
        $pchunks=str_split($pstr,$BLKSIZE);
        $echunks=array();
        foreach($pchunks as $chunk)
        {
            $echunk=openssl_encrypt($chunk,'AES-128-CBC',$ekey,OPENSSL_RAW_DATA,$iv);
            if($echunk===false)
            {
                header("HTTP/1.0 500 ES failed");
                throw new Exception("Error encountered while encrypting a fragment of your data");
            }
            $echunks[]=base64_encode($echunk);
        }
        $estring=implode($echunks,',');
        return base64_encode($estring);
    }  
    // have to encrypt in chunks
    // assumes a 4096 bit key (for RSA)
    // so can encrypt in 4096/8-11 = 501 byte chunks.  will use blocks of 400 bytes.
    // output will be a base64 encoded string of base64 encoded chunks separated by ','
    private function encryptString($pstr)
    {
        $BLKSIZE=ClaSnapClient::BLKSIZE;
        $ekey=($this->setupMode?$this->scsetupkey:$this->hostkey);
        $pchunks=str_split($pstr,$BLKSIZE);
        $echunks=array();
        foreach($pchunks as $chunk)
        {
            $echunk='';
            if(!openssl_private_encrypt($chunk,$echunk,$ekey))
                throw new Exception("I could not encrypt a chunk of your string",SC_SEVERITY_ERR);
            $echunks[]=base64_encode($echunk);
        }
        $estring=implode($echunks,',');
        return base64_encode($estring);
    }
    private function processResponse($eblob,&$rcmd,&$rdata)
    {
        $pblob=$this->decryptString($eblob);
        $pparts=explode(' ',$pblob);
        $rcmd=$pparts[0];
        $rdata=base64_decode($pparts[1]);
        return true;
    }
    public function HLO($host,$snappath)
    {
        $rcmd='';
        $rdata='';
        $url='https://' . $host . '/' . $snappath . 'snapserver.php';
        $args=array();
        $res=$this->execCommand('HLO',$url,$args,true);  // HLO always starts a new session.
        if($res===false)
           throw new Exception("EEEE: HLO failed: $this->lastExecMsg \n",SC_SEVERITY_ERR);
        $this->processResponse($res,$rcmd,$rdata);
        if($rcmd!=='HLO')
            throw new Exception('Server replied with invalid response command: ' . $rcmd . "\n",SC_SEVERITY_ERR);
        $this->scsid=$rdata;
        echo "CIIII: Received response data: $rdata and using it to set the session id\n";
    }
    // returns sid.
    public function BYE($host,$snappath)
    {
        $rcmd='';
        $rdata='';
        $url='https://' . $host . '/' . $snappath . 'snapserver.php';
        $args=array('');
        $res=$this->execCommand('BYE',$url,$args);
        if($res===false)
            throw new Exception("EEEE: BYE failed: $this->lastExecMsg \n",SC_SEVERITY_ERR);
        $this->processResponse($res,$rcmd,$rdata);
        if($rcmd!=='BYE')
            throw new Exception('Server replied with invalid response command: ' . $rcmd . "\n",SC_SEVERITY_ERR);
        echo "CIIII: Received response data: $rdata\n";
        return $rdata;
    }
    public function SUP($keybase,$host,$snappath)
    {
        $rcmd='';
        $rdata='';
        $this->setupMode=true;
        $this->hostKeyBase=$keybase;
        $keyfile=$keybase . '.pub';
        $prvkeyfile=$keybase . '.pem';
        $appprvkey=openssl_pkey_get_private('file://' . $prvkeyfile);
        if($appprvkey===false)
            throw new Exception('I could not parse the application key from ' . $prvkeyfile,SC_SEVERITY_ERR);
            
        trim($snappath);
        if($snappath[strlen($snappath)-1]!=='/')
        {
            if(strlen($snappath)>0)
                $snappath=$snappath . '/';
        }
        $url='https://' . $host . '/' . $snappath . 'snapserver.php'; 
        // protocol is:  HLO,SUP,BYE
        // In this case, HLO and SUP will use the setup key, and BYE will use the new key.
        $appkey=file_get_contents($keyfile);
        if($appkey===false)
        {
            $this->setupMode=false;
            throw new Exception('I could not read the contents of the application key file.',SC_SEVERITY_ERR);
        }
        
        echo "CIIII: Sending HLO\n";
        $this->HLO($host,$snappath);
        
        
        echo "CIIII: Sending SUP\n";
        $args=array('sc_appkey'=>$appkey);
        $res=$this->execCommand('SUP',$url,$args);
        if($res===false)
            throw new Exception("EEEE: SUP failed: $this->lastExecMsg \n",SC_SEVERITY_ERR);
        $this->setupMode=false; // the server should have changed keys now.
        $this->hostkey=$appprvkey;
        
        $this->processResponse($res,$rcmd,$rdata);
        echo "CIIII: Received response data: $rdata \n";
        $exitWarn=false;
         if($rdata!==$this->scsid)
           $exitWarn="SUP SC SID from server seems wrong\n";
        
        echo "CIIII: Sending BYE\n";
        $bsid=$this->BYE($host,$snappath);
        if($bsid!==$this->scsid)
            $exitWarn="BYE SC SID from server seems wrong\n";
        
        if($exitWarn!==false)
            throw new Exception($exitWarn,SC_SEVERITY_WRN);
         
    }
    public function readURLIntoFile($url,$lfilespec)
    {
        $rcon=true;
        $lfh=fopen($lfilespec,"wb");
        if($lfh===false)
            throw new Exception("I cannot open file $lfilespec for writing",SC_SEVERITY_ERR);
        $ch=curl_init($url);
        if($ch===false)
        {
            fclose($lfh);
            throw new Exception('Error initializing cURL',SC_SEVERITY_ERR);
        }
        $opts=array
        (
            CURLOPT_POST=>false,
            CURLOPT_USERAGENT=>'snapclient',
            CURLOPT_FOLLOWLOCATION => true,     // follow redirects
            CURLOPT_SSL_VERIFYHOST => false,        // don't verify certs and stuff.
            CURLOPT_SSL_VERIFYPEER => false,    // ditto
            CURLOPT_TIMEOUT=>300,  
            CURLOPT_COOKIEFILE=>$this->cookiejar,
            CURLOPT_COOKIEJAR=>$this->cookiejar,
        );    
        
        $opts[CURLOPT_FILE]=$lfh;
            
        curl_setopt_array($ch,$opts);
        
        $rcon=curl_exec($ch); 
        $this->lastExecMsg=curl_error($ch);
            
        curl_close($ch);
        fclose($lfh);

        return $rcon;
    }
    public function BFL($keybase,$host,$snappath,$lfilespec)
    {
        $lkeyfilespec=$lfilespec . ".keyring";
        echo "CIIII: BFL args:\n";
        echo "C-III:   keybase: $keybase \n";
        echo "C-III:      host: $host \n";
        echo "C-III:  snappath: $snappath \n";
        echo "C-III: lfilespec: $lfilespec \n";
        echo "C-III: lkeyfilespec: $lkeyfilespec \n";
        $rcmd='';
        $rdata='';
        $chksum='';
        $this->setupMode=false;
        $this->hostKeyBase=$keybase;
        $appkeyfile=$keybase . '.pem';
        $this->hostkey=openssl_pkey_get_private('file://' . $appkeyfile);
        if($this->hostkey===false)
            throw new Exception('I could not parse the application key.',SC_SEVERITY_ERR);
            
        // this will potentially take the server a long time, so:
        if(set_time_limit(0)===false)
            echo "CWWWW: WARNING: I could not set an infinite time limit for the script execution\n";
        trim($snappath);
        if($snappath[strlen($snappath)-1]!=='/')
        {
            if(strlen($snappath)>0)
                $snappath=$snappath . '/';
        }
        $url='https://' . $host . '/' . $snappath . 'snapserver.php'; 
        // protocol is:  HLO,BFL,SND,BYE
        
        echo "CIIII: Sending HLO\n";
        $this->HLO($host,$snappath);
        
        // Generate key and an iv.
        $this->currentSaltKey=openssl_random_pseudo_bytes(128);
        $this->currentIV=openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-128-CBC'));
        $keys=base64_encode($this->currentSaltKey) . "\n" . base64_encode($this->currentIV);
        file_put_contents($lkeyfilespec,$keys);
        //TODO: support more modes than just wordpress, and take the mode on the command line or something
        echo "CIIII: Sending BFL\n";
        $args=array('sc_mode'=>'wordpress','sc_symkey'=>$this->currentSaltKey,'sc_iv'=>$this->currentIV,'sc_noenc'=>'noencrypt');
       
        
        // First tell the server to create the backup
        $res=$this->execCommand('BFL',$url,$args,false,null,300); //TODO: don't hardcode the timeout
        
        $this->processResponse($res,$rcmd,$rdata);
        if($rcmd=='ERR')
            throw new Exception("Server experienced an error making file backup: $rdata \n",SC_SEVERITY_ERR);
        else 
        {
            $chksum=$rdata;
            echo "CIIII: The server's checksum is $chksum \n";
            $args=array('sc_sndmode'=>'download');
            // now tell the server to provide the URL of the backup.
            $res=$this->execCommand('SND',$url,$args,false,null/*$lfilespec*/,300); //TODO: don't hardcode the timeout
            if($res===false)
                throw new Exception("SND failed: $this->lastExecMsg \n",SC_SEVERITY_ERR);
            else 
            {
                echo "CIIII: Extracting URL from server response...\n";
                $this->processResponse($res,$rcmd,$rdata);
                if($rcmd=='ERR')
                    throw new Exception("Server failed to reply with a download URL during file backup: $rdata \n",SC_SEVERITY_ERR);
                
                $bflurl=$rdata;
                echo "CIIII: backup file URL is: $bflurl \n";
                
                // get the file from the server.
                if(!$this->readURLIntoFile($bflurl, $lfilespec))
                    throw new Exception("Error downloading file\n",SC_SEVERITY_ERR);
                echo "CIIII: File backup data received.  Verifying checksum.\n";
                $mysum=md5_file($lfilespec);
                echo "CIIII: My checksum is $mysum \n";
                if($mysum!==$chksum)
                {
                    throw new Exception("Checksum verification failed!\n",SC_SEVERITY_ERR);
                }
                else 
                    echo "CIIII: Checksum verification passed.\n";
            }
        }
       
        echo "CIIII: Sending BYE\n";
        $bsid=$this->BYE($host,$snappath);
        if($bsid!==$this->scsid)
            throw new Exception("BYE SC SID from server seems wrong\n",SC_SEVERITY_WRN);
        
        $cfrfilespec=$lfilespec . '.cfr';
        echo "CIIII: Encrypting file with symmetric key to $cfrfilespec.\n";
        $this->encryptFileSymmetric($lfilespec, $cfrfilespec, $this->currentSaltKey, $this->currentIV);
        echo "CIIII: Removing unencrypted file $lfilespec. \n";
        unlink($lfilespec);

    }
    
    public function BDB($keybase,$host,$snappath,$lfilespec)
    {
        $lkeyfilespec=$lfilespec . ".keyring";
        echo "CIIII: BDB args:\n";
        echo "C-III:   keybase: $keybase \n";
        echo "C-III:      host: $host \n";
        echo "C-III:  snappath: $snappath \n";
        echo "C-III: lfilespec: $lfilespec \n";
        echo "C-III: lkeyfilespec: $lkeyfilespec \n";
        $rcmd='';
        $rdata='';
        $chksum='';
        $this->setupMode=false;
        $this->hostKeyBase=$keybase;
        $appkeyfile=$keybase . '.pem';
        $this->hostkey=openssl_pkey_get_private('file://' . $appkeyfile);
        if($this->hostkey===false)
            throw new Exception('I could not parse the application key.',SC_SEVERITY_ERR);
 
        // this will potentially take the server a long time, so:
        if(set_time_limit(0)===false)
            echo "CWWWW: WARNING: I could not set an infinite time limit for the script execution\n";
        
        trim($snappath);
        if($snappath[strlen($snappath)-1]!=='/')
        {
            if(strlen($snappath)>0)
                $snappath=$snappath . '/';
        }
        $url='https://' . $host . '/' . $snappath . 'snapserver.php'; 
        // protocol is:  HLO,BDB,SND,BYE
        
        echo "CIIII: Sending HLO\n";
        $this->HLO($host,$snappath);
        
        $this->currentSaltKey=openssl_random_pseudo_bytes(128);
        $this->currentIV=openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-128-CBC'));
        $keys=base64_encode($this->currentSaltKey) . "\n" . base64_encode($this->currentIV);
        file_put_contents($lkeyfilespec,$keys);
        //TODO: support more modes than just wordpress, and take the mode on the command line or something
        echo "CIIII: Sending BDB\n";
        $args=array('sc_mode'=>'wordpress','sc_symkey'=>$this->currentSaltKey,'sc_iv'=>$this->currentIV,'sc_noenc'=>'noencrypt');
        
        // First tell the server to create the backup
        $res=$this->execCommand('BDB',$url,$args,false,null,300); //TODO: don't hardcode the timeout
        
        $this->processResponse($res,$rcmd,$rdata);
        if($rcmd=='ERR')
        {
             throw new Exception("Server experienced an error making DB backup: $rdata",SC_SEVERITY_ERR);
        }
        else 
        {
            $chksum=$rdata;
            echo "CIIII: The server's checksum is $chksum \n";
            $args=array('sc_sndmode'=>'download');
            $res=$this->execCommand('SND',$url,$args,false,null/*$lfilespec*/,300); //TODO: don't hardcode the timeout
            if($res===false)
                throw new Exception("SND failed: $this->lastExecMsg \n",SC_SEVERITY_ERR);
            else 
            {
                echo "CIIII: Extracting URL from server response...\n";
                $this->processResponse($res,$rcmd,$rdata);
                if($rcmd=='ERR')
                    throw new Exception("Server failed to reply with a download URL during database backup: $rdata \n",SC_SEVERITY_ERR);
                
                $bflurl=$rdata;
                echo "CIIII: backup file URL is: $bflurl \n";
                
                if(!$this->readURLIntoFile($bflurl, $lfilespec))
                    throw new Exception("Error downloading file\n",SC_SEVERITY_ERR);
                echo "CIIII: DB backup data received.  Verifying checksum.\n";
                $mysum=md5_file($lfilespec);
                echo "CIIII: My checksum is $mysum \n";
                if($mysum!==$chksum)
                {
                    throw new Exception("Checksum verification failed!\n",SC_SEVERITY_ERR);
                }
                else 
                    echo "CIIII: Checksum verification passed.\n";
            }
        }
       
        echo "CIIII: Sending BYE\n";
        $bsid=$this->BYE($host,$snappath);
        if($bsid!==$this->scsid)
           throw new Exception("BYE SC SID from server seems wrong\n",SC_SEVERITY_WRN);
        
       $cfrfilespec=$lfilespec . '.cfr';
       echo "CIIII: Encrypting file with symmetric key to $cfrfilespec.\n";
       $this->encryptFileSymmetric($lfilespec, $cfrfilespec, $this->currentSaltKey, $this->currentIV);
       echo "CIIII: Removing unencrypted file $lfilespec. \n";
       unlink($lfilespec);
        
     }
     public function decryptLocalFileSymmetric($encfile, $plnfile, $keyfile)
     {
        $this->setupMode=false;
       // $this->hostKeyBase=$keybase;
       // $appkeyfile=$keybase . '.pem';
       // $this->hostkey=openssl_pkey_get_private('file://' . $appkeyfile);
       // if($this->hostkey===false)
       //     throw new Exception('I could not parse the application key.',SC_SEVERITY_ERR);
 
        // this will potentially take a long time, so:
        if(set_time_limit(0)===false)
            echo "CWWWW: WARNING: I could not set an infinite time limit for the script execution\n";
        echo "CIIII: Decrypting $encfile to $plnfile \n";
        $this->decryptFileSymmetric($encfile,$plnfile, $keyfile);
               
     }
     public function decryptLocalFile($encfile, $plnfile, $keybase)
     {
        $this->setupMode=false;
        $this->hostKeyBase=$keybase;
        $appkeyfile=$keybase . '.pem';
        $this->hostkey=openssl_pkey_get_private('file://' . $appkeyfile);
        if($this->hostkey===false)
            throw new Exception('I could not parse the application key.',SC_SEVERITY_ERR);
 
        // this will potentially take a long time, so:
        if(set_time_limit(0)===false)
            echo "CWWWW: WARNING: I could not set an infinite time limit for the script execution\n";
        echo "CIIII: Decrypting $encfile to $plnfile \n";
        $this->decryptFile($encfile,$plnfile);
               
     }
    // $timeout is in seconds.  It's provided as an optional value so that when a backup command is run, it 
    // can be extended to 300 seconds or more.
    // $postArgs is passed as-is as the cURL post fields array, but with the following added in:
    //    sc_session => current scsid
    //    sc_command => command provided in $cmd
    // setting $clearcookies to true will force all cookies to be cleared, to start a new session.
    // if $intofile is not null, it is used as a filename of file to get the response from.
    //   This is useful for BDB and BFL, where the server will send nothing but the app key
    //   encrypted DB SQL or filesystem backup archive content.
    // TODO: see other TODO's.  I don't think I actually need the  timeout, though, since I deal with it
    //       in functions like BDB anyway.  So, I have to decide if I want to pass it in here or if
    //       I want to just let caller functions deal with timeouts.  I'm not sure which is prettier.  I'm conflicted.
    private function execCommand($cmd,$url,$postArgs,$clearcookies=false,$intofile=null,$timeout=20)
    {
        $doingFile=($intofile!==null);
        $fh=null;
        if($doingFile)
        {
            $fh=fopen($intofile,"wb");
            if($fh===false)
                throw new Exception("I cannot open file $intofile for writing",SC_SEVERITY_ERR);
        }
        $ch=curl_init($url);
        if($ch===false)
        {
            if($doingFile)
                fclose($fh);
            throw new Exception('Error initializing cURL',SC_SEVERITY_ERR);
        }
        $estr='';
        $comstr=$cmd;
        if(!is_null($this->scsid))
            $comstr.=' ' . base64_encode($this->scsid);
            
        foreach($postArgs as $k=>$v)
        {
            $comstr.=' ' . base64_encode($v);
        }
        $estr=$this->encryptString($comstr);
        $pargs=array('snapcap'=>$estr);
        $opts=array
        (
            CURLOPT_POST=>true,
            CURLOPT_USERAGENT=>'snapclient',
            CURLOPT_FOLLOWLOCATION => true,     // follow redirects
            CURLOPT_SSL_VERIFYHOST => false,        // don't verify certs and stuff.
            CURLOPT_SSL_VERIFYPEER => false,    // ditto
            CURLOPT_TIMEOUT=>$timeout,  
            CURLOPT_POSTFIELDS=>$pargs,
            CURLOPT_COOKIEFILE=>$this->cookiejar,
            CURLOPT_COOKIEJAR=>$this->cookiejar,
        );    
        
        if($doingFile)
        {
            $opts[CURLOPT_FILE]=$fh;
        }
        else 
            $opts[CURLOPT_RETURNTRANSFER]=true;
        
        if($clearcookies)
            $opts[CURLOPT_COOKIESESSION]=true;
            
        curl_setopt_array($ch,$opts);
        
        $rcon=curl_exec($ch); 
        $this->lastExecMsg=curl_error($ch);
            
        curl_close($ch);
        if($doingFile)
         fclose($fh);
        
        return $rcon;
    }
};

// command line mode operation
if(defined('STDIN'))
{
    try 
    {
        
    echo "CIIII: $argc arguments were provided\n";
    if($argc<2)
        throw new Exception('Please enter a command with your request.',SC_SEVERITY_ERR);
    $command=strtoupper(trim($argv[1]));
    switch($command)
    {
        case 'BDB':
            if($argc<5)
                throw new Exception('The BDB command requires 4 arguments: application key file base, taget host IP address or name, path to snapserver.php on the remote host, and local backup file name.',SC_SEVERITY_ERR);
            $sci=new ClaSnapClient();
            $sci->BDB($argv[2],$argv[3],$argv[4],$argv[5]);    
            break;       
        case 'BFL':
            if($argc<5)
                throw new Exception('The BFL command requires 4 arguments: application key file base, taget host IP address or name, path to snapserver.php on the remote host, and local backup file name.',SC_SEVERITY_ERR);
            $sci=new ClaSnapClient();
            $sci->BFL($argv[2],$argv[3],$argv[4],$argv[5]);    
            break;       
        case 'SUP':
            if($argc<4)
                throw new Exception('The SUP command requires 3 arguments: public key file base, target host IP address or name, and path to snapserver.php on the remote host.',SC_SEVERITY_ERR);
            $sci=new ClaSnapClient();
            $keyfilespec=$argv[2];
            $targetHost=$argv[3];
            $snappath=$argv[4];
            $sci->SUP($keyfilespec,$targetHost,$snappath);
            break;
        // utility commands
        case 'DECRYPTFILE':
            if($argc<4)
                throw new Exception('The decryptfile command requires 3 arguments: the application key file base, the path/name of encrypted and the path/name where you want the decrypted file',SC_SEVERITY_ERR);
            $sci=new ClaSnapClient();
            $keybase=$argv[2];
            $encfile=$argv[3];
            $plnfile=$argv[4];
            $kfile=substr($encfile,0,-4) . ".keyring";
            $sci->decryptLocalFileSymmetric($encfile,$plnfile,$kfile);
            break;
            
        default:
            throw new Exception('Invalid command: ' . $command . '.',SC_SEVERITY_ERR);
            break;
    }
    
    } catch (Exception $e) 
    {
        if($e->getCode()==SC_SEVERITY_ERR)
        {
            echo "CEEEE: " . $e->getMessage() . "\n";
            exit(SC_SEVERITY_ERR);
        }
        else if($e->getCode()==SC_SEVERITY_WRN)
        {
            echo "CEEEE: " . $e->getMessage() . "\n";
            exit(SC_SEVERITY_WRN);
        }
        
        echo "CEEEE: Unexpected exception (" . $e->getCode() . "): " . $e->getMessage() . "\n";
        exit(SC_SEVERITY_ERR);
        
    }
 
    exit(0); // sucess
    
}
?>
