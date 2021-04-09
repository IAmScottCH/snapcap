<?php

/*
 * MOST IMPORTANT NOTE: Exception messages must be read in a sultry, female, robot voice.  Thank you.
 * 
 * Sample sequence for setup (in reality, the whole sequence is handled by SUP, because there is a key change):
 * php -f snapclient.php HLO localhost
 * php -f snapclient.php SUP /home/scott/.ssh/test_sc_app localhost '/'
 *                           where to find test_sc_app.pem and .pub, target host, path to snapserver from doc root on target host
 * php -f snapclient.php BYE localhost
 */

DEFINE('SC_SETUP_KEY','/home/scott/.ssh/scsetup.pem');
DEFINE('SC_SETUP_PUB_KEY','/home/scott/.ssh/scsetup.pub');

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
        $this->cookiejar=__DIR__ . DIRECTORY_SEPARATOR . "snapcap_cookiejar.txt";
       
        $this->scsetupkey=openssl_pkey_get_private('file://' . SC_SETUP_KEY);
        if($this->scsetupkey===false)
            throw new Exception('I could not parse the setup key.');
        $this->scsetuppub=openssl_pkey_get_public('file://' . SC_SETUP_PUB_KEY);
        if($this->scsetuppub===false)
            throw new Exception('I could not parse the setup public key.');
                
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
            if(!openssl_private_decrypt(base64_decode($chunk),$pchunk,$ekey))
                throw new Exception('I could not decrypt one of the server chunks.');
                $rstr.=$pchunk;
        }
        return $rstr;
        
    }
    // have to encrypt in chunks
    // assumes a 4096 bit key
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
                throw new Exception("I could not encrypt a chunk of your string");
                $echunks[]=base64_encode($echunk);
        }
        $estring=implode($echunks,',');
        return base64_encode($estring);
    }
    private function processResponse($eblob,&$rcmd,&$rdata)
    {
        $eparts=explode(',',$eblob);
        $rcmd=$this->decryptString($eparts[0]);
        $rdata=$this->decryptString($eparts[1]);
        return true;
    }
    public function HLO($host,$snappath)
    {
        $rcmd='';
        $rdata='';
        $url='https://' . $host . '/' . $snappath . 'snapserver.php';
        $args=array('');
        $res=$this->execCommand('HLO',$url,$args,true);  // HLO always starts a new session.
        if($res===false)
            echo "EEEE: HLO failed: $this->lastExecMsg \n";
        $this->processResponse($res,$rcmd,$rdata);
        if($rcmd!=='HLO')
            throw new Exception('Server replied with invalid response command: ' . $rcmd . "\n");
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
            echo "EEEE: BYE failed: $this->lastExecMsg \n";
        $this->processResponse($res,$rcmd,$rdata);
        if($rcmd!=='BYE')
            throw new Exception('Server replied with invalid response command: ' . $rcmd . "\n");
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
            throw new Exception('I could not parse the application key from ' . $prvkeyfile);
            
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
            throw new Exception('I could not read the contents of the application key file.');
        }
        
        echo "CIIII: Sending HLO\n";
        $this->HLO($host,$snappath);
        
        
        echo "CIIII: Sending SUP\n";
        $args=array('sc_appkey'=>$appkey);
        $res=$this->execCommand('SUP',$url,$args);
        if($res===false)
            echo "EEEE: SUP failed: $this->lastExecMsg \n";
        $this->setupMode=false; // the server should have changed keys now.
        $this->hostkey=$appprvkey;
        
        $this->processResponse($res,$rcmd,$rdata);
        echo "CIIII: Received response data: $rdata \n";
        //TODO: verify sid here, and if wrong, do ... something.
        
        echo "CIIII: Sending BYE\n";
        $bsid=$this->BYE($host,$snappath);
        //TODO: verify bsid is sc_sid here, and if wrong, do ... something.
        
         
    }
    
    public function BDB($keybase,$host,$snappath,$lfilespec)
    {
        $rcmd='';
        $rdata='';
        $this->setupMode=false;
        $this->hostKeyBase=$keybase;
        $appkeyfile=$keybase . '.pem';
        $this->hostkey=openssl_pkey_get_private('file://' . $appkeyfile);
        if($this->hostkey===false)
            throw new Exception('I could not parse the application key.');
            
        trim($snappath);
        if($snappath[strlen($snappath)-1]!=='/')
        {
            if(strlen($snappath)>0)
                $snappath=$snappath . '/';
        }
        $url='https://' . $host . '/' . $snappath . 'snapserver.php'; 
        // protocol is:  HLO,BDB,BYE
        
        echo "CIIII: Sending HLO\n";
        $this->HLO($host,$snappath);
        
        //TODO: support more modes than just wordpress, and take the mode on the command line or something
        echo "CIIII: Sending BDB\n";
        $args=array('sc_mode'=>'wordpress');
        $res=$this->execCommand('BDB',$url,$args);
        if($res===false)
            echo "EEEE: BDB failed: $this->lastExecMsg \n";
        
        $this->processResponse($res,$rcmd,$rdata);
        if($rcmd=='ERR')
            echo "CEEEE: Server had an error: $rdata \n";
        else
            echo "CIIII: Received response data: $rdata \n";
        
        echo "CIIII: Sending BYE\n";
        $bsid=$this->BYE($host,$snappath);
        //TODO: verify bsid is sc_sid here, and if wrong, do ... something.       
    }

    // $timeout is in seconds.  It's provided as an optional value so that when a backup command is run, it 
    // can be extended to 300 seconds or more.
    // $postArgs is passed as-is as the cURL post fields array, but with the following added in:
    //    sc_session => current scsid
    //    sc_command => command provided in $cmd
    // setting $clearcookies to true will force all cookies to be cleared, to start a new session.
    private function execCommand($cmd,$url,$postArgs,$clearcookies=false,$timeout=20)
    {
        $ch=curl_init($url);
        if($ch===false)
            throw new Exception('Error initializing cURL');
        
        $estr='';
        if(!is_null($this->scsid))
            $postArgs['sc_session']=$this->scsid;
        
        $postArgs['sc_command']=$cmd;
        $pargs=array();
        foreach($postArgs as $k=>$v)
        {
            $pargs[$k]=$this->encryptString($v);
            //$ostring=$this->decryptString($pargs[$k],$this->scsetuppub); // if you want verify enc/dec.
        }
        $opts=array
        (
            CURLOPT_RETURNTRANSFER=>true,          // get the response as the return value
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
        
        if($clearcookies)
            $opts[CURLOPT_COOKIESESSION]=true;
            
        curl_setopt_array($ch,$opts);
        
        $rcon=curl_exec($ch); 
        $this->lastExecMsg=curl_error($ch);
            
        curl_close($ch);
        
        return $rcon;
    }
};

// command line mode operation
if(defined('STDIN'))
{
    echo "CIIII: $argc arguments were provided\n";
    if($argc<2)
        throw new Exception('Please enter a command with your request.');
    $command=strtoupper(trim($argv[1]));
    switch($command)
    {
        case 'BDB':
            if($argc<5)
                throw new Exception('The BDB command requires 4 arguments: application key file base, taget host IP address or name, path to snapserver.php on the remote host, and local backup file name.');
            $sci=new ClaSnapClient();
            $sci->BDB($argv[2],$argv[3],$argv[4],$argv[5]);    
            break;       
        case 'SUP':
            if($argc<4)
                throw new Exception('The SUP command requires 3 arguments: public key file base, target host IP address or name, and path to snapserver.php on the remote host.');
            $sci=new ClaSnapClient();
            $keyfilespec=$argv[2];
            $targetHost=$argv[3];
            $snappath=$argv[4];
            $sci->SUP($keyfilespec,$targetHost,$snappath);
            break;
        default:
            throw new Exception('Invalid command.');
            break;
    }
    
}
?>
