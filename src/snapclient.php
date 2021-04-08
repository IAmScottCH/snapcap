<?php

/*
 * MOST IMPORTANT NOTE: Exception messages must be read in a sultry, female, robot voice.  Thank you.
 */

DEFINE('SC_SETUP_KEY','/home/scott/.ssh/scsetup.pem');
DEFINE('SC_SETUP_PUB_KEY','/home/scott/.ssh/scsetup.pub');

class ClaSnapClient
{
    private $scsetupkey;  // the setup key
    private $scsetuppub;  // the pub setup key, for testing
    private $hostkey;     // current host key
    private $currentHost;
    private $scsid;
    private $sessionData;
    private $setupMode; // convenient!
    
    public function __construct()
    {
        $this->setupMode=false;
        $this->sessionData=array();
        $this->scsid=null;
        $this->currentHost='';
        $this->hostkey=null;
       
        $this->scsetupkey=openssl_pkey_get_private('file://' . SC_SETUP_KEY);
        if($this->scsetupkey===false)
            throw new Exception('I could not parse the setup key.');
        $this->scsetuppub=openssl_pkey_get_public('file://' . SC_SETUP_PUB_KEY);
        if($this->scsetuppub===false)
            throw new Exception('I could not parse the setup public key.');
                
    }
    
    public function SUP($keyfile,$host,$snappath)
    {
        $this->setupMode=true;
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
        
        //TODO: HLO
        $args=array('sc_appkey'=>$appkey);
    echo "IIII: Executing command SUP\n";
        $this->execCommand('SUP',$url,$args);
    echo "IIII: Command execution completed.\n";
        
        //TODO: BYE
        $this->setupMode=false;
    }
    
    // decrypt $argstring with the imported key $ekey
    // see encryptString for the way the message is structured in chunks and encoded.
    private function decryptString($argstring,$ekey)
    {
        $estr=base64_decode($argstring);
        $echunks=explode(',',$estr);
        $rstr='';
        foreach($echunks as $chunk)
        {
            
            $pchunk='';
            if(!openssl_public_decrypt(base64_decode($chunk),$pchunk,$ekey))
                throw new Exception('I could not decrypt one of the client chunks.');
            $rstr.=$pchunk;
        }
        return $rstr;
        
    }
    // have to encrypt in chunks
    // assumes a 4096 bit key
    // so can encrypt in 4096/8-11 = 501 byte chunks.  will use blocks of 400 bytes.
    // output will be a base64 encoded string of base64 encoded chunks separated by ','
    private function encryptString($pstr,$ekey)
    {
        $BLKSIZE=400;
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
    // $timeout is in seconds.  It's provided as an optional value so that when a backup command is run, it 
    // can be extended to 300 seconds or more.
    // $postArgs is passed as-is as the cURL post fields array, but with the following added in:
    //    sc_session => current scsid
    //    sc_command => command provided in $cmd
    private function execCommand($cmd,$url,$postArgs,$timeout=20)
    {
        $ch=curl_init($url);
        if($ch===false)
            throw new Exception('Error initializing cURL');
       
            
        $ekey=($this->setupMode?$this->scsetupkey:$this->hostkey);
        if(is_null($ekey))
            throw new Exception('Encryption key is null.');
        
        $estr='';
        if(!is_null($this->scsid))
            $postArgs['sc_session']=$this->scsid;
        
        $postArgs['sc_command']=$cmd;
        $pargs=array();
        foreach($postArgs as $k=>$v)
        {
            $pargs[$k]=$this->encryptString($v,$ekey);
            //$ostring=$this->decryptString($pargs[$k],$this->scsetuppub); // if you want verify enc/dec.
        }
        $opts=array
        (
            CURLOPT_RETURNTRANSFER=>1,          // get the response as the return value
            CURLOPT_POST=>1,
            CURLOPT_USERAGENT=>'snapclient',
            CURLOPT_FOLLOWLOCATION => true,     // follow redirects
            CURLOPT_SSL_VERIFYHOST => 0,        // don't verify certs and stuff.
            CURLOPT_SSL_VERIFYPEER => false,    // ditto
            CURLOPT_TIMEOUT=>$timeout,  
            CURLOPT_POSTFIELDS=>$pargs,
        );    
            
        curl_setopt_array($ch,$opts);
        
        $rcon=curl_exec($ch); 
        $emsg=curl_error($ch);
   print_r($rcon); echo "\n"; print_r($emsg); echo "\n";
            
        curl_close($ch);
        
    }
};

// command line mode operation
if(defined('STDIN'))
{
    $sci=new ClaSnapClient();
    if($argc<2)
        throw new Exception('Please enter a command with your request.');
    $command=strtoupper(trim($argv[1]));
    switch($command)
    {
        case 'SUP':
            if($argc<4)
                throw new Exception('The SUP command requires 3 arguments: public key file spec, target host IP address or name, and path to snapserver.php on the remote host.');
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
