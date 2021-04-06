<?php

/*
 * MOST IMPORTANT NOTE: Exception messages must be read in a sultry, female, robot voice.  Thank you.
 */

DEFINE('SC_SETUP_KEY','/home/scott/.ssh/scsetup');

class ClaSnapClient
{
    private $scsetupkey;
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
       
        $this->scsetupkey=file_get_contents(SC_SETUP_KEY);
        if($this->scsetupkey===false)
            throw new Exception('Setup key file read failed.');
    }
    
    public function SUP($keyfile,$host,$snappath)
    {
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
            throw new Exception('I could not read the contents of the application key file.');
        }
        
        //TODO: HLO
        $args=array('sc_appkey',$appkey);
    echo "IIII: Executing command SUP\n";
        $this->execCommand('SUP',$url,$args);
    echo "IIII: Command execution completed.\n";
        
        //TODO: BYE
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
       
        if(!is_null($this->scsid))
            $postArgs['sc_session']=$this->scsid;
        $postArgs['sc_command']=$cmd;
        $opts=array
        (
            CURLOPT_RETURNTRANSFER=>1,          // get the response as the return value
            CURLOPT_POST=>1,
            CURLOPT_USERAGENT=>'snapclient',
            CURLOPT_FOLLOWLOCATION => true,     // follow redirects
            CURLOPT_SSL_VERIFYHOST => 0,        // don't verify certs and stuff.
            CURLOPT_SSL_VERIFYPEER => false,    // ditto
            CURLOPT_TIMEOUT=>$timeout,  
            CURLOPT_POSTFIELDS=>$postArgs,
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
