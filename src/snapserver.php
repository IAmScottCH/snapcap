<?php 

/*
 * MOST IMPORTANT NOTE: Exception messages must be read in a sultry, female, robot voice.  Thank you.
 */
DEFINE('SC_APP_KEY_FILE','sc_app_key.pub');
DEFINE('SC_SUP_KEY_FILE','sc_sup_key.pub');
class ClaSnapServer
{
  private $setupPubKey;
  private $appPubKey;
  private $currentCommand;
  private $postVars;
  private $scsid;
  private $sessionData;
  private $setupMode;
  // assumes argstring is encrypted and then base64-encoded
  private function decryptArgument($argstring)
  {
      $estr=base64_decode($argstring);
      $echunks=explode(',',$estr);
      $rstr='';
      $ekey=($this->setupMode?$this->setupPubKey:$this->appPubKey);
      foreach($echunks as $chunk)
      {
          $dchunk=base64_decode($chunk);
          $pchunk='';
          if(!openssl_public_decrypt($dchunk,$pchunk,$ekey))
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
          if(!openssl_public_encrypt($chunk,$echunk,$ekey))
              throw new Exception("I could not encrypt a chunk of your string");
          $echunks[]=base64_encode($echunk);
      }
      $estring=implode($echunks,',');
      return base64_encode($estring);
  }
  public function __construct()
  {
     //TODO: after setup, empty the file such that the remote client can't
     //      do setup again.
     $this->setupMode=true;
     $this->setupPubKey=file_get_contents(SC_SUP_KEY_FILE);
     if($this->setupPubKey===false)
         throw new Exception('I could not read the setup key file.');
     if(strlen($this->setupPubKey)==0)
     {
         $this->setupPubKey=null;
         $this->appPubKey=openssl_pkey_get_public('file://' . SC_APP_KEY_FILE);
         if($this->appPubKey===false)
             throw new Exception('There are no keys available.  You will need to call a technician to help me.');
         $this->setupMode=false;
     }
     else
     {
         $this->appPubKey=null;
         $this->setupPubKey=openssl_pkey_get_public($this->setupPubKey);
         if($this->setupPubKey===false)
             throw new Exception('I could not parse the setup key.');
         $this->setupMode=true;    
     }
     $this->currentCommand='NOP';
     $this->scsid=null;
     $this->sessionData=array();
     $this->processPostVars();
  }
  
  public function identifyCommand()
  {
    $ec=trim($this->postVars['command']);
    $pc=$this->decryptArgument($ec);
    $c=strtoupper(trim($pc));   
    switch($c)
    {
        case 'SUP':
            echo 'COMMAND IS SUP';
            break;
            
        default:
            throw new Exception("Command $c not recognized");
            break;
    }
    // It's trimmed and uppered and a good command.
    $this->currentCommand=$c;
  }
  
  public function setSession()
  {
      if(!isset($this->postVars['session']))
          throw new Exception('You must process POST vars before a session may be established.');

      if(session_status()===PHP_SESSION_NONE)
      {
          session_start();
      }
      
      if(is_null($this->postVars['session']))
      {
          $this->scsid='sc_' . bin2hex(random_bytes(10));
          $_SESSION[$this->scsid]=array();
      }
      else
          $this->scsid=$this->postVars['session'];
      
      if(!isset($_SESSION[$this->scsid]))
          throw new Exception('Session initialization has failed.');
      
      $this->sessionData=$_SESSION[$this->scsid];
      
  }
  // NOTE: this is called by the constructor, so you shouldn't have to.
  public function processPostVars()
  {
      $this->postVars=array
      (
          'command'=>'',
          'session'=>null,
      );
      if(isset($_POST['sc_session']))
          $this->postVars['session']=$_POST['sc_session'];
      if(isset($_POST['sc_command']))
          $this->postVars['command']=$_POST['sc_command'];
      
      $this->identifyCommand();    
  }
    
  public function remoteSetup()
  {
      
  }
  public function doCommand()
  {
      switch($this->currentCommand)
      {
          case 'SUP':
              $this->remoteSetup();
              break;
          default:
              throw new Exception('Unrecognized command.');
              break;
      }
  }
};

$ssi=new ClaSnapServer();

$ssi->doCommand();

?>
