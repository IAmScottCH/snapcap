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
  //private $sessionData;
  private $setupMode;
  const BLKSIZE=400;
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
      $BLKSIZE=ClaSnapServer::BLKSIZE;
      
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
     //$this->sessionData=array();
     $this->processPostVars();
  }
  
  public function identifyCommand()
  {
    $ec=trim($this->postVars['command']);
    $pc=$this->decryptArgument($ec);
    $c=strtoupper(trim($pc));   
    switch($c)
    {
        case 'BYE':
        case 'HLO':
        case 'SUP':
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
          if(!is_null($this->postVars['session']))
           throw new Exception('You must process POST vars before a session may be established.');

      if(session_status()===PHP_SESSION_NONE)
      {
          session_start();
      }
      
      // if the client did not send a session id, then create a new session.
      if(is_null($this->postVars['session']))
      {
          if($this->currentCommand!=='HLO')  // null sessions from the client are only valid for HLO commands.
              throw new Exception("Client did not provide a session id, but command was not HLO!");
          $this->scsid='sc_' . bin2hex(random_bytes(10));
          $_SESSION[$this->scsid]=array();
      
      }
      else
      {
          $ec=trim($this->postVars['session']);
          $pc=$this->decryptArgument($ec);
          
          $this->scsid=$pc;
      }
      
      if(!isset($_SESSION[$this->scsid])) // will occur if the client sends the "wrong" session id.
          throw new Exception('Session initialization has failed for session id ' . $this->scsid);
      
      //$this->sessionData=$_SESSION[$this->scsid];
      
      
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
      $this->setSession();
  }
    
  public function remoteSetup()
  {

      if(!isset($_POST['sc_appkey']))
          throw new Exception("Client did not supply an application key for the SUP command");
      $this->postVars['sc_appkey']=$_POST['sc_appkey'];
      $pkey=$this->decryptArgument($this->postVars['sc_appkey']);
      $this->appPubKey=openssl_pkey_get_public($pkey);
      if($this->setupPubKey===false)
          throw new Exception('I could not parse the application key provided by the client.');
      file_put_contents(SC_APP_KEY_FILE,$pkey);   
      file_put_contents(SC_SUP_KEY_FILE,'');
      $this->setupMode=false;
      $this->emitResponse('SUP',$this->scsid);
  }
  public function HLO()
  {
      $this->emitResponse('HLO',$this->scsid);
          
  }
  public function BYE()
  {
      $this->emitResponse('BYE',$this->scsid);
      
  }
  
  // return command string and data as:
  //   base64 encoded(encrypted(cmd)),base64 encoded(encrypted(data))
  //   if $data is null, then it is not encrypted and the response does not 
  //   include the comma and encrypted data part.  Really, I never use that.
  public function emitResponse($cmd,$data)
  {
      $ekey=($this->setupMode?$this->setupPubKey:$this->appPubKey);
      $ecmd=$this->encryptString($cmd,$ekey);
      if(is_null($data))
      {
          echo $ecmd;
          return;
      }
      $edata=$this->encryptString($data,$ekey);
      echo $ecmd . ',' . $edata;
  }
  public function doCommand()
  {
      switch($this->currentCommand)
      {
          case 'BYE':
              $this->BYE();
              break;
          case 'HLO':
              $this->HLO();
              break;
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
