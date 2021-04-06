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
  public function __construct()
  {
     //TODO: move the pub key to a file, and after setup, empty the file such that the remote client can't
     //      do setup again.
     $this->setupPubKey=file_get_contents(SC_SUP_KEY_FILE);
     if($this->setupPubKey===false)
         throw new Exception('I could not read the setup key file.');
     if(strlen($this->setupPubKey)==0)
     {
         $this->setupPubKey=null;
         $this->appPubKey=file_get_content(SC_APP_KEY_FILE);
         if($this->appPubKey===false)
             throw new Exception('There are no keys available.  You will need to call a technician to help me.');
     }
     else 
         $this->appPubKey=null;
     $this->currentCommand='NOP';
     $this->scsid=null;
     $this->sessionData=array();
     $this->processPostVars();
  }
  
  public function identifyCommand()
  {
    $c=strtoupper(trim($this->postVars['command']));   
    switch($c)
    {
        case 'SUP':
            echo 'EXECUTE SUP HERE';
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
