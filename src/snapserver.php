<?php 

/*
 * MOST IMPORTANT NOTE: Exception messages must be read in a sultry, female, robot voice.  Thank you.
 */


DEFINE('SC_APP_KEY_FILE','sc_app_key.pub');
DEFINE('SC_SUP_KEY_FILE','sc_sup_key.pub');
DEFINE('SC_LONG_TIME',600); // seconds. 10 minutes.  
DEFINE('SC_TEMP_DIR',__DIR__ . DIRECTORY_SEPARATOR . "sctmp");
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
          {
              header("HTTP/1.0 500 DA failed");
              throw new Exception('I could not decrypt one of the client chunks.');
          }
          $rstr.=$pchunk;
      }
      return $rstr;
  }
  private function encryptFile($srcfile,$tarfile,$ekey)
  {
      $BLKSIZE=ClaSnapServer::BLKSIZE;
      
      $fsh=fopen($srcfile,"rb");
      if($fsh===false)
      {
          header("HTTP/1.0 500 Source file unreadable");
          throw new Exception("Could not open source file for encryption");
      }
      $fth=fopen($tarfile,"wb");
      if($fth===false)
      {
          fclose($fsh);
          header("HTTP/1.0 500 Target file unwritable");
          throw new Exception("Could not open target file for encryption");
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
            throw new Exception("Error encrypting file during read");
        }
        try 
        {
            $estr=$this->encryptString($pstr, $ekey);
            
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
                throw new Exception("Error encrypting file while writing separator");
            }
        }
        if(fwrite($fth,$estr)===false)
        {
            fclose($fsh);
            fclose($fth);
            header("HTTP/1.0 500 Target file write error");
            throw new Exception("Error encrypting file during write");
        }
        $fw=false;
      }
      
         
      
      fclose($fsh);
      fclose($fth);
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
          {
              header("HTTP/1.0 500 ES failed");
              throw new Exception("I could not encrypt a chunk of your string");
          }
          $echunks[]=base64_encode($echunk);
      }
      $estring=implode($echunks,',');
      return base64_encode($estring);
  }
  public function __construct()
  {
     //after setup, I will empty the SC_SUP_KEY_FILE file such that a remote client can't
     //      do setup again.  But, I will leave the file there so I have something to read,
     //      even if it is empty.  I don't know why.  Whatever.
     $this->setupMode=true;
     $this->setupPubKey=file_get_contents(SC_SUP_KEY_FILE);
     if($this->setupPubKey===false)
     {
         header("HTTP/1.0 500 SUP key unreadable");
         throw new Exception('I could not read the setup key file.');
     }
     if(strlen($this->setupPubKey)==0)
     {
         // Empty SUP key file, so I've already been set up before.  Let me try to load the application key.
         $this->setupMode=false;
         $this->setupPubKey=null;
         $this->appPubKey=openssl_pkey_get_public('file://' . SC_APP_KEY_FILE);
         if($this->appPubKey===false)
         {
            header("HTTP/1.0 500 Key ring is empty");
            throw new Exception('There are no keys available.  You will need to call a technician to help me.');
         }
     }
     else
     {
         // SUP key is not empty, so I must not have yet been successfully set up.
         $this->setupMode=true;    
         $this->appPubKey=null;
         $this->setupPubKey=openssl_pkey_get_public($this->setupPubKey);
         if($this->setupPubKey===false)
         {
            header("HTTP/1.0 500 SUP key invalid");
            throw new Exception('I could not parse the setup key.');
         }
     }
     $this->currentCommand='NOP';
     $this->scsid=null;
    
     $this->processPostVars();
  }
  
  public function identifyCommand()
  {
    $ec=trim($this->postVars['command']);
    $pc=$this->decryptArgument($ec);
    $c=strtoupper(trim($pc));   
    switch($c)
    {
        case 'BDB':
        case 'BFL':
        case 'BYE':
        case 'HLO':
        case 'SND':
        case 'SUP':
            break;
            
        default:
            header("HTTP/1.0 403 Not allowed");
            throw new Exception("Command $c not recognized");
            break;
    }
    // It's trimmed and uppered and a good command.
    $this->currentCommand=$c;
  }
  
  public function setSession()
  {
      
      if(!isset($this->postVars['session']))
      {
          if(!is_null($this->postVars['session']))
          {
            header("HTTP/1.0 500 Setup sequence is incorrect");
            throw new Exception('You must process POST vars before a session may be established.');
          }
      }

      if(session_status()===PHP_SESSION_NONE)
      {
          session_start();
      }
      
      // if the client did not send a session id, then create a new session.
      if(is_null($this->postVars['session']))
      {
          if($this->currentCommand!=='HLO')  // null sessions from the client are only valid for HLO commands.
          {
              header("HTTP/1.0 400 SC Session ID not provided");
              throw new Exception("Client did not provide a session id, but command was not HLO!");
          }
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
      {
          header("HTTP/1.0 400 Invalid Session ID");
          throw new Exception('Session initialization has failed for session id ' . $this->scsid);
      }
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
      // setupMode was set in the constructor.
      if(!$this->setupMode)
      {
          header("HTTP/1.0 403 Invalid mode");
          throw new Exception("SUP attempted after I have already been setup previously");
      }
      if(!file_exists(SC_TEMP_DIR))
      {
          if(mkdir(SC_TEMP_DIR,0770)===false)
          {
              header("HTTP/1.0 500 Could not create temp dir");
              throw new Exception("I could not create SC's temp dir during SUP");
          }
      }
      if(!isset($_POST['sc_appkey']))
          throw new Exception("Client did not supply an application key for the SUP command");
      $this->postVars['sc_appkey']=$_POST['sc_appkey'];
      $pkey=$this->decryptArgument($this->postVars['sc_appkey']);
      $this->appPubKey=openssl_pkey_get_public($pkey);
      if($this->setupPubKey===false)
      {
          header("HTTP/1.0 400 Invalid application key");
          throw new Exception('I could not parse the application key provided by the client.');
      }
      if(file_put_contents(SC_APP_KEY_FILE,$pkey)===false)
      {
          header("HTTP/1.0 500 Failed storing application key");
          throw new Exception('I could not parse the application key provided by the client.');
      }
      if(file_put_contents(SC_SUP_KEY_FILE,'')===false)
      {
          header("HTTP/1.0 500 Failed re-writing SUP key");
          throw new Exception('I could not parse the application key provided by the client.');
      }
          
      $this->setupMode=false;
      $this->emitResponse('SUP',$this->scsid);
  }
  public function HLO()
  {
      $this->emitResponse('HLO',$this->scsid);
          
  }
  public function BYE()
  {
      if(isset($_SESSION[$this->scsid]['tempfile']))
      {
          @unlink($_SESSION[$this->scsid]['tempfile']['spec']);
          unset($_SESSION[$this->scsid]['tempfile']);
      }
      $this->emitResponse('BYE',$this->scsid);
      unset($_SESSION[$this->scsid]);  // BYE means the session is over.
      
  }
  
  private function SND()
  {
     if(!isset($_SESSION[$this->scsid]['tempfile']))
     {
         $this->emitResponse('ERR',"There is no file send operation pending.");
         return;
     }
     // all the pre-condition checks are done, so now I'll set a long time limit, since I have
     // no idea in some cases how short it is on some servers.
     @set_time_limit(SC_LONG_TIME);  // I don't really care very much if this call fails.
     
     $finfo=$_SESSION[$this->scsid]['tempfile'];
     $this->emitFile($finfo['name'],$finfo['spec']);  // does a die()
   
  }
  // TODO: at least the plain text temp file should be under SnapCap's directory, I think. I can't use tmpfile(), because I 
  //       need a file name to give to mysqldump.
  private function doWordPressDBBackup()
  {
    // I get to assume I am a plugin.  So wp-config.php should be at:
    $wpspec='../../../wp-config.php';
    if(!file_exists($wpspec))
    {
        $this->emitResponse('ERR','I do not appear to be installed as a WordPress plugin.');
        return;
    }
    require($wpspec);
    
    // through all the checks, so set a long time limit.  I don't *think* the time in exec() is counted, but the
    // time spent in encrypting the file will be.
    @set_time_limit(SC_LONG_TIME);  // I don't really care very much if this call fails.
    
    // 	mysqldump -a -n --single-transaction --no-autocommit -u"$DBUSER" -p"$DBPASS" -h"$DBHOST" -P"$DBPORT" "$DBNAME" > "$DBBKSPEC"
    //  exit code is 0 on success.
    $dbtempname= 'sc_' . bin2hex(random_bytes(6));
    $dbtempspec=SC_TEMP_DIR . '/' . $dbtempname;
    $dbplainspec=SC_TEMP_DIR . '/sc_' . bin2hex(random_bytes(6));
    $cmd="mysqldump -a -n --single-transaction --no-autocommit -u'" . DB_USER . "' -p'" . DB_PASSWORD . "' -h'" . DB_HOST . "' '" . DB_NAME . "' > $dbplainspec" ;          
    $cmdout='';
    $cmdec=1;
    if(exec($cmd,$cmdout,$cmdec)===false)
    {
        $this->emitResponse('ERR',"Failed to execute DB export");
        return;
    }
    if($cmdec!=0)
    {
        $this->emitResponse('ERR',"Extraction failed with these message: " . implode("\n",$cmdout));
        return;
    }
    
    $this->encryptFile($dbplainspec,$dbtempspec,$this->appPubKey);
    unlink($dbplainspec);
    $_SESSION[$this->scsid]['tempfile']=array("name"=>$dbtempname,"spec"=>$dbtempspec);
    
    $chksum=md5_file($dbtempspec);
    $this->emitResponse('BDB',$chksum);

    
    
  }
  // TODO: at least the plain text temp file should be under SnapCap's directory, I think.  I can't use tmpfile(), because I 
  //       need a file name to give to tar.
  private function doWordPressFileBackup()
  {
    // I get to assume I am a plugin.  So wp-config.php should be at:
    $wpspec='../../../wp-config.php';
    if(!file_exists($wpspec))
    {
        $this->emitResponse('ERR','I do not appear to be installed as a WordPress plugin.');
        return;
    }
    $cwd=getcwd();
    if($cwd===false)
    {
        $this->emitResponse('ERR',"Could not get current working directory");
        return;
    }
    if(chdir('../../..')===false)  // go into wp-config.php's directory
    {
        $this->emitResponse('ERR',"Could not set working directory");
        return;
    }
    
    // through all the checks, so set a long time limit.  I don't *think* the time in exec() is counted, but the
    // time spent in encrypting the file will be.
    @set_time_limit(SC_LONG_TIME);  // I don't really care very much if this call fails.
    
    //  exit code of tar is 0 on success.
    $filtempname= 'sc_' . bin2hex(random_bytes(6));
    $filtempspec=SC_TEMP_DIR . '/' . $filtempname;
    $filplainspec=SC_TEMP_DIR . '/sc_' . bin2hex(random_bytes(6));
    
    $cmd="tar -czf '$filplainspec' .";          
    $cmdout='';
    $cmdec=1;
    if(exec($cmd,$cmdout,$cmdec)===false)
    {
        $this->emitResponse('ERR',"Failed to execute file export");
        return;
    }
    if($cmdec!=0)
    {
        $this->emitResponse('ERR',"Archiving failed with these message: " . implode("\n",$cmdout));
        return;
    }
    
    $this->encryptFile($filplainspec,$filtempspec,$this->appPubKey);
    unlink($filplainspec);
    $_SESSION[$this->scsid]['tempfile']=array("name"=>$filtempname,"spec"=>$filtempspec);
    
    $chksum=md5_file($filtempspec);
    $this->emitResponse('BFL',$chksum);

    
    
  }
  public function BFL()
  {
      if(!isset($_POST['sc_mode']))
          throw new Exception("Client did not supply a mode for the BFL command");
      $this->postVars['sc_mode']=$_POST['sc_mode'];
      $bflmode=strtolower(trim($this->decryptArgument($this->postVars['sc_mode'])));
      // Several possible modes.  The args will say which:
      // mode=>wordpress implies snapserver was installed as a plugin and should verify wp-config.php is
      // where it things it ought to be, and then backup from there down.
      // mode=m**** implies maria or mysql, and more arguments: dbname,dbuser,dbpass,dbhost,dbport
      switch($bflmode)
      {
          case 'wordpress':
              $this->doWordPressFileBackup();
              break;
          default:
              header("HTTP/1.0 400 Invalid BFL mode");
              throw new Exception('Invalid BFL mode: '. $bflmode);
              break;
      }     
  }
  public function BDB()
  {
      if(!isset($_POST['sc_mode']))
          throw new Exception("Client did not supply an mode for the BDB command");
      $this->postVars['sc_mode']=$_POST['sc_mode'];
      $bdbmode=strtolower(trim($this->decryptArgument($this->postVars['sc_mode'])));
      // Several possible modes.  The args will say which:
      // mode=>wordpress implies snapserver was installed as a plugin and should find wp-config.php
      // mode=m**** implies maria or mysql, and more arguments: dbname,dbuser,dbpass,dbhost,dbport
      switch($bdbmode)
      {
          case 'wordpress':
              $this->doWordPressDBBackup();
              break;
          default:
              header("HTTP/1.0 400 Invalid BDB  mode");
              throw new Exception('Invalid BDB mode: '. $bdbmode);
              break;
      }
  }
  
  public function emitFile($fname,$fspec)
  {
    $fsize=filesize($fspec);
    @ob_end_clean();
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'. $fname . '"');
    header('Content-Transfer-Encoding: binary');
    header('Accept-Ranges: bytes');
    
    header('Content-Length: ' . $fsize);
    
    readfile($fspec);  //If this fails, then the checksum verification at the client side will fail, so we're OK just cutting loose here.
    die();
    
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
          case 'BDB':
              $this->BDB();
              break;
          case 'BFL':
              $this->BFL();
              break;
          case 'BYE':
              $this->BYE();
              break;
          case 'HLO':
              $this->HLO();
              break;
          case 'SND':
              $this->SND();
              break;
          case 'SUP':
              $this->remoteSetup();
              break;
          default:
              header("HTTP/1.0 403 Invalid command string");
              throw new Exception('Unrecognized command.');
              break;
      }
  }
};

$ssi=new ClaSnapServer();

$ssi->doCommand();

?>
