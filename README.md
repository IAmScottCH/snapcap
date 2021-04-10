# SnapCap

*Version 2.0*

SnapCap is a simple application remote backup suite of utilities.  The first version was a bash script that ran on the server where the application to back up was deployed.  I took its operations and turned them into a very simple protocol for client/server operation.

There's nothing fancy about what SnapCap really does:
- it produces a MySQL/MariaDB database dump into a file
- it produces a tar-gzip of the files

SnapCap encrypts backups server-side with an application public key, which the client-side can decrypt with the private key.  Protocol commands exchanged between the client and server are also encrypted.

For initial setup, SnapCap is packaged with a setup public key.  A client with the setup private key can send a SUP command with an application public key as an argument, and the server will store the application public key and blank its copy of the setup public key (so SUP can't be issued again).

The initial release of version 2.0 only has a PHP client/server pair, but I plan on adding clients/servers in other languages/communication mechanisms as the needs arise in my own work.  Thus, while the PHP session is used server side for what little state needs to be maintained, that is only an envelope.  An independent session ID is generated by SnapCap for its own use as the truly significant session ID for its operations.  So, when I refer to the session ID (or SID), I'm talking about SnapCap's session ID, not PHP's (or any other platform-specific one).

The protocol commands the client can send follow.  arguments in [] are optional and those in <> are required.  Possible server responses are also listed after each client command.  NOTE: The server may not respond for internal errors or for things that indicate a stupid client (and possibly an attack attempt).  If it responds in-protocol to an error, it will send back an ERR response, as noted below.

```
HLO: hello -- used to setup a session.  Encrypted with setup key if SUP has not been issued yet, else encrypted with application key.
    HLO <SID> Encrypted with setup key if SUP has not been issued yet, else encrypted with application key.
SUP <SID> <application public key>: finish setting yourself up with the provided application key.  Encrypted with setup key.
    SUP <SID>
BDB <SID> <mode> [more args]: backup the database.  <mode> is how to go about it.  [more args] is other possible arguments, depending on mode.  The only mode currently supported is "wordpress".  In wordpress mode, no other arguments are needed: the SnapCap server assumes it is installed as a WordPress plugin and finds and loads wp-config.php to get the database parameters.
	BDB <checksum>: checksum is the MD5 checksum of the encrypted DB dump.
BFL <SID> <mode> [more args]: backup the files.  <mode> is how to go about it.  [more args] is other possible arguments, depending on mode.  The only mode currently supported is "wordpress".   In wordpress mode, no other arguments are needed: the SnapCap server assumes it should backup all files in and under the standard directory location for wp-config.php.
	BFL <checksum>: checksum is the MD5 checksum of the encrypted tar-gzip file archived.
SND <SID>: send the last backup file generated.  This must follow either a BDB or a BFL in the same session. 
    The server responds by dumping the encrypted backup data file down to the client.  After the data is received, the client is expected to generate its own MD5 sum of the downloaded data and compare it to the one previously returned by the server in response to the BDB or BFL commands.  Thus, even if the server fails to successfully complete the dump back the client, the client will detect it via a checksum mismatch.
BYE <SID>: close the session.
	BYE <SID>: The server "forgets" the session, so the SID may not be used for any more commands.
```

Additional possible server response:

`ERR <msg>: error.  Message is a hint as to what went wrong.  Encrypted with whatever key is currently in use.`

A plain text temp file is utilized during BDB and BFL on the server, which it deletes immediately after encrypting it.  The encrypted file is deleted by the BYE command processing, if the server "remembers" having one in the session.  It forgets having a file in the session immediately after deleting it.  It's not really a big deal if the file ends up lying around, since it is encrypted and the private key is needed to decrypt it.

Note that all commands from the client except HLO require the <SID> argument.  Since HLO initiates a session, the server must generate the SID.  The only responses from the server that do not have the <SID> as the data are responses to the BDB, BFL, and SND commands.  SND cannot provide any in a simple way, since it is file download, though in the future I may add a header.  BDB and BFL provide a checksum for data.  That may also change in the future to provide the SID in some way, but I doubt it.

Where the SID is provided the client or server may verify it is the correct SID (and the server really must).

*NOTE: SnapCap must be able to create subdirectory (and files in it) under its own directory.  Alternatively, you may pre-create a subdirectory called "sctmp" that it has r/w permissions to under its directory.  By that, I of course mean the user under which SnapCap is executing must effectively have those abilities/permissions.*

##Note on format of encrypted data
Encrypted data is encrypted in 400 byte chunks, due to how PHP's implementation of openssl_private_encrypt() (and openssl_public_encrypt(), for that matter) works.  I know that is specific to a run-time/platform, but it is the first I wrote version 2.0 for, so decided to just go with it.  Anyway, the chunks are encrypted and then base64 encoded.  Any message, therefore, greater than 400 bytes will have multiple chunks.  The chunks are separated by commas, since a comma is not a valid character in a base64 encoding.  Then the whole resulting blob is base64 encoded again (to get commas out of the mix for transit). Thus, to decrypt a message of more than one chunk, you first need to decrypt each chunk up to but not including the next comma, and reassemble the whole thing.

That's all actually harder to explain than to do.  See encryptString(), decryptString(), and decryptFile() in snapclient.php for examples.  Also encryptFile() in snapserver.php.

##Note on PHP implementation##

I kind of regret it, but the PHP server implementation of the protocol expects the command arguments as POST vars.  They keys are:
```
sc_appkey: application key
sc_session: the SnapCap session ID
sc_command: the SnapCap command
sc_mode: the mode argument for the BFL and BDB commands.
```
Some day I will refactor it so that it only recieves one POST var, which is the full proper protocol command string with arguments.
