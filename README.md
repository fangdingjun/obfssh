obfssh
=====

obfssh is wrapper for ssh protocol, use AES or RC4 to encrypt the transport data,
ssh is a good designed protocol and with the good encryption, but the protocol has a especially figerprint,
the firewall can easily identify the protocol and block it or QOS it, especial when we use its port forward function to escape from the state censorship.

obfssh encrypt the ssh protocol and hide the figerprint, the firewall can not identify the protocol.

We borrow the idea from https://github.com/brl/obfuscated-openssh, but not compatible with it,
beause the limitions of golang ssh library.




server usage example
====================

	import "github.com/fangdingjun/obfssh"
	import "golang.org/x/crypto/ssh"

	// key for encryption
	obfs_key := "some keyword"

	// encrypt method
	obfs_method := "rc4"

	config := &ssh.ServerConfig{
		// add ssh server configure here
		// for example auth method, cipher, MAC
		...
	}

	l, err := net.Listen(":2022")
	c, err := l.Accept()

	sc, err := obfssh.NewServer(c, config, obfs_method, obfs_key)

	sc.Run()


client usage example
====================


	import "github.com/fangdingjun/obfssh"
	import "golang.org/x/crypto/ssh"

	addr := "localhost:2022"

	// key for encryption
	obfs_key := "some keyword"

	// encrypt method
	obfs_method := "rc4"

	config := ssh.ClientConfig{
		// add ssh client config here
		// for example auth method
		...
	}

	c, err := net.Dial("tcp", addr)

	// create connection
	client, err := obfssh.NewClient(c, config, addr, obfs_method, obfs_key)

	// local to remote port forward
	client.AddLocalForward(":2234:10.0.0.1:3221")

	// remote to local port forward
	client.AddRemoteForward(":2234:10.2.0.1:3221")

	// dynamic port forward
	client.AddDynamicForward(":4321")

	// wait to be done
	client.Run()


limitions
========
 
 now, the server side only implements the port forward function, start shell or execute a command is not suppurted

 if set the `obfs_method` to `none`, obfssh is compatible with standard ssh server/client(OpenSSH)

License
=======
 
 GPLv3, see LICENSE file details
