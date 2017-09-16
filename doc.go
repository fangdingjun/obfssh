package obfssh

/*
Package obfssh is wrapper for ssh protocol, support connect to server via TLS


server usage example

	import "github.com/fangdingjun/obfssh"
	import "golang.org/x/crypto/ssh"

	config := &ssh.ServerConfig{
		// add ssh server configure here
		// for example auth method, cipher, MAC
		...
	}

	var l net.Listener
	var err error
	if useTLS {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		l, err = tls.Listen("tcp", ":2022", &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	}else{
		l, err = net.Listen(":2022")
	}
	defer l.Close()
	for{
		c, err := l.Accept()
		go func(c net.Conn){
			defer c.Close()
			sc, err := obfssh.NewServer(c, config, &obfssh.Conf{})
			sc.Run()
		}(c)
	}


client usage example

	import "github.com/fangdingjun/obfssh"
	import "golang.org/x/crypto/ssh"

	addr := "localhost:2022"

	config := ssh.ClientConfig{
		// add ssh client config here
		// for example auth method
		...
	}

	var c net.Conn
	var err error

	if useTLS{
		c, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName: "localhost",
			InsecureSkipVerify: true,
		})
	}else{
		c, err = net.Dial("tcp", addr)
	}

	// create connection
	client, err := obfssh.NewClient(c, config, addr, &obfssh.Conf{})

	// local to remote port forward
	client.AddLocalForward(":2234:10.0.0.1:3221")

	// remote to local port forward
	client.AddRemoteForward(":2234:10.2.0.1:3221")

	// dynamic port forward
	client.AddDynamicForward(":4321")

	// wait to be done
	client.Run()


*/
