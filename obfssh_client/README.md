obfssh\_client
=============

this is obfssh\_client example


usage
=====

run server

    go get github.com/fangdingjun/obfssh/obfssh_server
    
    cp $GOPATH/src/github.com/fangdingjun/obfssh/obfssh_server/config_example.yaml config.yaml

    vim config.yaml

    ssh-keygen -f ssh_host_rsa_key -t rsa

    $GOPATH/bin/obfssh_server -c config.yaml


run client

    go get github.com/fangdingjun/obfssh/obfssh_client

    $GOPATH/bin/obfssh_client -N -D :1234 -obfs_key some_keyworld -obfs_method rc4 -p 2022 -l user2 -pw user2 localhost

    this will create a socks proxy on :1234
