obfsshd
=============

this is obfsshd example


usage
=====

run server

    go get github.com/fangdingjun/obfssh/obfsshd
    
    cp $GOPATH/src/github.com/fangdingjun/obfssh/obfsshd/config_example.yaml config.yaml

    vim config.yaml

    ssh-keygen -f ssh_host_rsa_key -t rsa

    $GOPATH/bin/obfsshd -c config.yaml


run client

    go get github.com/fangdingjun/obfssh/obfssh

    $GOPATH/bin/obfssh -N -D :1234 -p 2022 -l user2 -pw user2 localhost

    this will create a socks proxy on :1234
