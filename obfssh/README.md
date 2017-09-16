obfssh\_client
=============

this is obfssh example


usage
=====

run server

    go get github.com/fangdingjun/obfssh/obfsshd
    
    cp $GOPATH/src/github.com/fangdingjun/obfssh/obfsshd/config_example.yaml server_config.yaml

    vim server_config.yaml

    ssh-keygen -f ssh_host_rsa_key -t rsa

    $GOPATH/bin/obfsshd -c server_config.yaml


run client

    go get github.com/fangdingjun/obfssh/obfssh

    $GOPATH/bin/obfssh -N -D :1234 -p 2022 -l user2 -pw user2 localhost
    
or
    
    cp $GOPATH/src/github.com/fangdingjun/obfssh/obfssh/config_example.yaml client_config.yaml

    vim client_config.yaml

    $GOPATH/bin/obfssh -f client_config.yaml
