obfssh\_client
=============

this is obfssh\_client example


usage
=====

run server

    go get github.com/fangdingjun/obfssh/obfssh_server
    
    cp $GOPATH/src/github.com/fangdingjun/obfssh/obfssh_server/config_example.yaml server_config.yaml

    vim server_config.yaml

    ssh-keygen -f ssh_host_rsa_key -t rsa

    $GOPATH/bin/obfssh_server -c server_config.yaml


run client

    go get github.com/fangdingjun/obfssh/obfssh_client

    $GOPATH/bin/obfssh_client -N -D :1234 -obfs_key some_keyworld -obfs_method rc4 -p 2022 -l user2 -pw user2 localhost
    
or
    
    cp $GOPATH/src/github.com/fangdingjun/obfssh/obfssh_client/config_example.yaml client_config.yaml

    vim client_config.yaml

    $GOPATH/bin/obfssh_client -f client_config.yaml
