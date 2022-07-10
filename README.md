# Utility to fetch tokens (and actually most info about connected devices) from Xiaomi CLoud

Inspired by Piotr Machowski python solution founded in https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor

## How to run 

All required parameters should be specified in command line. I.e.:

```
$ ./getXiaomiTokens -uid 4183xxxxxx -pass xxxxxxx -server xx
```

Server should be one of this : cn de ru us tw sg in i2. If server not specified cn will be used

## Output example

```
2022/07/10 02:53:39 loging
2022/07/10 02:53:44 login ok
 deviceid = 3437**************
 Token = ***60107*************e3ab94f1***
 Ip = 192.168.111.2
 Parent =  ()
 Model = cgllc.gateway.s1
 Online = true

 deviceid = 3437**************
 Token = ***60107*************e3ab94f1***
 Ip = 192.168.111.3
 Parent =  ()
 Model = cgllc.gateway.s1
 Online = true

```

## License and author

This project licensed under MIT license

Author Eugene Chertikhin
