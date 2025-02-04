# Intro
simple tool to send multiple requests/responses to AIRS API and retrieve reports

# Preparation
in shell export the variable corresponding to `x-pan-token`
```
export aipantoken=k...w
```

you can also export default profile
```
export aiprofilename=profile-1
```

# chats / llm interactions
The tool loads `chat_basic.py` file which is included in the repo.

It also attempts to load `chats_extra.py` which is not included in the repo

# run it
If you provide no parameters it will call async api and use all the chats
```
./airs.py
```
you can force the sync api for all the chats
```
./airs.py --sync
```

and run it for single chat and which will also then use sync api
```
./airs.py --chat chat2
```

# specifc profile
you can temporarily use a different profile for (specific) chats
```
./airs_api.py --profile-name profile-2
```
or for specifc one
```
./airs_api.py --profile-name profile-2 --chat chat6
```


# scan and report
you can retrieve individual scan
```
./airs_api.py --scan-id ab222163-...
```

or report
 ```
 ./airs_api.py --report-id Rab222163-...
 ```
