A clipboard web server, support multiple mothod.

Eg: 

paste:
```
curl -X POST -d "Hello from curl!" http://ip:port/paste
```

copy:
```
curl http://ip:port/copy
```

And support web page to use:
`http://ip:port/web/paste` to paste and `http://ip:port/web/copy` to automatically copy.
