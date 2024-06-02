## Current thinking about format implementation

There is a cursor concept in suricata, i need to implement the notion of order of matches, i cannot just say match pattern1 and pattern2 and not pattern3 all in discord, 
i need to put an order.

```ru
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outdated Firefox on Windows"; content:"User-Agent|3A| Mozilla/5.0 |28|Windows|3B| "; content:"Firefox/3."; distance:0; content:!"Firefox/3.6.13"; distance:-10; sid:9000000; rev:1;)
```
So i came with theses two solutions:

This one is more compact:

```yml
detection:
    http.user_agent: "User-Agent|3A| Mozilla/5.0 |28|Windows|3B|"
    http.user_agent|dist0: "Firefox/3."
    http.user_agent|dist-10|not: "Firefox/3.6.13"
```

This one is bigger but more understandable.

```yml
detection:
    - http.user_agent: "User-Agent|3A| Mozilla/5.0 |28|Windows|3B|"
    - http.user_agent: "Firefox/3."
      dist: 0
    - http.user_agent|not: "Firefox/3.6.13"
      dist: -10

```