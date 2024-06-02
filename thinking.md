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

Finally, this one is more compact but still clear

> I assume there is always an AND operator playing between matches, i'm maybe mistaking

```yml
detection:
    http.user_agent: 
      - content: "User-Agent|3A| Mozilla/5.0 |28|Windows|3B|"
      - content: "Firefox/3."
        dist: 0
      - content|not: "Firefox/3.6.13"
        dist: -10

```
this one is minimalist but less clear
```yml
detection:
    http.user_agent: 
      - "User-Agent|3A| Mozilla/5.0 |28|Windows|3B|"
      - "Firefox/3.":
        dist: 0
      - "!Firefox/3.6.13":
        dist: -10

```

## Test of rules

We have the same issue than in sigma, we need targeted logs to test rules.
I like what hayabusa is cooking, maybe we can do the same

Something like :

```yml
test:
    http.user_agent: "User-Agent (Mozilla/5.0 ;Windows))"
```

which can be then played to confirm rule is working.