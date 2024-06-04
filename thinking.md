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
    - ttl: 10 
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
    ttl: 10 
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

## Mutliple matches in a flow

I just saw that flowbits serve to make a rule match when a previous packet match inside a flow (a flow is a group of packets matched by same protocl client port/ip and server port/ip)

```ru
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET EXPLOIT VNC Possible Vulnerable Server Response"; flow:established; dsize:12; content:"RFB 003.00"; depth:11; flowbits:noalert; flowbits:set,BSposs.vuln.vnc.svr; reference:url,www.realvnc.com/docs/rfbproto.pdf; reference:cve,2006-2369; classtype:misc-activity; sid:2002912; rev:7; metadata:created_at 2010_07_30, updated_at 2019_07_26;)

```
```ru
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT VNC Client response"; flowbits:isset,BSposs.vuln.vnc.svr; flow:established; dsize:12; content:"RFB 003.0"; depth:9; flowbits:noalert; flowbits:set,BSis.vnc.setup; reference:url,www.realvnc.com/docs/rfbproto.pdf; classtype:misc-activity; sid:2002913; rev:7; metadata:created_at 2010_07_30, updated_at 2019_07_26;)

```

Our format has to take this into account in some way, like a correlation rule in sigma.

## Classtype use for level ?

CLasstype is used for setting priority to alerts, which is exactly what the sigma level thing is made for, so I think about setting classtype as level 