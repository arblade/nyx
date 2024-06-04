# Nyx specification

## Structure


```
title
ref [optional]
description
id
level
action
protocol 

detection
    {keyword_field:value} [optional]
    protocol_field [optional]
      {key:value}
stream [optional]
  direction [optional]
  flow [optional]
  # optional if any, any
  source [optional]
      {adress:value} [optional]
      {port: value} [optional]
  destination [optional]
      {adress:value} [optional]
      {port: value} [optional]
```

## Components

### Title

A brief title to summarize the newtork detection

### Id

Here we have a dilemma.

Option 1: A unique identifier as an integer (it sucks as users have to check if their integer is already existing, but this is snort/suricata specification for sid).

Option2: An uuid, and in the process sid will be automatically generated (user can provide a range of sids to process from). Uuid will then be placed in metadata field.

> Collaboration will be easier with option 2, but the user can be mistaken by rule 2 

### Status (optional)

- stable
- test
- experimental
- deprecated

### Description

Description of the rule and its analysis process 

### References (optional)

Refrences for the rule

### Level

Level of the rule.
- critical
- high
- medium
- low

### Action

Usefull for ips to take action (drop packet for example)

- drop
- alert # this drops and generates alert
- pass (usefull ?)


### Protocol

The protocol targeted

```yaml
protocol: tcp
```

### Detection

Fields values targeted, organised in selections which are handled with condition field.

```yml
detection:
    http.user_agent: 
      - content: "User-Agent|3A| Mozilla/5.0 |28|Windows|3B|"
      - content: "Firefox/3."
        dist: 0
      - content|not: "Firefox/3.6.13"
        dist: -10
```

### Flow

Network directions targeted

```yaml
stream:
  flow: to_client
  direction: out
  source: 
      address: $EXTERNAL_NET
      port: any
  destination:
      address: $HOME_NET
      port: any
```

## Example

```yml
title: Outdated Firefox on Windows
id: 9000000
description: Detects outdated Firefox browsers (version 3.x except 3.6.13) on Windows.
level: high
action: alert
protocol: http

detection:
    http.user_agent: 
      - content: "User-Agent|3A| Mozilla/5.0 |28|Windows|3B|"
      - content: "Firefox/3."
        dist: 0
      - content|not: "Firefox/3.6.13"
        dist: -10
stream:
  direction: out
  flow: from_client
```