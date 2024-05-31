# Nyx specification

## Structure


```
title
ref [optional]
description
id
level
action [optional]

protocols
  {osi_layer:protocol}

detection
  {selection_name}
    {field:value}
  condition

flow [optional]
  direction
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


### Protocols

A mapping of osi layers and protocols targeted, example here:

```yaml
protocols:
    ip: tcp
    application: http
```

### Detection

Fields values targeted, organised in selections which are handled with condition field.

```yml
detection:
    selection:
        tcp.flags:
            - S
            - 12
        tcp.window: 55808
    condition: selection
```

### Flow

Network directions targeted

```yaml
flow:
  direction: out
  source: 
      address: $EXTERNAL_NET
      port: any
  destination:
      address: $HOME_NET
      port: any
```