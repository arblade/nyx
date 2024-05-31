# Nyx specification

## Structure


```
title
ref [optional]
description
id
level
action
protocols
  {protocol:value}

detection
  {field:value}

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

Here we have a dilemna.

Option 1 : A unique identifier as an integer (it sucks as users have to check if their integer is already existing, btu this is snort/suricata specification for sid)

Option 2 : An uuid, and in the process sid will be automaticly generated (user can provide a range of sids to process from). Uuid will then be placed in metadata field.

