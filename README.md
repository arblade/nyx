# Nyx
A new generation network detection format inspired from Sigma.

<p align="start">
<img src="./logo.png" width="200" style="text-">
</p>

> [!NOTE] 
> This is an ongoing work (not yet alpha), there could be some incoherences between parts of the project

## Why ?

We are dealing with specific rules of different IPS/IDS, and we need to find a common basis to discharge analyst from the burden of knowing all the details of multiple IPS/IDS. A simple format, like Sigma, will allow all analysts to easily craft their own rules, which can be converted then on the IDS/IPS format of their choice.
We want this format to be extensive, as the network rules can be fine tuned to be more efficient following each IPS/IDS specificity.

## Philosophy

We don't want to be exhaustive and fully compliant with one format or another, our objective is to conceptualize network rules and remove useless complexities from analysts.

We will first focus on suricata and snort formats.

## Get Started

Watch the [format specification](./documentation/specification.md)

Go to the current issues i am struggling with on [current thinking](./thinking.md)

## Want a taste ?

A baby script is available :

```bash
pip install pynyx
nyx your_rule.yaml
```
You can check that the rule is suricata validated by copying your rule to a file and running :

```bash
./scripts/test_alert_suricata.sh ./tests/test.rules # replace here with your file with your suricata alert inside
```


