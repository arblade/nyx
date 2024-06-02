if [ -z "$1" ]; then
  echo "Usage: $0 <your rules files>"
  exit 1
fi
RULES_FILE="$1"
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
docker run --rm -v $PARENT_DIR/docker/config/suricata.yml:/etc/suricata/suricata.yaml -v $RULES_FILE:/etc/suricata/rules/myrules.rules jasonish/suricata:latest suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/myrules.rules
