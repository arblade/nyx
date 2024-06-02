import re
from typing import List, Optional


class NyxRuleField:
    def __init__(self, content: str) -> None:
        self.content = content

    def convert(self):
        return self.content


class NyxRuleTitle(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)


class NyxRuleDescription(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)

    def convert(self):
        return super().convert().replace(",", " ")


class NyxRuleId(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)

    def convert(self):
        return f"sid:{self.content}"


class NyxRuleLevel(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)

    def convert(self):
        return f"level {self.content}"


class NyxRuleAction(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)


class NyxRuleDetectionField:
    def __init__(
        self,
        field: str,
        value: dict,
        distance=None,
        within=None,
        depth=None,
        is_not=False,
    ) -> None:
        self.field = field
        self.value = value
        self.distance = distance
        self.within = within
        self.depth = depth
        self.is_not = is_not

    def convert(self):
        field = f"{self.field}"

        not_str = ""
        if self.is_not:  # adding not modifier
            not_str = "!"
        content = f'content:"{not_str}{self.value}"'
        modifiers = []
        if self.distance:
            modifiers.append(f"distance:{self.distance}")

        return "; ".join([field, content] + modifiers)

    @classmethod
    def from_dict(cls, field: dict):
        # as this is not ordered, we need to find the field
        distance = None
        is_not = None
        within = None
        depth = None
        print(field)
        print(field.items())
        for key, value in field.items():
            print(key)
            if re.search("[a-z_\\|-]+\\.[a-z_\\|-]+", str(key)):
                # this is it
                if "|" in key:
                    field_name = key.split("|")[0]
                    modifier = key.split("|")[1]
                    if modifier == "not":
                        is_not = True
                else:
                    field_name = key

                field_value = value
            elif key == "dist":
                distance = value

        return cls(
            field=field_name, value=field_value, distance=distance, is_not=is_not
        )


class NyxRuleCondition:
    def __init__(self, content) -> None:
        self.content = content


class NyxRuleDetection:
    def __init__(self, fields: List[NyxRuleDetectionField]) -> None:
        self.fields = fields

    def convert(self):
        return "; ".join([field.convert() for field in self.fields])

    @classmethod
    def from_dict(cls, detections: list):
        return NyxRuleDetection(
            [NyxRuleDetectionField.from_dict(field) for field in detections]
        )


class NyxRuleProtocol:
    def __init__(self, protocol: str) -> None:
        self.protocol = protocol

    def convert(self):
        return self.protocol


class NyxRuleEndpoint:
    def __init__(self, address: str = "any", port: int = "any") -> None:
        self.address = address
        self.port = port

    @classmethod
    def from_dict(cls, endpoint: dict):
        address = "any"
        source = "any"
        if "address" in endpoint.keys():
            address = endpoint["address"]
        if "port" in endpoint.keys():
            address = endpoint["port"]
        return NyxRuleEndpoint(address=address, source=source)


class NyxRuleFlow:
    def __init__(
        self,
        direction: str,
        source: Optional[NyxRuleEndpoint] = None,
        destination: Optional[NyxRuleEndpoint] = None,
    ) -> None:
        self.direction = direction
        self.source = source
        self.destination = destination

    def convert(self):
        res = ""
        if self.source:
            source_str = f"{self.source.address} {self.source.port}"
        else:
            source_str = "any any"
        if self.destination:
            destination_str = f"{self.destination.address} {self.source.port}"
        else:
            destination_str = "any any"
        return " -> ".join([source_str, destination_str])

    @classmethod
    def from_dict(self, flow: dict):
        source = None
        destination = None
        direction = flow["direction"]
        if "source" in flow.keys():
            source = NyxRuleEndpoint.from_dict(flow["source"])
        if "destination" in flow.keys():
            destination = NyxRuleEndpoint.from_dict(flow["destination"])
        return NyxRuleFlow(direction=direction, source=source, destination=destination)


class NyxRule:
    def __init__(
        self,
        title: NyxRuleTitle,
        id: NyxRuleId,
        description: NyxRuleDescription,
        level: NyxRuleLevel,
        action: NyxRuleAction,
        protocol: NyxRuleProtocol,
        flow: NyxRuleFlow,
        detection: NyxRuleDetection,
    ) -> None:
        self.title = title
        self.id = id
        self.description = description
        self.level = level
        self.protocol = protocol
        self.action = action
        self.detection = detection
        self.flow = flow

    def convert(self):
        conv_title = self.title.convert()
        conv_id = self.id.convert()
        conv_protocol = self.protocol.convert()
        conv_description = self.description.convert()
        conv_level = self.level.convert()
        conv_action = self.action.convert()
        conv_detection = self.detection.convert()
        conv_flow = self.flow.convert()

        return f'{conv_action} {conv_protocol} {conv_flow} msg("{conv_title}"); {conv_detection}; {conv_id} rev:1; metadata: description "{conv_description}"'

    @classmethod
    def from_dict(cls, dict):
        title = NyxRuleTitle(dict["title"])
        description = NyxRuleDescription(dict["description"])
        id = NyxRuleId(dict["id"])
        level = NyxRuleLevel(dict["level"])
        action = NyxRuleAction(dict["action"])
        protocol = NyxRuleProtocol(dict["protocol"])
        detection = NyxRuleDetection.from_dict(dict["detection"])
        flow = NyxRuleFlow.from_dict(dict["flow"])
        return NyxRule(
            title=title,
            description=description,
            id=id,
            level=level,
            action=action,
            protocol=protocol,
            detection=detection,
            flow=flow,
        )
