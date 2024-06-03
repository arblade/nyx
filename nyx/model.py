import re
from typing import List, Optional

from nyx.exceptions import FormatException


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


class NyxRuleDetectionProtocolFieldValue:
    def __init__(
        self,
        content: str,
        distance: int = None,
        within: int = None,
        depth: int = None,
        is_not: bool = False,
    ) -> None:
        self.content = content
        self.distance = distance
        self.within = within
        self.depth = depth
        self.is_not = is_not

    def convert(self):
        all_elems = []
        all_fields = ["distance", "within", "depth"]
        for field in all_fields:
            if self.__getattribute__(field):
                all_elems.append(f"{field}:{self.__getattribute__(field)}")
        is_not = ""
        if self.is_not:
            is_not = "!"
        return f'content:"{is_not}{self.content}";' + " " + "; ".join(all_elems)

    @classmethod
    def from_dict(cls, field_value: dict):
        base = cls(None)
        for key, value in field_value.items():
            print(key)
            if key.split("|")[0] == "content":
                if "|not" in key:
                    base.is_not = True
                base.content = value
            elif key == "dist":
                base.distance = value
            elif key == "within":
                base.within = value
            elif key == "depth":
                base.depth = value
            elif key == "is_not":
                base.is_not = value
        return base


class NyxRuleDetectionProtocolField:
    def __init__(
        self, name: str, value: List[NyxRuleDetectionProtocolFieldValue]
    ) -> None:
        self.name = name
        self.value = value

    @classmethod
    def from_dict(cls, field_name: str, field_value: dict):
        # as this is not ordered, we need to find the field

        if type(field_value) == str:
            return cls(field_name=field_name, field_value=[field_value])
        elif type(field_value) == list:
            all_field_values = []
            for value in field_value:
                field_value = NyxRuleDetectionProtocolFieldValue.from_dict(value)
                all_field_values.append(field_value)
            return cls(name=field_name, value=all_field_values)
        else:
            raise FormatException(
                f"{field_name} value is not a list or a str, please fix"
            )

    def convert(self):
        return f"{self.name}; " + " ".join([a.convert() for a in self.value])


class NyxRuleDetectionClassicField:
    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value: str = value

    def convert(self):
        return f"{self.name}:{self.value}"

    @classmethod
    def from_dict(cls, field_name: str, field_value: dict):
        # as this is not ordered, we need to find the field

        return cls(name=field_name, value=field_value)


class NyxRuleDetection:
    def __init__(
        self, fields: List[NyxRuleDetectionClassicField | NyxRuleDetectionProtocolField]
    ) -> None:
        self.fields = fields

    def convert(self):
        return "; ".join([field.convert() for field in self.fields])

    @classmethod
    def from_dict(cls, detections: dict):
        all_fields = []
        print(f"{detections=}")
        for field_name, field_value in detections.items():
            print(field_name)
            if not re.search(
                "[a-z_\\|-]+\\.[a-z_\\|-]+", str(field_name)
            ):  # we here on a classic keyword
                all_fields.append(
                    NyxRuleDetectionClassicField.from_dict(
                        field_name=field_name, field_value=field_value
                    )
                )
            else:  # we are on a protocol field
                print("passing here")
                all_fields.append(
                    NyxRuleDetectionProtocolField.from_dict(
                        field_name=field_name, field_value=field_value
                    )
                )

        return cls(all_fields)


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

        return f'{conv_action} {conv_protocol} {conv_flow} (msg:"{conv_title}"; {conv_detection}; {conv_id}; rev:1; metadata: description "{conv_description}";)'

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
