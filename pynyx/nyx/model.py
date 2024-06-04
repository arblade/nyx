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


class NyxRuleReferences:

    def __init__(self, references: List[str]) -> None:
        if type(references) == str:
            references = [references]
        self.references = references

    def convert(self):
        return " ".join([f"reference:url,{ref}" for ref in self.references])


class NyxRuleLevel(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)

    def convert(self):
        return f"classtype:{self.content}"


class NyxRuleAction(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)


class NyxRuleDetectionProtocolFieldValue:
    KEYWORDS = [
        "dist",
        "within",
        "depth",
        "offset",
        "pcre",
        "rawbytes",
        "isdataat",
        "bsize",
        "dsize",
        "fast",
    ]
    KEYWORDS_MAPPING = {"dist": "distance", "fast": "fast_pattern"}

    def __init__(
        self,
        content: str,
        distance: int = None,
        within: int = None,
        depth: int = None,
        is_not: bool = False,
        no_case: bool = False,
    ) -> None:
        self.content = content
        self.keywords = {}
        self.is_not = is_not
        self.no_case = no_case

    def convert(self):
        all_elems = []

        for keyword, value in self.keywords.items():
            if keyword in type(self).KEYWORDS_MAPPING.keys():
                keyword = type(self).KEYWORDS_MAPPING[keyword]
            all_elems.append(f"{keyword}:{value}")
        is_not = ""
        if self.is_not:
            is_not = "!"
        no_case = ""
        if self.no_case:
            no_case = "nocase;"
        return (
            f'content:"{is_not}{self.content}"; {no_case}' + " " + "; ".join(all_elems)
        )

    @classmethod
    def from_dict(cls, field_value: dict):
        base = cls(None)
        for key, value in field_value.items():

            if key.split("|")[0] == "content":
                if "|not" in key:
                    base.is_not = True
                if "|nocase" in key:
                    base.no_case = True
                base.content = value
            elif key in cls.KEYWORDS:
                base.keywords[key] = value
        return base


class NyxRuleDetectionProtcolTransformer:
    TRANSFORMERS = [
        "nospace",
        "dotprefix",
        "lower",
        "lowerheader",
        "upper",
        "md5",
        "sha1",
        "sha256",
        "urldecode",
    ]
    COMPLEX_TRASNFORMERS = ["xor", "pcrexform"]
    TRANSFORMERS_MAPPING = {
        "nospace": "strip_whitespace",
        "lower": "to_lower",
        "upper": "to_upper",
        "lowerheader": "header_lowercase",
        "md5": "to_md5",
        "sha1": "to_sha1",
        "sha256": "to_sha256",
        "urldecode": "url_decode",
    }

    def __init__(self, key: str, value: str) -> None:
        self.value = value
        self.key = key

    def convert(self):
        if self.key in type(self).TRANSFORMERS_MAPPING.keys():
            key = type(self).TRANSFORMERS_MAPPING[self.key]
        else:
            key = self.key
        if self.value != None:
            return f'{key}:"{self.value}";'
        else:
            return f"{key};"


class NyxRuleDetectionProtocolField:

    def __init__(
        self,
        name: str,
        transformers: List[NyxRuleDetectionProtcolTransformer],
        value: List[NyxRuleDetectionProtocolFieldValue],
    ) -> None:

        self.name = name

        self.transformers = transformers
        self.value = value

    @classmethod
    def from_dict(cls, field_name: str, field_value: dict):
        # as this is not ordered, we need to find the field
        transformers = []
        if "|" in field_name:
            parts = field_name.split("|")
            field_name = parts[0]
            transformers = [
                NyxRuleDetectionProtcolTransformer(key=tr, value=None)
                for tr in parts[1:]
            ]

        if type(field_value) == str:
            return cls(field_name=field_name, field_value=[field_value])
        elif type(field_value) == list:
            all_field_values = []
            for value in field_value:
                print(type(value))
                if "content" in value.keys() or "pcre" in value.keys():
                    field_value = NyxRuleDetectionProtocolFieldValue.from_dict(value)
                    all_field_values.append(field_value)
                elif (
                    list(value.keys())[0]
                    in NyxRuleDetectionProtcolTransformer.COMPLEX_TRASNFORMERS
                ):
                    transformers.append(
                        NyxRuleDetectionProtcolTransformer(
                            key=list(value.keys())[0], value=list(value.values())[0]
                        )
                    )

            return cls(
                name=field_name, transformers=transformers, value=all_field_values
            )
        else:
            raise FormatException(
                f"{field_name} value is not a list or a str, please fix"
            )

    def convert(self):

        return (
            f"{self.name}; {' '.join([f'{tr.convert()}' for tr in self.transformers])} "
            + " ".join([a.convert() for a in self.value])
        )


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

        for field_name, field_value in detections.items():

            if not re.search(
                "[a-z_\\|-]+\\.[a-z_\\|-]+", str(field_name)
            ):  # we here on a classic keyword
                all_fields.append(
                    NyxRuleDetectionClassicField.from_dict(
                        field_name=field_name, field_value=field_value
                    )
                )
            else:  # we are on a protocol field

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


class NyxRuleStreamFlow:
    def __init__(self, options: List[str]) -> None:
        if type(options) == str:
            options = [options]
        self.options = options

    def convert(self):
        return f"flow:{','.join(self.options)};"


class NyxRuleStream:
    def __init__(
        self,
        direction: str,
        flow: NyxRuleStreamFlow,
        source: Optional[NyxRuleEndpoint] = None,
        destination: Optional[NyxRuleEndpoint] = None,
    ) -> None:
        self.direction = direction
        self.source = source
        self.destination = destination
        self.flow = flow

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
    def from_dict(self, stream: dict):
        source = None
        destination = None
        direction = stream["direction"]
        if "source" in stream.keys():
            source = NyxRuleEndpoint.from_dict(stream["source"])
        if "destination" in stream.keys():
            destination = NyxRuleEndpoint.from_dict(stream["destination"])
        if "flow" in stream.keys():
            flow = NyxRuleStreamFlow(stream["flow"])
        return NyxRuleStream(
            direction=direction,
            source=source,
            flow=flow,
            destination=destination,
        )


class NyxRule:
    def __init__(
        self,
        title: NyxRuleTitle,
        id: NyxRuleId,
        description: NyxRuleDescription,
        references: NyxRuleReferences,
        level: NyxRuleLevel,
        action: NyxRuleAction,
        protocol: NyxRuleProtocol,
        stream: NyxRuleStream,
        detection: NyxRuleDetection,
    ) -> None:
        self.title = title
        self.id = id
        self.description = description
        self.reference = references
        self.level = level
        self.protocol = protocol
        self.action = action
        self.detection = detection
        self.stream = stream

    def convert(self):
        conv_title = self.title.convert()
        conv_id = self.id.convert()
        conv_protocol = self.protocol.convert()
        conv_description = self.description.convert()
        conv_references = self.reference.convert()
        conv_level = self.level.convert()
        conv_action = self.action.convert()
        conv_detection = self.detection.convert()
        conv_stream = self.stream.convert()
        conv_flow = self.stream.flow.convert()
        return f'{conv_action} {conv_protocol} {conv_stream} (msg:"{conv_title}"; {conv_flow} {conv_detection}; {conv_references}; {conv_level}; {conv_id}; rev:1; metadata: description "{conv_description}";)'

    @classmethod
    def from_dict(cls, dict):
        title = NyxRuleTitle(dict["title"])
        description = NyxRuleDescription(dict["description"])
        id = NyxRuleId(dict["id"])
        level = NyxRuleLevel(dict["level"])
        references = NyxRuleReferences(dict["references"])
        action = NyxRuleAction(dict["action"])
        protocol = NyxRuleProtocol(dict["protocol"])
        detection = NyxRuleDetection.from_dict(dict["detection"])
        stream = NyxRuleStream.from_dict(dict["stream"])
        return NyxRule(
            title=title,
            description=description,
            id=id,
            references=references,
            level=level,
            action=action,
            protocol=protocol,
            detection=detection,
            stream=stream,
        )
