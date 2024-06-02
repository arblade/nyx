from typing import List


class NyxRuleField:
    def __init__(self, content: str) -> None:
        self.content = content

    def convert(self):
        return self.content


class NyxRuleTitle(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)

    def convert(self):
        return f'msg:"{self.content}"'


class NyxRuleDescription(NyxRuleField):
    def __init__(self, content: str) -> None:
        super().__init__(content)

    # TODO: where do i put it ?


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


class NyxRuleSelection:
    def __init__(self, content: dict) -> None:
        pass


class NyxRuleDetection:
    def __init__(
        self, selections: List[NyxRuleSelection], condition: NyxRuleCondition
    ) -> None:
        pass


class NyxRule:
    def __init__(
        self,
        title: NyxRuleTitle,
        id: NyxRuleId,
        description: NyxRuleDescription,
        level: NyxRuleLevel,
        action: NyxRuleAction,
        detection: NyxRuleDetection,
    ) -> None:
        pass
