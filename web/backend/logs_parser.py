from pydantic import BaseModel


class Log(BaseModel):
    code: str
    text: str
    is_error: bool


def parse_output(output: str):
    all_res = []
    lines = output.split("\n")
    for ln in lines:
        res = parse_log(ln)
        if res:
            all_res.append(res)
    return all_res


def parse_log(log: str):
    parts = log.split(":")
    if len(parts) >= 2:
        level = parts[0]
        code = parts[1]
        text = "".join(parts[2:])
        if text.endswith("at line 1"):
            return None
        if level == "Error":
            return Log(code=code, text=text, is_error=True)

    return None


def parse_log_old(log: str):
    parts = log.split(" - ")
    if len(parts) >= 3:
        level = parts[1]
        code = parts[2]
        text = parts[3]
        if text.endswith("at line 1"):
            return None
        if code.startswith("[ERRCODE"):
            return Log(code=code, text=text, is_error=True)
    return None
