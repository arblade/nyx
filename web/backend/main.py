import subprocess
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from nyx.main import convert_from_yaml
import os
import uuid
import asyncio

from logs_parser import parse_output

app = FastAPI()


# Define the request body model
class RuleRequest(BaseModel):
    raw_rule: str


@app.post("/api/convert")
async def read_item(req: RuleRequest):
    if len(req.raw_rule) > 4000:
        return JSONResponse(status_code=501, content={"error": "too huge file"})
    rule = convert_from_yaml(req.raw_rule)
    filename = str(uuid.uuid4()) + ".rules"
    with open("/tmp/" + filename, "w") as f:
        f.write(rule)
    command = f"suricata -T -S /tmp/{filename}"

    process = await asyncio.create_subprocess_shell(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    stdout, stderr = await process.communicate()
    os.remove("/tmp/" + filename)
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    print(stdout)
    print(stderr)
    print("---------")
    res_err = parse_output(stderr)
    if res_err:
        return JSONResponse(
            status_code=400,
            content={"error": "\n".join([r.text for r in res_err]), "converted": rule},
        )
    else:
        return JSONResponse(status_code=200, content={"converted": rule})
