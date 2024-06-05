import { useState } from "react";
import { MyEditor } from "./Editor";
import { Button } from "@/components/ui/button";

import "./App.css";

function App() {
  const [rawRule, setRawRule] = useState(
    'title: Example rule of Outdated Firefox on Windows\n\
id: 1000001\n\
references: "test"\n\
description: Detects outdated Firefox browsers (version 3.x except 3.6.13) on Windows.\n\
level: high\n\
action: alert\n\
protocol: http\n\
\n\
detection:\n\
  http.user_agent:\n\
    - content: "User-Agent|3A| Mozilla/5.0 |28|Windows|3B|"\n\
    - content: "Firefox/3."\n\
      dist: 0\n\
    - content|not|nocase: "Firefox/3.6.13"\n\
      dist: -10\n\
\n\
\n\
stream:\n\
  flow: from_client\n\
  direction: out'
  );
  const [converted, setConverted] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sendRule = () =>
    fetch("/api/convert", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ raw_rule: rawRule }),
    })
      .then(async (res) => {
        if (res.ok) {
          return res.json();
        } else {
          if (res.status == 400) {
            await res.json().then((data) => {
              setConverted(data.converted);
              throw new Error(data.error);
            });
          } else {
            setConverted(null);
            throw new Error("something went wrong...");
          }
        }
      })
      .then((data) => {
        console.log(data);
        setError(null);
        setConverted(data.converted);
      })
      .catch((err) => {
        console.log(err.message.error);
        setError(err.message);
      });
  return (
    <>
      <div className="font-bold text-2xl mb-8 text-zinc-700 w-full text-center">
        Nyx Convertor
      </div>
      <div className="flex items-center justify-start flex-col">
        {" "}
        <div className="w-1/2">
          <MyEditor
            text={rawRule}
            readonly={false}
            setText={(a: string | undefined) => {
              setRawRule(a as string);
            }}
          />
        </div>
        <div>
          <Button variant="outline" onClick={sendRule}>
            Submit
          </Button>
        </div>
        {converted && (
          <div className="w-1/2 bg-zinc-100 p-4 px-6 my-4 rounded-lg font-mono text-zinc-800">
            {converted}
          </div>
        )}
        {error ? (
          <div className="w-1/2 text-red-600">{error}</div>
        ) : (
          <div className="text-green-600">we're good !</div>
        )}
      </div>
    </>
  );
}

export default App;
