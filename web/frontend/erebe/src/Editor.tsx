import { useState } from "react";

import Editor from "@monaco-editor/react";
import { Check, Copy } from "lucide-react";

export function MyEditor({
  text,
  readonly,
  setText,
}: {
  text: string;
  readonly: boolean;
  setText: (value: string | undefined, e: unknown) => void;
}) {
  const [copySuccess, setCopySuccess] = useState<boolean>(false);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(text).then(
      () => {
        setCopySuccess(true);
        setTimeout(() => setCopySuccess(false), 4000);
      },
      () => {
        setCopySuccess(false);
        setTimeout(() => setCopySuccess(false), 4000);
      }
    );
  };
  return (
    <div className="relative w-full">
      <Editor
        height="50vh"
        defaultLanguage="yaml"
        options={{
          readOnly: readonly,
          minimap: { enabled: false },
          automaticLayout: true,
          scrollBeyondLastLine: false,
        }}
        value={text}
        onChange={setText}
        loading={<div className="spinner"></div>}
      />
      <div
        onClick={copyToClipboard}
        className="absolute top-2 right-6 p-1 hover:cursor-pointer hover:bg-slate-100 rounded-full bg-white"
      >
        {copySuccess ? (
          <div className="flex space-x-1 items-center justify-center z-10">
            <Check size={15} />
          </div>
        ) : (
          <Copy size={15} />
        )}
      </div>
    </div>
  );
}
