"use strict";
// API console for /docs. `pnpm run build` emits docs.js from docs.ts; edit docs.ts.
const ResponseDisplayLimit = 1048576;
const ById = (Id, Type) => {
    const Found = document.getElementById(Id);
    if (!(Found instanceof Type))
        throw new Error(`Missing console element #${Id}`);
    return Found;
};
const OperationSelect = ById('operation', HTMLSelectElement);
const Description = ById('description', HTMLElement);
const Parameters = ById('parameters', HTMLElement);
const FileLabel = ById('file-label', HTMLElement);
const FileInput = ById('file', HTMLInputElement);
const BodyLabel = ById('body-label', HTMLElement);
const Body = ById('body', HTMLTextAreaElement);
const Token = ById('token', HTMLInputElement);
const RequestForm = ById('request', HTMLFormElement);
const ResponseView = ById('response', HTMLElement);
const Operations = [];
let Selected;
function Choose() {
    Selected = Operations[Number(OperationSelect.value)];
    if (!Selected)
        return;
    Description.textContent = Selected.Operation.summary ?? '';
    Parameters.replaceChildren();
    for (const Parameter of Selected.Operation.parameters ?? []) {
        const Label = document.createElement('label');
        Label.textContent = `${Parameter.name} (${Parameter.in})`;
        const Input = document.createElement('input');
        Input.name = `${Parameter.in}:${Parameter.name}`;
        Input.required = Boolean(Parameter.required);
        Label.append(Input);
        Parameters.append(Label);
    }
    const Content = Selected.Operation.requestBody?.content ?? {};
    FileLabel.hidden = !Content['application/pdf'];
    BodyLabel.hidden = !Content['application/json'];
    const Examples = { '/v1/acquisitions': { url: 'https://example.org/document.pdf' } };
    Body.value = JSON.stringify(Examples[Selected.Path] ?? (Selected.Method === 'put' ? { enabled: true } : {}), null, 2);
}
async function Start() {
    const Spec = (await (await fetch('/openapi.json')).json());
    for (const [Path, Methods] of Object.entries(Spec.paths)) {
        for (const [Method, Operation] of Object.entries(Methods)) {
            Operations.push({ Path, Method, Operation });
            const Option = document.createElement('option');
            Option.value = String(Operations.length - 1);
            Option.textContent = `${Method.toUpperCase()} ${Path}`;
            OperationSelect.append(Option);
        }
    }
    Choose();
}
async function ReadLimited(Stream) {
    const Reader = Stream.getReader();
    const Chunks = [];
    let Count = 0;
    for (;;) {
        const Chunk = await Reader.read();
        if (Chunk.done)
            break;
        Count += Chunk.value.length;
        if (Count > ResponseDisplayLimit) {
            await Reader.cancel();
            throw new Error('Response exceeds console display limit; use curl to save the complete response.');
        }
        Chunks.push(Chunk.value);
    }
    const Bytes = new Uint8Array(Count);
    let Offset = 0;
    for (const Chunk of Chunks) {
        Bytes.set(Chunk, Offset);
        Offset += Chunk.length;
    }
    return Bytes;
}
async function Send(Current) {
    let Path = Current.Path;
    const RequestHeaders = {};
    const Query = new URLSearchParams();
    for (const Input of Parameters.querySelectorAll('input')) {
        if (!Input.value)
            continue;
        const [Place, Name = ''] = Input.name.split(':');
        if (Place === 'path')
            Path = Path.replace(`{${Name}}`, encodeURIComponent(Input.value));
        if (Place === 'query')
            Query.set(Name, Input.value);
        if (Place === 'header')
            RequestHeaders[Name] = Input.value;
    }
    if (Token.value)
        RequestHeaders['Authorization'] = `Bearer ${Token.value}`;
    const Options = { method: Current.Method.toUpperCase(), headers: RequestHeaders, redirect: 'error' };
    if (!FileLabel.hidden) {
        const Pdf = FileInput.files?.[0];
        if (!Pdf) {
            ResponseView.textContent = 'Select a PDF first.';
            return;
        }
        RequestHeaders['Content-Type'] = 'application/pdf';
        Options.body = Pdf;
    }
    else if (!BodyLabel.hidden) {
        RequestHeaders['Content-Type'] = 'application/json';
        Options.body = Body.value;
    }
    ResponseView.textContent = 'Request running…';
    const Reply = await fetch(Path + (Query.size ? `?${Query.toString()}` : ''), Options);
    const Type = Reply.headers.get('content-type') ?? '';
    if (Type.includes('json') || Type.startsWith('text/')) {
        const Bytes = Reply.body ? await ReadLimited(Reply.body) : new Uint8Array();
        ResponseView.textContent = `${Reply.status} ${Reply.statusText}\n${new TextDecoder().decode(Bytes)}`;
    }
    else {
        await Reply.body?.cancel();
        ResponseView.textContent = `${Reply.status} ${Reply.statusText}\nBinary download available at ${Path}. Use curl with your access token to save it.`;
    }
}
OperationSelect.addEventListener('change', Choose);
RequestForm.addEventListener('submit', Submission => {
    Submission.preventDefault();
    if (!Selected)
        return;
    Send(Selected).catch((Failure) => {
        ResponseView.textContent = String(Failure);
    });
});
Start().catch((Failure) => {
    ResponseView.textContent = String(Failure);
});
