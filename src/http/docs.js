'use strict';
const byId = id => document.getElementById(id);
const operations = [];
let selected;
function choose() {
  selected = operations[Number(byId('operation').value)];
  byId('description').textContent = selected.operation.summary;
  byId('parameters').replaceChildren();
  for (const parameter of selected.operation.parameters || []) {
    const label = document.createElement('label');
    label.textContent = `${parameter.name} (${parameter.in})`;
    const input = document.createElement('input');
    input.name = `${parameter.in}:${parameter.name}`;
    input.required = Boolean(parameter.required);
    label.append(input);
    byId('parameters').append(label);
  }
  const content = selected.operation.requestBody?.content || {};
  byId('file-label').hidden = !content['application/pdf'];
  byId('body-label').hidden = !content['application/json'];
  const examples = { '/v1/acquisitions': { url: 'https://example.org/document.pdf' } };
  byId('body').value = JSON.stringify(examples[selected.path] || (selected.method === 'put' ? {enabled:true} : {}),null,2);
}
async function start() {
  const spec = await (await fetch('/openapi.json')).json();
  for (const [path,methods] of Object.entries(spec.paths)) {
    for (const [method,operation] of Object.entries(methods)) {
      operations.push({path,method,operation});
      const option = document.createElement('option');
      option.value = String(operations.length - 1);
      option.textContent = `${method.toUpperCase()} ${path}`;
      byId('operation').append(option);
    }
  }
  choose();
}
byId('operation').addEventListener('change',choose);
byId('request').addEventListener('submit',async event => {
  event.preventDefault();
  let path = selected.path;
  const headers = {};
  const query = new URLSearchParams();
  for (const input of byId('parameters').querySelectorAll('input')) {
    if (!input.value) continue;
    const [place,name] = input.name.split(':');
    if (place === 'path') path = path.replace(`{${name}}`,encodeURIComponent(input.value));
    if (place === 'query') query.set(name,input.value);
    if (place === 'header') headers[name] = input.value;
  }
  if (byId('token').value) headers.Authorization = `Bearer ${byId('token').value}`;
  const options = {method:selected.method.toUpperCase(),headers,redirect:'error'};
  if (!byId('file-label').hidden) {
    const file = byId('file').files[0];
    if (!file) {byId('response').textContent='Select a PDF first.';return;}
    headers['Content-Type']='application/pdf'; options.body=file;
  } else if (!byId('body-label').hidden) {
    headers['Content-Type']='application/json'; options.body=byId('body').value;
  }
  byId('response').textContent='Request running…';
  try {
    const response=await fetch(path+(query.size?`?${query}`:''),options);
    const type=response.headers.get('content-type') || '';
    if (type.includes('json') || type.startsWith('text/')) {
      const reader=response.body.getReader();const chunks=[];let count=0;
      while (true) {const {done,value}=await reader.read();if(done)break;count+=value.length;if(count>1048576){await reader.cancel();throw new Error('Response exceeds console display limit; use curl to save the complete response.');}chunks.push(value);}
      const bytes=new Uint8Array(count);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
      byId('response').textContent=`${response.status} ${response.statusText}\n${new TextDecoder().decode(bytes)}`;
    } else {
      await response.body?.cancel();
      byId('response').textContent=`${response.status} ${response.statusText}\nBinary download available at ${path}. Use curl with your access token to save it.`;
    }
  } catch(error) {byId('response').textContent=String(error);}
});
start().catch(error => {byId('response').textContent=String(error);});
