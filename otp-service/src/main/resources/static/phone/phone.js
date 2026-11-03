// Polls the simulated inbox for one number every 3 s while the page is open.
(function () {
  const form = document.getElementById('lookup');
  const input = document.getElementById('msisdn');
  const list = document.getElementById('messages');
  const status = document.getElementById('status');
  let timer = null;
  let lastCount = -1;

  async function load() {
    const res = await fetch('/phone/v1/inbox?msisdn=' + encodeURIComponent(input.value));
    if (!res.ok) { status.textContent = 'Could not read messages.'; return; }
    const messages = await res.json();
    list.replaceChildren(...messages.map(m => {
      const li = document.createElement('li');
      const when = document.createElement('time');
      when.dateTime = new Date(m.sentAt).toISOString();
      when.textContent = new Date(m.sentAt).toLocaleTimeString('en-IN') + ' · to ' + m.to;
      li.append(when, document.createTextNode(m.text));
      return li;
    }));
    if (messages.length !== lastCount) {
      status.textContent = messages.length === 0 ? 'No messages yet.' : messages.length + ' message(s).';
      lastCount = messages.length;
    }
  }

  form.addEventListener('submit', e => {
    e.preventDefault();
    if (!input.checkValidity()) { status.textContent = 'Enter +91 and a 10-digit mobile number.'; return; }
    lastCount = -1;
    clearInterval(timer);
    load();
    timer = setInterval(load, 3000);
  });
})();
