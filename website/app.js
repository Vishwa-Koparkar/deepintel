// These examples explain URL signals; the static site never claims to run the model.
const examples = {
  impersonation: {
    url: 'https://rnicrosoft.com/account/verify', title: 'Looks familiar. Isn’t Microsoft.', badge: 'LOOKALIKE',
    evidence: 'The letters “rn” visually imitate “m”. The registered domain is rnicrosoft.com, not microsoft.com.',
    why: 'A dedicated lookalike detector checks brand impersonation beyond the model’s statistical features.', layer: 'LOOKALIKE DETECTOR'
  },
  subdomain: {
    url: 'https://login.paypal.evil.com/verify', title: 'PayPal in the name. A different owner.', badge: 'DECEPTIVE HOST',
    evidence: 'The registered domain is evil.com. The “paypal” label is a subdomain and does not establish ownership by PayPal.',
    why: 'Brand names buried in subdomains are checked separately so a familiar word cannot establish trust.', layer: 'SUBDOMAIN CHECK'
  },
  benign: {
    url: 'https://example.com/docs?lang=en', title: 'A path is not proof of a threat.', badge: 'BENIGN STRUCTURE',
    evidence: 'Paths and query strings are ordinary URL components. Their presence alone is not evidence of phishing.',
    why: 'Benign URL augmentation adds realistic paths and queries to reduce the shortcut learned from bare-domain training data.', layer: 'DATA QUALITY'
  }
};
function selectExample(key) {
  const example = examples[key];
  if (!example) return;
  for (const field of ['url', 'title', 'badge', 'evidence', 'why', 'layer']) {
    document.getElementById(`example-${field}`).textContent = example[field];
  }
  document.getElementById('example-badge').classList.toggle('benign', key === 'benign');
  for (const button of document.querySelectorAll('[data-example]')) {
    const active = button.dataset.example === key;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  }
}
for (const button of document.querySelectorAll('[data-example]')) {
  button.addEventListener('click', () => selectExample(button.dataset.example));
}
